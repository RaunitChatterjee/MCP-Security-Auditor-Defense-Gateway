"""
Defense gateway — FastAPI entrypoint
========================================
Day 12: a transparent reverse proxy in front of the 4 range servers.
Day 13: policy.check_policy() runs before every tools/call is forwarded.
Day 14: session_tracker.SessionTracker flags anomalous call sequences.
Day 15: /api/findings unifies this gateway's alert log with the latest
        scanner report (scanner/scan.py) into one JSON endpoint, and every
        alert is also written to a SOC Core outbox file in the same event
        shape SOC Core ingests (see _push_to_soc_core below).

One client-facing endpoint per backend server:
    POST /gateway/{server_id}/mcp      (server_id: 1-4, matching the range)

`initialize` and `tools/list` pass straight through untouched — only
`tools/call` goes through policy + tracking, since those are the only
calls that can actually do anything.

Run:
    python3 -m uvicorn gateway.app:app --port 9000
"""

from __future__ import annotations

import glob
import json
import os
import uuid
from datetime import datetime, timezone

import requests
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from gateway.policy import check_policy
from gateway.session_tracker import SessionTracker

BACKENDS = {
    1: ("git-helper-mcp", 8001),
    2: ("project-files-mcp", 8002),
    3: ("ops-console-mcp", 8003),
    4: ("crm-assistant-mcp", 8004),
}

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
LOG_PATH = os.path.join(BASE_DIR, "logs", "gateway_events.jsonl")
OUTBOX_PATH = os.path.join(BASE_DIR, "logs", "soc_core_outbox.jsonl")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

app = FastAPI(title="mcp-defense-gateway")
tracker = SessionTracker()

# Allows the dashboard's Vite dev server (and its built/served form) to call
# GET /api/findings directly from the browser. Scoped to localhost dev ports
# only — tighten this before deploying the gateway anywhere public.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:4173", "http://127.0.0.1:4173"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    expose_headers=["X-Gateway-Alert", "X-Gateway-Alert-Title"],
)


def _log_event(event: dict):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


def _push_to_soc_core(event: dict):
    """
    SOC Core (your other project) is designed to ingest events in this
    JSON shape via its HTTP intake. SOC Core isn't reachable as a live
    service from this build environment, so this writes to a local
    outbox file instead of making a real network call — swap the body of
    this function for `requests.post(SOC_CORE_INGEST_URL, json=event)`
    once SOC Core's endpoint is available, and nothing else in this file
    needs to change.
    """
    with open(OUTBOX_PATH, "a") as f:
        f.write(json.dumps({**event, "event_type": "gateway_alert"}) + "\n")


def _forward(port: int, body: dict, auth_header: str | None) -> requests.Response:
    headers = {"Authorization": auth_header} if auth_header else {}
    return requests.post(f"http://127.0.0.1:{port}/mcp", json=body, headers=headers, timeout=10)


@app.post("/gateway/{server_id}/mcp")
async def gateway_mcp(server_id: int, request: Request):
    if server_id not in BACKENDS:
        return JSONResponse({"error": f"unknown backend id {server_id}"}, status_code=404)
    server_name, port = BACKENDS[server_id]
    session_id = request.headers.get("x-session-id") or f"anon-{uuid.uuid4().hex[:8]}"
    auth_header = request.headers.get("authorization")
    body = await request.json()
    method = body.get("method")

    # Day 12: initialize / tools/list pass straight through, unmodified.
    if method != "tools/call":
        resp = _forward(port, body, auth_header)
        return JSONResponse(resp.json(), status_code=resp.status_code)

    params = body.get("params", {}) or {}
    tool_name = params.get("name")
    arguments = params.get("arguments", {}) or {}

    # Day 13: policy check BEFORE the call ever reaches the backend.
    blocked, rule_id, reason = check_policy(tool_name, arguments)
    if blocked:
        event = {
            "session_id": session_id, "server_name": server_name, "server_id": server_id,
            "tool": tool_name, "arguments": arguments, "decision": "BLOCKED",
            "rule_id": rule_id, "reason": reason,
        }
        _log_event(event)
        _push_to_soc_core(event)
        return JSONResponse({
            "jsonrpc": "2.0", "id": body.get("id"),
            "error": {"code": -32010, "message": f"Blocked by gateway policy ({rule_id}): {reason}"},
        }, status_code=403)

    # Allowed — forward to the real backend, transparently.
    resp = _forward(port, body, auth_header)
    result = resp.json()
    response_text = ""
    if "result" in result:
        response_text = "\n".join(c.get("text", "") for c in result["result"].get("content", []))

    # Day 14: behavioral check over the session's whole call history.
    tracker.record(session_id, server_name, tool_name, arguments, response_text)
    seq_alert = tracker.check_sequence(session_id)

    event = {
        "session_id": session_id, "server_name": server_name, "server_id": server_id,
        "tool": tool_name, "arguments": arguments, "decision": "ALLOWED",
        "response_snippet": response_text[:200],
    }
    if seq_alert:
        event["sequence_alert"] = seq_alert
    _log_event(event)
    if seq_alert:
        _push_to_soc_core(event)

    # Day 17: surface a sequence alert as a response HEADER, not a change to
    # the JSON-RPC body — the body stays byte-for-byte what the backend
    # returned (Day 12's transparency guarantee), while a live caller (e.g.
    # the dashboard) can still see that this specific call tripped a
    # behavioral flag without polling /api/findings separately.
    headers = {}
    if seq_alert:
        headers["X-Gateway-Alert"] = seq_alert["rule_id"]
        headers["X-Gateway-Alert-Title"] = seq_alert["title"]
    return JSONResponse(result, status_code=resp.status_code, headers=headers)


@app.get("/api/findings")
def unified_findings():
    """Day 15: scanner report + gateway alert history, merged."""
    latest_scan = None
    files = sorted(glob.glob(os.path.join(REPORTS_DIR, "scan_report_*.json")))
    if files:
        with open(files[-1]) as f:
            latest_scan = json.load(f)

    gateway_alerts = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            for line in f:
                event = json.loads(line)
                if event.get("decision") == "BLOCKED" or "sequence_alert" in event:
                    gateway_alerts.append(event)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner_report": latest_scan,
        "gateway_alerts": gateway_alerts,
        "gateway_alert_count": len(gateway_alerts),
    }


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "mcp-defense-gateway"}
