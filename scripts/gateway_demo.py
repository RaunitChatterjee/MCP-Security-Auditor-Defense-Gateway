"""
Gateway demo (Phase 4, Days 12-15) — run this against the live range + gateway
to reproduce every claim in the Phase 4 write-up in one script.

Prereqs (4 terminals, or background them):
    python3 -m uvicorn range.server1_cmdinj.server:server.app --port 8001
    python3 -m uvicorn range.server2_traversal.server:server.app --port 8002
    python3 -m uvicorn range.server3_noauth.server:server.app --port 8003
    python3 -m uvicorn range.server4_overpriv.server:server.app --port 8004
    python3 -m uvicorn gateway.app:app --port 9000

Run:
    python3 -m scripts.gateway_demo
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from client.harness import MCPClient  # noqa: E402


def safe_call(client: MCPClient, tool: str, **kwargs) -> str:
    try:
        return client.call_tool(tool, **kwargs)
    except RuntimeError as e:
        return f"[GATEWAY BLOCKED] {e}"


def main():
    print("### DAY 12 — transparent passthrough ###")
    c1 = MCPClient("http://127.0.0.1:9000/gateway/1", session_id="demo-legit")
    print(safe_call(c1, "git_log", author="Range"))

    print("\n### DAY 13 — policy blocks the Phase 2 exploit payloads live ###")
    cmd_payload = "' ; id ; cat /etc/passwd | head -3 ; echo '"
    print("[cmd injection]  ", safe_call(c1, "git_log", author=cmd_payload))

    c2 = MCPClient("http://127.0.0.1:9000/gateway/2", session_id="demo-legit")
    print("[path traversal] ", safe_call(c2, "read_file", path=("../" * 12 + "etc/passwd")))
    print("[sanity: legit read still works] ", safe_call(c2, "read_file", path="notes.txt"))

    print("\n### DAY 14 — the sequence-level attack, run through the gateway ###")
    session = "demo-attacker"
    c2b = MCPClient("http://127.0.0.1:9000/gateway/2", session_id=session)
    c4 = MCPClient("http://127.0.0.1:9000/gateway/4", session_id=session)

    ids_raw = safe_call(c2b, "read_file", path="customer_ids.txt")
    print("[step 1 — legitimate list read]", ids_raw.replace("\n", " "))
    customer_ids = [l.strip() for l in ids_raw.splitlines() if l.strip()]
    for cid in customer_ids:
        time.sleep(0.2)
        print(f"[step — legitimate single-ID lookup] {cid}:", safe_call(c4, "lookup_customer", customer_id=cid))
    print("-> none of the above were blocked by Day 13's policy (correctly — none individually "
          "violate it). Check logs/gateway_events.jsonl or GET /api/findings for the SEQ-001 "
          "behavioral alert this sequence triggers.")

    print("\n### DAY 15 — unified findings ###")
    import requests
    findings = requests.get("http://127.0.0.1:9000/api/findings").json()
    print(f"gateway_alert_count: {findings['gateway_alert_count']}")
    print(f"scanner_report present: {findings['scanner_report'] is not None}")


if __name__ == "__main__":
    main()
