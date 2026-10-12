"""
Minimal MCP client/agent harness
====================================
A small, dependency-light MCP client (JSON-RPC 2.0 over Streamable HTTP)
used to drive the vulnerable range during development, and later reused by
the scanner (Phase 3) and the attack scripts (Phase 2).

Usage:
    python3 -m client.harness discover            # discover + list tools on every range server
    python3 -m client.harness call <port> <tool> key=value [key2=value2 ...]

Example:
    python3 -m client.harness call 8001 git_log author=Range
"""

from __future__ import annotations

import sys
import requests

# Registry of the range servers this harness knows about. Scanner/gateway
# code (Phase 3/4) will extend this with discovery instead of a hardcoded
# list, but a fixed registry is all Day 3 needs.
RANGE_SERVERS = {
    8001: "git-helper-mcp (server1_cmdinj)",
    8002: "project-files-mcp (server2_traversal)",
    8003: "ops-console-mcp (server3_noauth)",
    8004: "crm-assistant-mcp (server4_overpriv)",
}


class MCPClient:
    """A minimal MCP client for one server, speaking JSON-RPC 2.0 over HTTP."""

    def __init__(self, base_url: str, bearer_token: str | None = None, session_id: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.session_id = session_id  # when set, sent as X-Session-Id (used by the Phase 4 gateway)
        self._id = 0

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        headers = {}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        if self.session_id:
            headers["X-Session-Id"] = self.session_id
        resp = requests.post(
            f"{self.base_url}/mcp",
            json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}},
            headers=headers,
            timeout=10,
        )
        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"{method} -> RPC error {data['error']}")
        return data["result"]

    def initialize(self) -> dict:
        return self._rpc("initialize")

    def list_tools(self) -> list[dict]:
        return self._rpc("tools/list")["tools"]

    def call_tool(self, name: str, **arguments) -> str:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        text = "\n".join(c.get("text", "") for c in result.get("content", []))
        if result.get("isError"):
            return f"[TOOL ERROR] {text}"
        return text


def discover():
    print(f"{'PORT':<6} {'SERVER':<28} {'STATUS':<10} TOOLS")
    for port, label in RANGE_SERVERS.items():
        client = MCPClient(f"http://127.0.0.1:{port}")
        try:
            info = client.initialize()
            tools = client.list_tools()
            tool_names = ", ".join(t["name"] for t in tools)
            print(f"{port:<6} {label:<28} {'UP':<10} {tool_names}")
        except Exception as e:  # noqa: BLE001
            print(f"{port:<6} {label:<28} {'DOWN':<10} ({e})")


def call(port: int, tool: str, kv_args: list[str]):
    args = {}
    for kv in kv_args:
        key, _, val = kv.partition("=")
        args[key] = val
    client = MCPClient(f"http://127.0.0.1:{port}")
    print(client.call_tool(tool, **args))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "discover":
        discover()
    elif cmd == "call":
        call(int(sys.argv[2]), sys.argv[3], sys.argv[4:])
    else:
        print(__doc__)
        sys.exit(1)
