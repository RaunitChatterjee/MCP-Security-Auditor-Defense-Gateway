"""
mcp_lite.py — a minimal, dependency-free MCP (Model Context Protocol) server
runtime, speaking JSON-RPC 2.0 over Streamable HTTP (a single POST /mcp
endpoint), following the MCP spec's core method set:

    initialize
    tools/list
    tools/call

We hand-roll this instead of depending on the official `mcp` PyPI package
because that package's current release has a broken internal import in this
environment (mcp.shared.experimental.tasks references a constant that
doesn't exist in mcp.types — a packaging bug, not something fixable on our
end). MCP itself is a thin protocol on top of JSON-RPC 2.0, so a ~150-line
reimplementation is both faster to get working and easier to reason about
for a vulnerability-research range, where we WANT full control over exactly
what the server does with each call.

Every vulnerable server in range/ imports this module and registers tools
with the @server.tool() decorator, exactly the way the official SDK's
FastMCP works, so the servers themselves read like normal MCP server code.
"""

from __future__ import annotations

import inspect
import traceback
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

MCP_PROTOCOL_VERSION = "2026-06-18"  # current MCP protocol version string


class ToolDef:
    def __init__(self, name: str, description: str, fn: Callable, input_schema: dict):
        self.name = name
        self.description = description
        self.fn = fn
        self.input_schema = input_schema

    def to_mcp_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class MCPLiteServer:
    """A minimal MCP server exposing tools over JSON-RPC 2.0 / Streamable HTTP."""

    def __init__(self, name: str, version: str = "0.1.0", require_auth: bool = True,
                 auth_token: str | None = None):
        self.name = name
        self.version = version
        self.require_auth = require_auth
        self.auth_token = auth_token
        self.tools: dict[str, ToolDef] = {}
        self.app = FastAPI(title=name)
        self.app.post("/mcp")(self._handle_rpc)
        self.app.get("/healthz")(lambda: {"status": "ok", "server": self.name})

    # ---- tool registration -------------------------------------------------
    def tool(self, description: str = "", input_schema: dict | None = None):
        def decorator(fn: Callable):
            sig = inspect.signature(fn)
            schema = input_schema or {
                "type": "object",
                "properties": {
                    p.name: {"type": "string"} for p in sig.parameters.values()
                },
                "required": [p.name for p in sig.parameters.values()
                             if p.default is inspect.Parameter.empty],
            }
            self.tools[fn.__name__] = ToolDef(
                name=fn.__name__,
                description=description or (fn.__doc__ or "").strip(),
                fn=fn,
                input_schema=schema,
            )
            return fn
        return decorator

    # ---- JSON-RPC plumbing ---------------------------------------------------
    def _rpc_error(self, req_id, code: int, message: str, data: Any = None) -> dict:
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": req_id, "error": err}

    def _rpc_result(self, req_id, result: Any) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _check_auth(self, request: Request) -> bool:
        if not self.require_auth:
            return True
        header = request.headers.get("authorization", "")
        expected = f"Bearer {self.auth_token}"
        return header == expected

    async def _handle_rpc(self, request: Request):
        body = await request.json()
        req_id = body.get("id")
        method = body.get("method")
        params = body.get("params", {}) or {}

        if method == "initialize":
            return JSONResponse(self._rpc_result(req_id, {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": {"name": self.name, "version": self.version},
                "capabilities": {"tools": {}},
            }))

        # every method except `initialize` requires auth on a properly-built
        # server; vulnerable servers override require_auth=False to model
        # CVE-class "missing authentication" findings.
        if not self._check_auth(request):
            return JSONResponse(
                self._rpc_error(req_id, -32001, "Unauthorized: missing or invalid bearer token"),
                status_code=401,
            )

        if method == "tools/list":
            return JSONResponse(self._rpc_result(req_id, {
                "tools": [t.to_mcp_dict() for t in self.tools.values()]
            }))

        if method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {}) or {}
            tool = self.tools.get(tool_name)
            if tool is None:
                return JSONResponse(self._rpc_error(req_id, -32602, f"Unknown tool: {tool_name}"))
            try:
                result = tool.fn(**args)
                return JSONResponse(self._rpc_result(req_id, {
                    "content": [{"type": "text", "text": str(result)}],
                    "isError": False,
                }))
            except Exception as e:  # noqa: BLE001 - deliberately broad: tool errors become MCP errors
                return JSONResponse(self._rpc_result(req_id, {
                    "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}],
                    "isError": True,
                }))

        return JSONResponse(self._rpc_error(req_id, -32601, f"Method not found: {method}"))
