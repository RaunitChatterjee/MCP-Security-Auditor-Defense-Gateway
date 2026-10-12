"""
Vulnerable MCP Server #3 — Missing / Weak Authentication
============================================================
Models an "ops console" MCP tool server: an agent-facing tool that lets an
LLM agent look up and modify user account records — e.g. for a support-bot
agent. This is a realistic pattern: teams wire an MCP server directly to
internal admin APIs, assume the MCP transport layer (localhost, internal
network, a VPN) is "trusted enough", and never add per-call identity checks.

VULNERABILITY (intentional): the server never verifies caller identity on
ANY tool call — there's no bearer token, no session, no distinction between
"the support agent looking up its own assigned tickets" and "anyone who can
reach this port". Every tool, including destructive ones, is callable by
anyone who can send it a JSON-RPC request. This mirrors the "Missing/Weak
Authentication" class disclosed repeatedly in the 2026 MCP CVE wave —
several official reference servers shipped with auth either off by default
or trivially bypassable.

Contrast with server1/server2: those require no auth either, but model
*other* vulnerability classes (cmd injection, path traversal). This server
is the one where the ONLY thing wrong is the missing auth check itself —
the tool logic is otherwise "correct".
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from mcp_lite import MCPLiteServer  # noqa: E402

server = MCPLiteServer(name="ops-console-mcp", version="0.1.0", require_auth=False)

# in-memory "user directory" standing in for a real admin backend
USERS = {
    "u1001": {"name": "Asha Rao", "email": "asha@example.com", "role": "customer", "balance": 4200},
    "u1002": {"name": "Priya Nair", "email": "priya@example.com", "role": "customer", "balance": 980},
    "u1003": {"name": "Admin Service Account", "email": "svc-admin@example.com", "role": "admin", "balance": 0},
}


@server.tool(description="Look up a user's account record by user ID.")
def get_user(user_id: str) -> str:
    # --- VULNERABLE: no auth, no check that the caller is allowed to see
    # this specific user (e.g. "support agent may only view users assigned
    # to its open tickets") -----------------------------------------------
    user = USERS.get(user_id)
    if not user:
        return f"No such user: {user_id}"
    return str(user)


@server.tool(description="Update a user's account balance (e.g. after a support credit/refund).")
def update_balance(user_id: str, new_balance: str) -> str:
    # --- VULNERABLE: a WRITE action, including on the admin service
    # account, with zero authentication or authorization check. A real
    # support-bot tool should never be callable by an unauthenticated
    # party, let alone one that can target arbitrary user_ids including
    # privileged accounts. ---------------------------------------------
    user = USERS.get(user_id)
    if not user:
        return f"No such user: {user_id}"
    old = user["balance"]
    user["balance"] = int(new_balance)
    return f"Updated {user_id} balance: {old} -> {user['balance']}"


@server.tool(description="List all user accounts in the system.")
def list_users() -> str:
    # --- VULNERABLE: a full directory dump, including the admin account
    # and emails, with no auth. -------------------------------------------
    return "\n".join(f"{uid}: {u['name']} <{u['email']}> role={u['role']}" for uid, u in USERS.items())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(server.app, host="127.0.0.1", port=8003)
