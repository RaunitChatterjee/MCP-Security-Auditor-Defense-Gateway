"""
Vulnerable MCP Server #4 — Over-Permissioned Tools
======================================================
Models a "CRM assistant" MCP tool server: an agent-facing tool whose
DOCUMENTED, INTENDED purpose is a single narrow lookup — "find one customer
by their ID, read-only" — the kind of tool an LLM agent would use to answer
"what's this customer's plan tier?"

VULNERABILITY (intentional): the tool's actual implementation grants far
more capability than its stated purpose needs. Instead of a parameterized
"get customer by exact ID" query, it accepts a free-form `filter` string and
splices it directly into a SQL WHERE clause. The *documented* scope is
"read one customer record"; the *actual* scope is "run arbitrary read
access across the whole customers table" (and, because it's string-built
SQL, arbitrary SQL injection on top of that). This is the "Over-Permissioned
Tools" class from the project brief: a tool exposing more capability than
the task requires, violating least privilege — the agent (or an attacker
driving the agent via prompt injection) never needed table-wide access to
answer "what's this one customer's plan?", but the tool grants it anyway.

Note the difference from server1 (cmd injection) and server2 (path
traversal): the bug class here isn't "an escape sequence breaks out of a
shell/path" — it's a design/scoping bug. The least-privilege violation
would still be a vulnerability even with perfect SQL-injection-proofing,
because the tool was never supposed to accept a free-form filter at all.
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from mcp_lite import MCPLiteServer  # noqa: E402

server = MCPLiteServer(name="crm-assistant-mcp", version="0.1.0", require_auth=False)

_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.execute("""
    CREATE TABLE customers (
        customer_id TEXT PRIMARY KEY,
        name TEXT,
        plan_tier TEXT,
        email TEXT,
        card_last4 TEXT
    )
""")
_conn.executemany(
    "INSERT INTO customers VALUES (?, ?, ?, ?, ?)",
    [
        ("c001", "Rohan Mehta", "Pro", "rohan@example.com", "4412"),
        ("c002", "Fatima Khan", "Starter", "fatima@example.com", "9087"),
        ("c003", "Internal Test Account", "Enterprise", "internal-test@example.com", "0000"),
    ],
)
_conn.commit()


@server.tool(description="Look up a single customer's plan tier by customer ID.")
def lookup_customer(customer_id: str, filter: str = "") -> str:
    # --- VULNERABLE LINE ----------------------------------------------
    # The tool's STATED purpose ("look up ONE customer by ID") never
    # needed a free-form `filter` parameter at all — that's the
    # over-permissioning: the tool exposes a whole-table query surface
    # for a task that only needed a single parameterized lookup. On top
    # of that design flaw, the filter is string-concatenated into SQL,
    # so it's injectable too.
    where = f"customer_id = '{customer_id}'"
    if filter:
        where += f" OR {filter}"
    query = f"SELECT customer_id, name, plan_tier, email, card_last4 FROM customers WHERE {where}"
    rows = _conn.execute(query).fetchall()
    # ---------------------------------------------------------------------
    if not rows:
        return f"No customer found for: {customer_id}"
    return "\n".join(str(r) for r in rows)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(server.app, host="127.0.0.1", port=8004)
