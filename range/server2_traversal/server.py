"""
Vulnerable MCP Server #2 — Path Traversal
===========================================
Models a "project files" MCP tool server: an agent-facing tool that lets an
LLM agent read files from a project's working directory — another very
common MCP tool pattern (file-access / workspace servers).

VULNERABILITY (intentional): `read_file` joins the caller-supplied relative
path onto a sandbox base directory with naive `os.path.join`, then opens it,
without resolving and checking that the final path still lives inside the
sandbox. A caller can pass `../../../../etc/passwd` (or an absolute path) to
read arbitrary files outside the intended workspace scope. This mirrors the
path-traversal class disclosed in several MCP filesystem-tool servers in the
2026 CVE wave.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from mcp_lite import MCPLiteServer  # noqa: E402

SANDBOX_DIR = os.path.join(os.path.dirname(__file__), "workspace")

server = MCPLiteServer(name="project-files-mcp", version="0.1.0", require_auth=False)


def _ensure_sandbox():
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    notes_path = os.path.join(SANDBOX_DIR, "notes.txt")
    if not os.path.exists(notes_path):
        with open(notes_path, "w") as f:
            f.write("TODO: finish the quarterly report.\n")
    # A perfectly legitimate, in-scope project file — part of the Day 8
    # sequence-level attack's setup: reading this file is NOT a vulnerable
    # call on its own (no traversal, no injection), it's just a project
    # file an agent could plausibly need. The attack chain starts here.
    ids_path = os.path.join(SANDBOX_DIR, "customer_ids.txt")
    if not os.path.exists(ids_path):
        with open(ids_path, "w") as f:
            f.write("c001\nc002\nc003\n")


@server.tool(description="Read a text file from the current project workspace, by relative path.")
def read_file(path: str) -> str:
    # --- VULNERABLE LINE -------------------------------------------------
    # No normalization, no containment check: os.path.join happily returns
    # a path outside SANDBOX_DIR when `path` contains "../" segments or is
    # itself absolute (os.path.join discards the base dir entirely for an
    # absolute second argument).
    target = os.path.join(SANDBOX_DIR, path)
    with open(target, "r", errors="replace") as f:
        return f.read()
    # -----------------------------------------------------------------------


@server.tool(description="List files in the current project workspace.")
def list_files() -> str:
    return "\n".join(sorted(os.listdir(SANDBOX_DIR)))


_ensure_sandbox()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(server.app, host="127.0.0.1", port=8002)
