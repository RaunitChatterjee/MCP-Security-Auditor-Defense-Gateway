"""
Vulnerable MCP Server #1 — STDIO/OS Command Injection
======================================================
Models a realistic "git helper" MCP tool server: an agent-facing tool that
wraps local `git` CLI commands so an LLM agent can query repo history,
search commit logs, and check file blame — a very common pattern in coding-
assistant MCP servers.

VULNERABILITY (intentional): the `git_log` and `git_grep` tools build a
shell command string by directly interpolating the caller-supplied argument
and executing it with `shell=True`. This mirrors a real vulnerability class
disclosed across several MCP git/devtools servers in the Jan-Apr 2026 CVE
wave: tool arguments that reach a subprocess shell unsanitized, allowing an
attacker (or a prompt-injected agent) to break out of the intended command
and execute arbitrary OS commands with the server process's privileges.

Run:
    uvicorn range.server1_cmdinj.server:server.app --port 8001
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
from mcp_lite import MCPLiteServer  # noqa: E402

REPO_DIR = os.path.join(os.path.dirname(__file__), "sample_repo")

server = MCPLiteServer(name="git-helper-mcp", version="0.1.0", require_auth=False)


def _ensure_sample_repo():
    """Create a tiny throwaway git repo so git_log has something to show."""
    if os.path.isdir(os.path.join(REPO_DIR, ".git")):
        return
    os.makedirs(REPO_DIR, exist_ok=True)
    run = lambda *a: subprocess.run(a, cwd=REPO_DIR, check=True,
                                     capture_output=True)
    run("git", "init", "-q")
    run("git", "config", "user.email", "bot@example.com")
    run("git", "config", "user.name", "Range Bot")
    with open(os.path.join(REPO_DIR, "README.md"), "w") as f:
        f.write("# Sample repo for the MCP vulnerable range\n")
    run("git", "add", "README.md")
    run("git", "commit", "-q", "-m", "initial commit")


@server.tool(description="Show git commit log, optionally filtered by author name.")
def git_log(author: str = "") -> str:
    # --- VULNERABLE LINE -----------------------------------------------
    # `author` is interpolated straight into a shell string. A caller can
    # pass something like:  "" ; cat /etc/passwd #
    # to break out of the intended `--author=` argument entirely.
    cmd = f"git log --oneline --author='{author}'" if author else "git log --oneline"
    result = subprocess.run(cmd, shell=True, cwd=REPO_DIR,
                             capture_output=True, text=True, timeout=5)
    # ---------------------------------------------------------------------
    return result.stdout + result.stderr


@server.tool(description="Search commit messages and diffs for a text pattern.")
def git_grep(pattern: str) -> str:
    # --- VULNERABLE LINE -----------------------------------------------
    cmd = f"git log --all --oneline --grep='{pattern}'"
    result = subprocess.run(cmd, shell=True, cwd=REPO_DIR,
                             capture_output=True, text=True, timeout=5)
    # ---------------------------------------------------------------------
    return result.stdout + result.stderr


_ensure_sample_repo()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(server.app, host="127.0.0.1", port=8001)
