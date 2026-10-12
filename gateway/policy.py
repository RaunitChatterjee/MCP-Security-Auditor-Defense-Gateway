"""
Input sanitization / policy enforcement (Day 13)
====================================================
Pattern-based pre-filters the gateway applies to every `tools/call` BEFORE
it reaches a backend server. Deliberately simple, deliberately generic —
these aren't tied to our 4 range servers' specific tool names, just to
argument shape, which is the same "argument-shape mismatch" heuristic the
Day 4 IOC sheet called out as the most reusable signal across vuln classes.

Two rules, matching the Phase 2 exploits this gateway has to block:
  POL-EXEC-001 — shell metacharacters in ANY string argument
  POL-FS-001   — traversal sequences or absolute paths in a path/file-named argument

This is intentionally a blocklist, not a full parser — a determined
attacker could likely find an encoding this misses (that's a known,
honest limitation worth naming in the write-up, same spirit as the
dynamic tester's documented auth-probe gap). The point of this layer is to
stop the EXACT payload classes from Phase 2, in real time, not to claim
complete coverage.
"""

from __future__ import annotations

import re

SHELL_META_RE = re.compile(r"[;&|`]|\$\(")
TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\\\")
ABS_PATH_RE = re.compile(r"^(/|[A-Za-z]:\\\\)")
PATH_LIKE_PARAM_RE = re.compile(r"path|file", re.IGNORECASE)


def check_policy(tool_name: str, arguments: dict) -> tuple[bool, str | None, str | None]:
    """Returns (blocked, rule_id, reason). Does not mutate arguments."""
    for key, value in arguments.items():
        if not isinstance(value, str):
            continue
        if SHELL_META_RE.search(value):
            return True, "POL-EXEC-001", (
                f"Shell metacharacter detected in argument '{key}' "
                f"(matches the Day 5 command-injection payload shape)"
            )
        if PATH_LIKE_PARAM_RE.search(key):
            if TRAVERSAL_RE.search(value) or ABS_PATH_RE.match(value):
                return True, "POL-FS-001", (
                    f"Traversal sequence or absolute path detected in path-like argument '{key}' "
                    f"(matches the Day 6 path-traversal payload shape)"
                )
    return False, None, None
