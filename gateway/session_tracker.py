"""
Behavioral monitoring / session tracking (Day 14)
======================================================
The whole point of Day 8's sequence-level attack is that no single call
looks wrong — POL-EXEC-001 / POL-FS-001 (Day 13) can't catch it, because
neither rule fires on any individual call. This module is the part of the
gateway that looks at a SESSION's call history instead of one call at a
time.

Two generic signals (neither hardcoded to our range's server/tool names):

  SEQ-001 "list-then-harvest" — a tool response that LOOKS like a list of
  short tokens (IDs, filenames, etc.), followed shortly after by >=2 more
  calls (to any tool, any server, same session) whose argument values
  match tokens from that list. This is exactly the Day 8 attack's shape:
  read a list, then loop a single-item lookup over it.

  SEQ-002 "rapid repeated calls" — the same tool called with >=3 distinct
  argument combinations within a short window, with no list-read source
  identified. Catches straightforward enumeration/brute-force patterns
  that don't happen to originate from a prior list call.

Both are intentionally heuristic — a real gateway would tune thresholds
against production traffic. The thresholds here (15s window, 2-call
harvest, 3-call repetition) are sized to the pacing in exploit4_sequence.py
(0.2s between calls) with generous headroom for a slower, more careful
real attacker.
"""

from __future__ import annotations

import time
from collections import defaultdict

SESSION_WINDOW_SECONDS = 15
HARVEST_MATCH_THRESHOLD = 2
REPEAT_THRESHOLD = 3


def _extract_list_tokens(response_text: str) -> list[str]:
    lines = [ln.strip() for ln in response_text.splitlines() if ln.strip()]
    tokens = [ln for ln in lines if len(ln) <= 20 and " " not in ln]
    return tokens if len(tokens) >= 2 else []


class SessionTracker:
    def __init__(self):
        self.history: dict[str, list[dict]] = defaultdict(list)

    def record(self, session_id: str, server_name: str, tool_name: str,
               arguments: dict, response_text: str):
        self.history[session_id].append({
            "ts": time.time(), "server_name": server_name, "tool": tool_name,
            "arguments": dict(arguments), "response": response_text,
        })

    def check_sequence(self, session_id: str) -> dict | None:
        events = self.history.get(session_id, [])
        if len(events) < 2:
            return None
        now = time.time()
        recent = [e for e in events if now - e["ts"] <= SESSION_WINDOW_SECONDS]

        # --- Signal A: list-then-harvest --------------------------------
        for i, e in enumerate(recent):
            tokens = _extract_list_tokens(e["response"])
            if not tokens:
                continue
            later = recent[i + 1:]
            matches = [
                m for m in later
                if any(str(v) in tokens for v in m["arguments"].values())
            ]
            if len(matches) >= HARVEST_MATCH_THRESHOLD:
                return {
                    "rule_id": "SEQ-001",
                    "title": "Sequence-level exfiltration suspected (list-then-harvest)",
                    "severity": "Critical",
                    "detail": (
                        f"Session read a {len(tokens)}-item list from "
                        f"{e['server_name']}.{e['tool']}, then made {len(matches)} subsequent "
                        f"call(s) to {sorted({m['tool'] for m in matches})} using values from "
                        f"that list, within {SESSION_WINDOW_SECONDS}s. Each call individually "
                        f"matches its tool's intended usage — only the sequence is anomalous."
                    ),
                    "step_count": len(matches) + 1,
                }

        # --- Signal B: rapid repeated calls, same tool ----------------------
        by_tool: dict[tuple, list] = defaultdict(list)
        for e in recent:
            by_tool[(e["server_name"], e["tool"])].append(e)
        for (server_name, tool), calls in by_tool.items():
            distinct_args = {str(sorted(c["arguments"].items())) for c in calls}
            if len(distinct_args) >= REPEAT_THRESHOLD:
                return {
                    "rule_id": "SEQ-002",
                    "title": "Rapid repeated calls to the same tool with distinct arguments",
                    "severity": "High",
                    "detail": (
                        f"{len(distinct_args)} distinct-argument calls to {server_name}.{tool} "
                        f"within {SESSION_WINDOW_SECONDS}s — possible enumeration, not sourced "
                        f"from an identified prior list call."
                    ),
                    "step_count": len(distinct_args),
                }
        return None
