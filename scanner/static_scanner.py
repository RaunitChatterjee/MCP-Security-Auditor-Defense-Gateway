"""
Static config scanner (Day 9)
=================================
Walks range/*/manifest.json, applies a fixed rule set, and produces
structured findings — no network calls, no live server needed. This is the
"what does the server CLAIM about itself" half of the scanner; Phase 3's
dynamic tester (Day 10) is the "what does the server ACTUALLY do when
poked" half, and Day 11 unifies both into one severity-scored report.

Each rule is a small function: (manifest) -> list[Finding]. Adding a new
check means adding a new rule function and registering it in RULES — no
other code needs to change, which matters once this scans real third-party
MCP manifests, not just the 4-server range.

Run:
    python3 -m scanner.static_scanner                  # scan the whole range/
    python3 -m scanner.static_scanner --json            # machine-readable output
"""

from __future__ import annotations

import glob
import json
import os
import sys
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    server_name: str
    manifest_path: str
    rule_id: str
    title: str
    severity: str  # Critical | High | Medium | Low
    detail: str
    tool_name: str | None = None


RANGE_ROOT = os.path.join(os.path.dirname(__file__), "..", "range")


# ---- individual rules ------------------------------------------------------

def rule_missing_auth(m: dict) -> list[Finding]:
    auth = m.get("auth", {})
    if auth.get("required") is False:
        has_write = any(t.get("declared_scope") == "read-write" for t in m.get("tools", []))
        has_pii = any(t.get("accesses_pii") for t in m.get("tools", []))
        sev = "Critical" if (has_write or has_pii) else "High"
        return [Finding(
            server_name=m["server_name"], manifest_path="", rule_id="AUTH-001",
            title="Server requires no authentication",
            severity=sev,
            detail="auth.required is false — every tool is callable by any party that can "
                    "reach the endpoint, with no identity check." +
                    (" Server exposes PII and/or write tools, raising severity to Critical."
                     if (has_write or has_pii) else ""),
        )]
    return []


def rule_untrusted_source(m: dict) -> list[Finding]:
    src = m.get("registry_source")
    if src == "unverified-url":
        return [Finding(
            server_name=m["server_name"], manifest_path="", rule_id="SRC-001",
            title="Server installed from an unverified source",
            severity="Medium",
            detail=f"registry_source=unverified-url. {m.get('source_note', '')}",
        )]
    return []


def rule_shell_subprocess(m: dict) -> list[Finding]:
    findings = []
    for t in m.get("tools", []):
        if t.get("executes_subprocess") and t.get("subprocess_shell"):
            sev = "Critical" if t.get("accepts_free_form_query") else "High"
            findings.append(Finding(
                server_name=m["server_name"], manifest_path="", rule_id="EXEC-001",
                title="Tool spawns a shell subprocess",
                severity=sev, tool_name=t["name"],
                detail="executes_subprocess + subprocess_shell=true: any argument that reaches "
                       "this tool unsanitized is a potential OS command injection path." +
                       (" Tool also accepts a free-form query — high exploitability."
                        if t.get("accepts_free_form_query") else ""),
            ))
    return findings


def rule_unsandboxed_filesystem(m: dict) -> list[Finding]:
    findings = []
    for t in m.get("tools", []):
        if t.get("filesystem_access") and t.get("sandbox_enforced_in_code") is False:
            findings.append(Finding(
                server_name=m["server_name"], manifest_path="", rule_id="FS-001",
                title="Filesystem tool declares a sandbox root but doesn't enforce it in code",
                severity="High", tool_name=t["name"],
                detail=f"declared_sandbox_root={t.get('declared_sandbox_root')!r} but "
                       "sandbox_enforced_in_code=false — manifest claims containment the "
                       "implementation doesn't actually perform. Confirm with the dynamic tester.",
            ))
    return findings


def rule_over_permissioned_scope(m: dict) -> list[Finding]:
    findings = []
    for t in m.get("tools", []):
        scope = t.get("declared_scope", "")
        if "single-record" in scope and t.get("accepts_free_form_query"):
            findings.append(Finding(
                server_name=m["server_name"], manifest_path="", rule_id="SCOPE-001",
                title="Tool's free-form parameter exceeds its declared single-record scope",
                severity="High", tool_name=t["name"],
                detail=f"declared_scope={scope!r} but accepts a free-form "
                       f"'{t.get('free_form_param_name')}' parameter" +
                       (" that reaches the backend query directly — classic least-privilege "
                        "violation (over-permissioned tool)." if t.get("free_form_reaches_backend_query")
                        else "."),
            ))
    return findings


def rule_full_table_exposure(m: dict) -> list[Finding]:
    findings = []
    for t in m.get("tools", []):
        if t.get("returns_full_table") and t.get("accesses_pii"):
            findings.append(Finding(
                server_name=m["server_name"], manifest_path="", rule_id="SCOPE-002",
                title="Tool returns a full-table dump of PII-bearing records",
                severity="Medium" if m.get("auth", {}).get("required") else "High",
                tool_name=t["name"],
                detail="returns_full_table=true on a PII-bearing resource — consider whether "
                       "this tool needs to exist at all for an agent's stated task scope.",
            ))
    return findings


def rule_privileged_target_write(m: dict) -> list[Finding]:
    findings = []
    for t in m.get("tools", []):
        if t.get("declared_scope") == "read-write" and t.get("can_target_privileged_accounts"):
            findings.append(Finding(
                server_name=m["server_name"], manifest_path="", rule_id="WRITE-001",
                title="Write tool can target privileged/admin accounts with no scoping",
                severity="Critical", tool_name=t["name"],
                detail="No declared restriction preventing this write tool from targeting "
                       "admin/service accounts rather than only the caller's own scope.",
            ))
    return findings


RULES = [
    rule_missing_auth,
    rule_untrusted_source,
    rule_shell_subprocess,
    rule_unsandboxed_filesystem,
    rule_over_permissioned_scope,
    rule_full_table_exposure,
    rule_privileged_target_write,
]


def scan_manifest(path: str) -> list[Finding]:
    with open(path) as f:
        manifest = json.load(f)
    findings = []
    for rule in RULES:
        for finding in rule(manifest):
            finding.manifest_path = path
            findings.append(finding)
    return findings


def scan_range(range_root: str = RANGE_ROOT) -> list[Finding]:
    all_findings = []
    for path in sorted(glob.glob(os.path.join(range_root, "*", "manifest.json"))):
        all_findings.extend(scan_manifest(path))
    return all_findings


def _print_human(findings: list[Finding]):
    by_server: dict[str, list[Finding]] = {}
    for f in findings:
        by_server.setdefault(f.server_name, []).append(f)

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for server, items in by_server.items():
        print(f"\n=== {server} ===")
        for f in sorted(items, key=lambda f: sev_order.get(f.severity, 9)):
            tool = f" [{f.tool_name}]" if f.tool_name else ""
            print(f"  [{f.severity:<8}] {f.rule_id}{tool} — {f.title}")
            print(f"             {f.detail}")
    print(f"\nTotal findings: {len(findings)} across {len(by_server)} server(s)")


if __name__ == "__main__":
    findings = scan_range()
    if "--json" in sys.argv:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        _print_human(findings)
