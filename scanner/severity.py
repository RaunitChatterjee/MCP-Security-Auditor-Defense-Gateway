"""
Severity / scoring engine (Day 11)
======================================
Merges static_scanner findings (what a server's manifest CLAIMS) with
dynamic_tester findings (what the server ACTUALLY does when probed) into
one per-server risk score, and — importantly — marks each static finding
as "confirmed live" when a matching dynamic probe reproduced it, or
"static-only" when it didn't.

That distinction is the whole point of running both halves: a manifest
claim nobody has verified live is a weaker signal than one a live exploit
reproduced, and (see project-files-mcp below) a dynamic probe missing
something a static read still caught is itself useful information, not a
reason to trust the dynamic result over the static one.
"""

from __future__ import annotations

SEVERITY_WEIGHT = {"Critical": 40, "High": 25, "Medium": 10, "Low": 5}
CONFIRMED_BONUS = 10

# static rule_id -> the dynamic rule_id that would reproduce it live, if any
STATIC_TO_DYNAMIC = {
    "AUTH-001": "DYN-AUTH-001",
    "EXEC-001": "DYN-EXEC-001",
    "FS-001": "DYN-FS-001",
    "SCOPE-001": "DYN-SCOPE-001",
}


def correlate(static_findings: list, dynamic_findings: list) -> list[dict]:
    """Return one enriched dict per static finding, with confirmation status."""
    dyn_by_server: dict[str, set] = {}
    for d in dynamic_findings:
        dyn_by_server.setdefault(d.server_name, set()).add(d.rule_id)

    enriched = []
    for f in static_findings:
        dyn_rule = STATIC_TO_DYNAMIC.get(f.rule_id)
        confirmed = dyn_rule is not None and dyn_rule in dyn_by_server.get(f.server_name, set())
        weight = SEVERITY_WEIGHT.get(f.severity, 0) + (CONFIRMED_BONUS if confirmed else 0)
        status = (
            "Confirmed live" if confirmed else
            ("Static-only — no live dynamic probe for this class" if dyn_rule is None else
             "Static-only — dynamic probe did not reproduce it (see known limitations)")
        )
        enriched.append({
            "server_name": f.server_name, "rule_id": f.rule_id, "title": f.title,
            "tool_name": f.tool_name, "severity": f.severity, "status": status,
            "confirmed_live": confirmed, "risk_weight": weight, "detail": f.detail,
        })
    return enriched


def score_servers(enriched_findings: list[dict]) -> dict[str, dict]:
    sev_rank = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    servers: dict[str, dict] = {}
    for f in enriched_findings:
        s = servers.setdefault(f["server_name"], {
            "total_risk_score": 0, "finding_count": 0, "confirmed_count": 0,
            "highest_severity": "Low",
        })
        s["total_risk_score"] += f["risk_weight"]
        s["finding_count"] += 1
        s["confirmed_count"] += 1 if f["confirmed_live"] else 0
        if sev_rank[f["severity"]] > sev_rank[s["highest_severity"]]:
            s["highest_severity"] = f["severity"]
    return servers
