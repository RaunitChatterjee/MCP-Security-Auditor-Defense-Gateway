"""
scan.py — Phase 3 orchestrator (Day 11 deliverable)
=======================================================
Runs the static scanner + dynamic tester, correlates and severity-scores
the results, prints a human summary, and writes one unified JSON findings
report to reports/.

Run:
    python3 -m scanner.scan
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from scanner.static_scanner import scan_range
from scanner.dynamic_tester import test_range
from scanner.severity import correlate, score_servers

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")


def run() -> dict:
    static_findings = scan_range()
    dynamic_findings = test_range()
    enriched = correlate(static_findings, dynamic_findings)
    server_scores = score_servers(enriched)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "servers": {},
    }
    for server, score in server_scores.items():
        report["servers"][server] = {
            **score,
            "findings": [f for f in enriched if f["server_name"] == server],
        }
    return report


def _print_human(report: dict):
    sev_rank = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    ranked = sorted(report["servers"].items(),
                     key=lambda kv: (-sev_rank[kv[1]["highest_severity"]], -kv[1]["total_risk_score"]))

    print(f"{'SERVER':<22} {'RISK SCORE':<11} {'HIGHEST SEV':<12} {'CONFIRMED/TOTAL'}")
    for server, s in ranked:
        print(f"{server:<22} {s['total_risk_score']:<11} {s['highest_severity']:<12} "
              f"{s['confirmed_count']}/{s['finding_count']}")

    print("\n" + "=" * 70)
    for server, s in ranked:
        print(f"\n### {server}  (risk score: {s['total_risk_score']}, "
              f"highest: {s['highest_severity']})")
        for f in sorted(s["findings"], key=lambda f: -sev_rank[f["severity"]]):
            tool = f" [{f['tool_name']}]" if f["tool_name"] else ""
            tag = "✓ CONFIRMED LIVE" if f["confirmed_live"] else "  static-only"
            print(f"  [{f['severity']:<8}] {tag:<18} {f['rule_id']}{tool} — {f['title']}")


if __name__ == "__main__":
    report = run()
    _print_human(report)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = os.path.join(REPORTS_DIR, f"scan_report_{ts}.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[*] Unified findings report written to {out_path}")
