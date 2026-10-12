const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };

function sevBadge(sev) {
  if (sev === "Critical") return "badge-danger";
  if (sev === "High") return "badge-warn";
  return "badge-neutral";
}

export default function FindingsLedger({ scanReport }) {
  if (!scanReport) {
    return (
      <div className="card card-pad">
        <p>No scan report loaded yet — run <code>python3 -m scanner.scan</code>.</p>
      </div>
    );
  }

  const servers = Object.entries(scanReport.servers || {}).sort(
    (a, b) => b[1].total_risk_score - a[1].total_risk_score
  );

  const allFindings = servers.flatMap(([name, s]) =>
    (s.findings || []).map((f) => ({ ...f, server_name: name }))
  ).sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

  return (
    <div>
      <div className="stat-grid">
        {servers.map(([name, s]) => (
          <div className="stat-card" key={name}>
            <div className="name">{name}</div>
            <div className="score-row">
              <span className="score" style={{ color: s.highest_severity === "Critical" ? "var(--danger)" : s.highest_severity === "High" ? "var(--warn)" : "var(--ink)" }}>
                {s.total_risk_score}
              </span>
              <span className="score-label">risk score</span>
            </div>
            <div className="sub">{s.confirmed_count}/{s.finding_count} confirmed live · highest: {s.highest_severity}</div>
          </div>
        ))}
      </div>

      <div className="card table-card">
        <table className="ftable">
          <thead>
            <tr>
              <th>Server</th>
              <th>Rule</th>
              <th>Severity</th>
              <th>Status</th>
              <th>What it means</th>
            </tr>
          </thead>
          <tbody>
            {allFindings.map((f, i) => (
              <tr key={i}>
                <td className="server-cell">{f.server_name}{f.tool_name ? ` · ${f.tool_name}` : ""}</td>
                <td className="rule-cell">{f.rule_id}</td>
                <td><span className={`badge ${sevBadge(f.severity)}`}>{f.severity}</span></td>
                <td>
                  <span className={`badge ${f.confirmed_live ? "badge-danger" : "badge-neutral"}`}>
                    {f.confirmed_live ? "Confirmed live" : "Static only"}
                  </span>
                </td>
                <td className="detail-cell">
                  <strong>{f.title}.</strong> {f.detail}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
