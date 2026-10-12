function timeOnly(ts) {
  try {
    return new Date(ts).toISOString().slice(11, 19);
  } catch {
    return "--:--:--";
  }
}

export default function GatewayFeed({ events }) {
  const alerts = (events || [])
    .filter((e) => e.decision === "BLOCKED" || e.sequence_alert)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 12);

  if (alerts.length === 0) {
    return (
      <div className="card card-pad">
        <p>No gateway alerts yet — run <code>python3 -m scripts.gateway_demo</code> against a live gateway.</p>
      </div>
    );
  }

  return (
    <div className="card card-pad">
      <div className="timeline">
        {alerts.map((e, i) => {
          const isBlocked = e.decision === "BLOCKED";
          const label = isBlocked ? e.rule_id : e.sequence_alert.rule_id;
          const reason = isBlocked ? e.reason : e.sequence_alert.detail;
          return (
            <div className="timeline-row" key={i}>
              <div className={`timeline-bar ${isBlocked ? "danger" : "warn"}`} />
              <div className="trow-main">
                <div className="trow-top">
                  <span className="tool-name">{e.server_name}.{e.tool}</span>
                  <span className={`badge ${isBlocked ? "badge-danger" : "badge-warn"}`}>
                    {isBlocked ? "Blocked" : "Flagged"} · {label}
                  </span>
                </div>
                <div className="reason">{reason}</div>
                <div className="meta">{timeOnly(e.timestamp)} · session {e.session_id}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
