// Shapes real gateway_events (captured in seed.json from actual Phase 4 runs)
// into the ordered sequence the hero inspection lane replays. We deliberately
// use two real session runs chronologically — not synthetic/mock data — so
// the lane is literally replaying what the gateway actually did.

const NARRATIVE_SESSIONS = ["demo-session-2", "attacker-session-1"];

function shortCall(ev) {
  const argStr = Object.entries(ev.arguments || {})
    .map(([k, v]) => `${k}=${JSON.stringify(String(v)).slice(0, 28)}`)
    .join(", ");
  return `${ev.tool}(${argStr})`;
}

export function buildLaneItems(seed) {
  const events = (seed.gateway_events || [])
    .filter((e) => NARRATIVE_SESSIONS.includes(e.session_id))
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  return events.map((ev, i) => {
    let verdict = "cleared";
    let stampLabel = "CLEARED";
    let note = "";

    if (ev.decision === "BLOCKED") {
      verdict = "blocked";
      stampLabel = "BLOCKED";
      note = `${ev.rule_id} — ${ev.reason}`;
    } else if (ev.sequence_alert) {
      verdict = "flagged";
      stampLabel = "FLAGGED";
      note = `${ev.sequence_alert.rule_id} — ${ev.sequence_alert.title}`;
    } else {
      note = "passed policy + behavioral checks";
    }

    return {
      id: `${ev.session_id}-${i}`,
      call: shortCall(ev),
      server: ev.server_name,
      verdict,
      stampLabel,
      note,
    };
  });
}
