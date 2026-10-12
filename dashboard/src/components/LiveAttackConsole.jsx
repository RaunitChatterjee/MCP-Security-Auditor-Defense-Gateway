import { useState } from "react";
import { callTool } from "../lib/mcpClient.js";
import { LIVE_ATTACKS } from "../data/liveAttacks.js";

const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL || "http://127.0.0.1:9000";

const VERDICT_BADGE = {
  cleared: { cls: "badge-safe", label: "Cleared" },
  blocked: { cls: "badge-danger", label: "Blocked" },
  flagged: { cls: "badge-warn", label: "Flagged" },
};

function argsLabel(args) {
  return Object.entries(args)
    .map(([k, v]) => `${k}=${JSON.stringify(String(v)).slice(0, 36)}`)
    .join(", ");
}

export default function LiveAttackConsole() {
  const [selected, setSelected] = useState("cmdinj");
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);

  async function run() {
    setRunning(true);
    setResults([]);
    setError(null);
    const sessionId = `live-${Date.now().toString(36)}`;
    const attack = LIVE_ATTACKS[selected];

    try {
      if (attack.isSequence) {
        const s1 = attack.firstStep;
        const r1 = await callTool(GATEWAY_URL, s1.serverId, sessionId, s1.tool, s1.args);
        setResults((prev) => [...prev, { label: `${s1.tool}(${argsLabel(s1.args)})`, ...r1 }]);

        const ids = (r1.raw || "").split("\n").map((s) => s.trim()).filter(Boolean);
        for (const id of ids) {
          await new Promise((res) => setTimeout(res, 350));
          const step = attack.harvestStep(id);
          const r = await callTool(GATEWAY_URL, step.serverId, sessionId, step.tool, step.args);
          setResults((prev) => [...prev, { label: `${step.tool}(${argsLabel(step.args)})`, ...r }]);
        }
      } else {
        for (const step of attack.steps) {
          const r = await callTool(GATEWAY_URL, step.serverId, sessionId, step.tool, step.args);
          setResults((prev) => [...prev, { label: `${step.tool}(${argsLabel(step.args)})`, ...r }]);
        }
      }
    } catch {
      setError(
        `Can't reach the gateway at ${GATEWAY_URL}. Start it with: ` +
        `python3 -m uvicorn gateway.app:app --port 9000 (and the 4 range servers on 8001-8004) ` +
        `— or just run "bash scripts/dev_up.sh" from the repo root.`
      );
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="lane-panel" id="live-attack">
      <div className="lane-panel-head">
        <div>
          <h3>Fire a real attack, right now</h3>
          <p>{LIVE_ATTACKS[selected].description}</p>
        </div>
      </div>

      <div className="pill-row" style={{ marginBottom: 14 }}>
        {Object.entries(LIVE_ATTACKS).map(([key, a]) => (
          <button
            key={key}
            className="pill-btn"
            aria-pressed={selected === key}
            onClick={() => setSelected(key)}
            disabled={running}
          >
            {a.label}
          </button>
        ))}
      </div>

      <button className="btn btn-primary" onClick={run} disabled={running}>
        {running ? "Running…" : "▶ Run against the live gateway"}
      </button>

      {error && <p className="lane-note">{error}</p>}

      {results.length > 0 && (
        <div className="timeline" style={{ marginTop: 20 }}>
          {results.map((r, i) => (
            <div className="timeline-row" key={i}>
              <div className={`timeline-bar ${r.verdict === "blocked" ? "danger" : r.verdict === "flagged" ? "warn" : ""}`} />
              <div className="trow-main">
                <div className="trow-top">
                  <span className="tool-name" style={{ color: "#fff" }}>{r.label}</span>
                  <span className={`badge ${VERDICT_BADGE[r.verdict].cls}`}>
                    {VERDICT_BADGE[r.verdict].label}{r.ruleId ? ` · ${r.ruleId}` : ""}
                  </span>
                </div>
                {r.message && <div className="reason" style={{ color: "var(--dark-soft)" }}>{r.message}</div>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
