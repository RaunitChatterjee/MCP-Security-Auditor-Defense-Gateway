import { useEffect, useRef, useState } from "react";

const PHASE_TIMING = { enter: 650, gate: 900, exit: 650 };

const VERDICT_BADGE = {
  cleared: { cls: "badge-safe", label: "Cleared" },
  blocked: { cls: "badge-danger", label: "Blocked" },
  flagged: { cls: "badge-warn", label: "Flagged" },
};

export default function InspectionLane({ items }) {
  const [index, setIndex] = useState(-1);
  const [phase, setPhase] = useState("idle"); // idle | enter | gate | exit
  const [running, setRunning] = useState(false);
  const timerRef = useRef(null);

  useEffect(() => () => clearTimeout(timerRef.current), []);

  function start() {
    if (items.length === 0) return;
    setRunning(true);
    setIndex(0);
    setPhase("enter");
  }

  function reset() {
    clearTimeout(timerRef.current);
    setRunning(false);
    setIndex(-1);
    setPhase("idle");
  }

  useEffect(() => {
    if (!running || index < 0) return;
    clearTimeout(timerRef.current);

    if (phase === "enter") {
      timerRef.current = setTimeout(() => setPhase("gate"), PHASE_TIMING.enter);
    } else if (phase === "gate") {
      timerRef.current = setTimeout(() => setPhase("exit"), PHASE_TIMING.gate);
    } else if (phase === "exit") {
      timerRef.current = setTimeout(() => {
        if (index + 1 < items.length) {
          setIndex(index + 1);
          setPhase("enter");
        } else {
          setRunning(false);
          setPhase("idle");
        }
      }, PHASE_TIMING.exit);
    }
    return () => clearTimeout(timerRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, index, running]);

  const current = index >= 0 ? items[index] : null;
  const left = phase === "enter" ? "14%" : phase === "gate" ? "50%" : phase === "exit" ? "86%" : "14%";
  const showBadge = phase === "gate" || phase === "exit";

  return (
    <div className="lane-panel">
      <div className="lane-panel-head">
        <div>
          <h3>Replay: real captured traffic</h3>
          <p>A real recorded run — command injection, path traversal, and a multi-step data-exfiltration attack, replayed in order.</p>
        </div>
        <div className="pill-row">
          <button className="pill-btn" onClick={start} disabled={running || items.length === 0} aria-pressed={running}>
            ▶ Run replay
          </button>
          <button className="pill-btn" onClick={reset} disabled={!running && index === -1}>
            Reset
          </button>
        </div>
      </div>

      <div className="lane-track" role="img" aria-label="Animation of tool calls being marked cleared, blocked, or flagged">
        <div className="lane-gate-line" />
        {current ? (
          <div className="lane-chip" style={{ left }} key={current.id}>
            <span className="call">{current.call}</span>
            <span className="server">{current.server}</span>
            {showBadge && (
              <div className="badge-row">
                <span className={`badge ${VERDICT_BADGE[current.verdict].cls}`}>
                  {VERDICT_BADGE[current.verdict].label}
                </span>
              </div>
            )}
          </div>
        ) : (
          <div className="lane-empty">
            {items.length === 0 ? "No captured traffic yet." : "Press \u201cRun replay\u201d to see it in action"}
          </div>
        )}
      </div>

      <div className="lane-legend">
        <span><span className="badge badge-safe">Cleared</span> passed every check</span>
        <span><span className="badge badge-danger">Blocked</span> matched a known attack pattern</span>
        <span><span className="badge badge-warn">Flagged</span> looked fine alone, suspicious as a sequence</span>
      </div>

      {current && showBadge && (
        <p className="lane-note"><strong>{VERDICT_BADGE[current.verdict].label}:</strong> {current.note}</p>
      )}
    </div>
  );
}
