import { useEffect, useState } from "react";
import TopNav from "./components/TopNav.jsx";
import Hero from "./components/Hero.jsx";
import InspectionLane from "./components/InspectionLane.jsx";
import LiveAttackConsole from "./components/LiveAttackConsole.jsx";
import FindingsLedger from "./components/FindingsLedger.jsx";
import GatewayFeed from "./components/GatewayFeed.jsx";
import VulnIndex from "./components/VulnIndex.jsx";
import Footer from "./components/Footer.jsx";
import { buildLaneItems } from "./data/laneItems.js";
import seed from "./data/seed.json";

const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL || "http://127.0.0.1:9000";

export default function App() {
  const [scanReport, setScanReport] = useState(seed.scan_report);
  const [gatewayEvents, setGatewayEvents] = useState(seed.gateway_events);
  const [live, setLive] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(`${GATEWAY_URL}/api/findings`)
      .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
      .then((data) => {
        if (cancelled) return;
        if (data.scanner_report) setScanReport(data.scanner_report);
        setLive(true);
      })
      .catch(() => {
        // gateway not running locally — the bundled real capture from the
        // actual Phase 1-4 runs is shown instead, which is expected.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const laneItems = buildLaneItems({ gateway_events: gatewayEvents });

  return (
    <>
      <TopNav />
      <Hero />

      <section className="section" id="findings" style={{ paddingTop: 48 }}>
        <div className="wrap">
          <div className="section-head">
            <span className="kicker">Step 1 — Scan</span>
            <h2>What the scanner found</h2>
            <p>Each server's config checked on paper, then actually probed live — a finding only counts as "confirmed" when both agree.</p>
          </div>
          <FindingsLedger scanReport={scanReport} />
        </div>
      </section>

      <section className="section" id="activity" style={{ paddingTop: 0 }}>
        <div className="wrap">
          <div className="section-head">
            <span className="kicker">Step 2 — Defend</span>
            <h2>Gateway activity</h2>
            <p>Every call the gateway blocked outright, plus the sneakier sequences it flagged after watching a whole session.</p>
          </div>
          <GatewayFeed events={gatewayEvents} />
        </div>
      </section>

      <section className="section" id="live-attack" style={{ paddingTop: 0 }}>
        <div className="wrap">
          <div className="section-head">
            <span className="kicker">Step 3 — Visualize</span>
            <h2>See it in action</h2>
            <p>
              {live
                ? "Connected to a live gateway — the console below fires real requests right now."
                : "No live gateway detected, so the replay below shows a real captured run instead. Start the backend (see the README) to fire live attacks."}
            </p>
          </div>
          <div style={{ display: "grid", gap: 16 }}>
            <InspectionLane items={laneItems} />
            <LiveAttackConsole />
          </div>
        </div>
      </section>

      <section className="section" id="vuln-classes" style={{ paddingTop: 0 }}>
        <div className="wrap">
          <div className="section-head">
            <span className="kicker">Reference</span>
            <h2>The 5 vulnerability classes this project covers</h2>
            <p>Mapped to the OWASP Top 10 for LLM Applications.</p>
          </div>
          <VulnIndex />
        </div>
      </section>

      <Footer />
    </>
  );
}
