# MCP Security Auditor & Defense Gateway (dashboard)

The Phase 5 React dashboard. Clean modern layout, light surface, one vivid
amber accent, and a plain 3-color severity system (green = cleared, orange
= flagged, red = blocked/critical) so it reads at a glance without decoding
any jargon first.

## Run it
```bash
npm install
npm run dev        # http://localhost:5173
```

It works two ways:
- **Standalone** — ships with `src/data/seed.json`, a real capture from an
  actual Phase 1-4 run (real exploit payloads, real gateway decisions, real
  scanner findings). Opens and works with zero backend running.
- **Live** — if `python3 -m uvicorn gateway.app:app --port 9000` is running
  (with the 4 range servers up too — or just `bash scripts/dev_up.sh` from
  the repo root), the dashboard fetches `GET /api/findings` on load and
  switches to live data. The gateway's CORS config already allows
  `localhost:5173`/`4173`. Override the URL with `VITE_GATEWAY_URL` if your
  gateway runs somewhere else.

## Page structure (top to bottom)
1. **Hero** — one-sentence explanation of the whole project, plus a
   "Scan → Defend → Visualize" 3-step strip so the flow is clear before any
   data shows up.
2. **What the scanner found** (`#findings`) — per-server risk-score cards,
   then the full findings table with severity + confirmed-live badges.
3. **Gateway activity** (`#activity`) — a timeline of every blocked call and
   behavioral (sequence) alert.
4. **See it in action** (`#live-attack`) — the captured-traffic replay, and
   below it the **live attack console**: pick one of the 4 exploit classes
   and it fires the real Phase 2 payload from your browser straight at the
   live gateway via `fetch`, no server-side script involved. Honest by
   design: "Unauthenticated access" comes back **cleared**, not blocked —
   the gateway doesn't enforce auth itself (that's the scanner's job, see
   `AUTH-001` in the findings table) — and the console shows that gap live
   rather than faking a block.
5. **Vulnerability classification index** — the 5 vuln classes, OWASP-mapped.

## Structure
```
src/
  App.jsx                   — page layout + live-fetch-with-fallback logic
  components/
    TopNav.jsx                — sticky nav + GitHub link
    Hero.jsx                  — headline + "how it works" 3-step strip
    InspectionLane.jsx        — animated replay of real gateway events
    LiveAttackConsole.jsx     — fires a real attack at the live gateway from the browser
    FindingsLedger.jsx        — scanner report, severity-scored
    GatewayFeed.jsx           — blocked calls + sequence alerts, as a timeline
    VulnIndex.jsx             — the 5 vuln classes, OWASP-mapped
    Footer.jsx
  lib/
    mcpClient.js              — browser-side MCP JSON-RPC client (mirrors client/harness.py)
  data/
    seed.json                — real captured data (scan report + gateway events)
    laneItems.js              — shapes gateway_events into the lane's replay sequence
    liveAttacks.js             — the 4 live attack payload definitions
  styles.css                  — the whole visual identity (see design notes below)
```

## Design notes
Light surface (`#f6f6f9` background, white cards), vivid amber (`#f5a623`)
as the single brand accent, a dark near-black hero/panel for contrast. One
severity system used everywhere — green/orange/red badges — rather than a
metaphor to decode. Sora for headings, Inter for body text, monospace
reserved for actual code-like content (tool calls, rule IDs). Rounded cards
and soft shadows throughout.

## Build for deployment
```bash
npm run build       # outputs to dist/
npm run preview     # serve the build locally to sanity-check it
```
