# MCP Security Auditor & Defense Gateway

Build-in-progress, following the 18-day roadmap. Status: **Phase 1-5 (Days 1-17) complete.** Phase 6 / Day 18 (final write-up) is all that's left.

## Structure
```
range/
  common/mcp_lite.py          # hand-rolled minimal MCP server runtime (JSON-RPC 2.0 / Streamable HTTP)
  server1_cmdinj/server.py    # vulnerable: OS command injection (git-helper-mcp)
  server2_traversal/server.py # vulnerable: path traversal (project-files-mcp)
  server3_noauth/server.py    # vulnerable: missing authentication (ops-console-mcp)
  server4_overpriv/server.py  # vulnerable: over-permissioned tool scope (crm-assistant-mcp)
client/
  harness.py                  # minimal MCP client — discover all range servers, call any tool
scripts/
  common/exploit_logger.py    # shared JSONL structured log capture (same schema as the gateway will emit)
  exploit1_cmdinj.py          # Day 5 — command injection
  exploit2_traversal.py       # Day 6 — path traversal
  exploit3_noauth.py          # Day 7 — unauthenticated read + write
  exploit4_sequence.py        # Day 8 — sequence-level exfiltration (the one per-call scanners miss)
scanner/
  static_scanner.py           # Day 9 — parses range/*/manifest.json, rule-based findings
  dynamic_tester.py           # Day 10 — schema-driven live probes (auth, cmd inj, traversal, scope)
  severity.py                 # Day 11 — correlates static+dynamic, severity-scores per server
  scan.py                     # Day 11 — orchestrator: run both, merge, print + write JSON report
gateway/
  policy.py                   # Day 13 — blocks cmd injection / path traversal patterns pre-forward
  session_tracker.py          # Day 14 — behavioral/sequence anomaly detection (SEQ-001, SEQ-002)
  app.py                      # Day 12 + 15 — FastAPI proxy entrypoint + unified /api/findings (CORS enabled for the dashboard)
dashboard/                    # Day 16 — React/Vite dashboard, see dashboard/README.md
docs/
  day1_threat_model_notes.md
  day4_ioc_reference.md       # exact exploit payloads + IOCs, all 4 servers
logs/                         # exploit + gateway event logs (JSONL), gitignored — a few sample runs committed
reports/                      # scan.py's unified findings reports (JSON), gitignored — one sample committed
```

Each range server now also ships a `manifest.json` (self-declared tool scopes,
auth posture, registry source) — this is what `static_scanner.py` reads.

## Quick start
```bash
pip install -r requirements.txt
bash scripts/dev_up.sh      # starts all 4 range servers + the gateway in the background
curl http://127.0.0.1:9000/healthz
python3 -m client.harness discover
bash scripts/dev_down.sh    # stops everything dev_up.sh started
```

## Running the range (manually, one at a time)
```bash
pip install fastapi uvicorn requests
python3 -m uvicorn range.server1_cmdinj.server:server.app --port 8001
python3 -m uvicorn range.server2_traversal.server:server.app --port 8002
python3 -m uvicorn range.server3_noauth.server:server.app --port 8003
python3 -m uvicorn range.server4_overpriv.server:server.app --port 8004
```
All four expose a single MCP endpoint at `POST /mcp` (JSON-RPC 2.0: `initialize`,
`tools/list`, `tools/call`) and a `GET /healthz`.

```bash
python3 -m client.harness discover            # list tools on every range server
python3 -m client.harness call 8001 git_log author=Range
```

## Running the exploit scripts
```bash
python3 -m scripts.exploit1_cmdinj      # command injection — server1
python3 -m scripts.exploit2_traversal   # path traversal — server2
python3 -m scripts.exploit3_noauth      # unauthenticated read+write — server3
python3 -m scripts.exploit4_sequence    # sequence-level exfiltration — server2 + server4 chained
```
Each writes a timestamped `.jsonl` log to `logs/` — one structured event per
tool call (server, tool, arguments, response, OWASP LLM category, vuln
class). This is the same event shape the Phase 4 gateway will emit for live
traffic and the same shape SOC Core ingests.

## Running the scanner
```bash
python3 -m scanner.static_scanner      # manifest-based findings, no live servers needed
python3 -m scanner.dynamic_tester      # live probes against the 4 range servers
python3 -m scanner.scan                # both, correlated + severity-scored -> reports/scan_report_*.json
```
`scan.py`'s output marks each finding **"✓ CONFIRMED LIVE"** (static claim
reproduced by a dynamic probe) or **"static-only"**. Worth knowing for the
write-up: `project-files-mcp`'s missing-auth finding currently shows
static-only — the generic auth probe only tests the server's *first* tool,
and that tool (`read_file`) throws a file-not-found error on the probe's
placeholder path before the auth gap would even show. The static scanner
still caught it correctly from the manifest. Documented as a known
limitation rather than quietly patched — it's a genuine, useful
demonstration of why the report correlates two independent methods instead
of trusting either alone.

## Done
- [x] Day 1 — threat model notes + vulnerability class reference (`docs/day1_threat_model_notes.md`)
- [x] Day 2 — servers 1 & 2 built, confirmed exploitable end-to-end
- [x] Day 3 — servers 3 & 4 built, confirmed exploitable end-to-end; client harness talking to all 4
- [x] Day 4 — full IOC reference sheet across all 4 servers (`docs/day4_ioc_reference.md`)
- [x] Day 5 — exploit script 1 (command injection), log capture confirmed
- [x] Day 6 — exploit script 2 (path traversal), log capture confirmed
- [x] Day 7 — exploit script 3 (unauthenticated read + write), log capture confirmed
- [x] Day 8 — exploit script 4 (sequence-level exfiltration: server2 → server4 chain), log capture confirmed
- [x] Day 9 — static config scanner, 12 findings across 4 servers from manifests alone
- [x] Day 10 — dynamic tester, 7 live-confirmed findings via generic schema-driven probes
- [x] Day 11 — severity engine + unified report (`scanner/scan.py`), all 4 servers ranked Critical/High

- [x] Day 12 — transparent proxy (`gateway/app.py`), legitimate traffic passes through unmodified
- [x] Day 13 — policy enforcement (`gateway/policy.py`), both Phase 2 exploits blocked live (POL-EXEC-001, POL-FS-001)
- [x] Day 14 — behavioral monitoring (`gateway/session_tracker.py`), Day 8 sequence attack detected (SEQ-001)
- [x] Day 15 — unified `/api/findings` (gateway alerts + latest scanner report) + SOC Core outbox hook

## Running the gateway
```bash
# with all 4 range servers already running (see above):
python3 -m uvicorn gateway.app:app --port 9000
python3 -m scripts.gateway_demo        # reproduces every Phase 4 claim end-to-end
curl http://127.0.0.1:9000/api/findings | python3 -m json.tool
```
Client calls go through `http://127.0.0.1:9000/gateway/{1-4}/mcp` instead of
hitting a backend port directly — `{1,2,3,4}` map to the 4 range servers in
the order they're listed above. Pass a stable `X-Session-Id` header (the
harness's `MCPClient(..., session_id=...)` does this) so the gateway can
correlate a session's call sequence — without it, every call gets a random
one-off session and Day 14's behavioral check can never see a pattern.

**Known limitation, documented on purpose:** `gateway/policy.py` is a
pattern blocklist, not a full parser — a sufficiently obfuscated/encoded
payload could likely slip past it. That's consistent with the rest of this
project's approach (see the Day 10 dynamic-tester limitation): name the gap
rather than overclaim coverage.

- [x] Day 16 — React dashboard (`dashboard/`), real captured data, live-fetch with offline fallback — see `dashboard/README.md`
- [x] Day 17 — live attack console: fires real Phase 2 payloads from the browser at the live gateway, confirmed against all 4 exploit classes (2 blocked, 1 correctly cleared — the documented auth gap — 1 flagged live via SEQ-001)

## Running the dashboard
```bash
cd dashboard
npm install
npm run dev      # http://localhost:5173
```
Works standalone (bundled real data) or live against `gateway/app.py` on
port 9000 — see `dashboard/README.md` for details.

## Next — Phase 6 (Day 18)
- [ ] Final public README rewrite, architecture diagram, recorded demo video, public release
