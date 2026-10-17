#!/usr/bin/env bash
# Starts the whole backend stack (4 range servers + gateway) in the
# background in one command. Logs land in .dev-logs/, PIDs in .dev-pids
# so scripts/dev_down.sh can clean up after you.
#
# Safe to re-run even if a previous run was never cleanly stopped (e.g.
# you closed the terminal instead of running dev_down.sh) — it force-frees
# every port this project uses before starting anything, and verifies
# each service actually came up rather than assuming it did.
#
# Run from the repo root:  bash scripts/dev_up.sh
set -e
cd "$(dirname "$0")/.."
mkdir -p .dev-logs
rm -f .dev-pids

PORTS="8001 8002 8003 8004 9000"

echo "Freeing ports (safe no-op if nothing's there)..."
for port in $PORTS; do
  pids=$(lsof -ti:"$port" 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo "  killing stale process(es) on port $port: $pids"
    kill -9 $pids 2>/dev/null || true
  fi
done
sleep 1

start() {
  name="$1"; shift
  if command -v setsid > /dev/null 2>&1; then
    setsid nohup "$@" > ".dev-logs/${name}.log" 2>&1 < /dev/null &
  else
    nohup "$@" > ".dev-logs/${name}.log" 2>&1 < /dev/null &
  fi
  echo $! >> .dev-pids
}

echo "Starting range servers..."
start server1_cmdinj   python3 -m uvicorn range.server1_cmdinj.server:server.app   --port 8001 --host 127.0.0.1
start server2_traversal python3 -m uvicorn range.server2_traversal.server:server.app --port 8002 --host 127.0.0.1
start server3_noauth    python3 -m uvicorn range.server3_noauth.server:server.app    --port 8003 --host 127.0.0.1
start server4_overpriv  python3 -m uvicorn range.server4_overpriv.server:server.app  --port 8004 --host 127.0.0.1

sleep 1
echo "Starting gateway..."
start gateway python3 -m uvicorn gateway.app:app --port 9000 --host 127.0.0.1

echo ""
echo "Verifying everything actually came up (retries for a few seconds —"
echo "server1 in particular runs real git commands at startup and can be"
echo "slower than the others)..."
all_ok=true
check_port() {
  name="$1"; port="$2"
  attempts=10
  for i in $(seq 1 $attempts); do
    # -f makes curl itself fail (nonzero exit) on a non-2xx response, so a
    # WRONG process answering on this port (a stale leftover from an
    # earlier run, say) is correctly reported as FAIL, not mistaken for
    # success just because something responded.
    # The command substitution + check live inside this `if` condition on
    # purpose — with `set -e` active, a failing command OUTSIDE an
    # if-condition kills the whole script immediately, before this
    # function could ever print FAIL or let the script reach its summary.
    if response=$(curl -sf --max-time 2 "http://127.0.0.1:${port}/healthz" 2>/dev/null) \
       && echo "$response" | grep -q '"status":[[:space:]]*"ok"'; then
      echo "  OK   $name (:$port)"
      return 0
    fi
    sleep 0.5
  done
  echo "  FAIL $name (:$port) after ${attempts} attempts — check .dev-logs/${name}.log (or: something else may already be using this port)"
  all_ok=false
}
check_port server1_cmdinj 8001
check_port server2_traversal 8002
check_port server3_noauth 8003
check_port server4_overpriv 8004
check_port gateway 9000

echo ""
if [ "$all_ok" = true ]; then
  echo "All 5 services confirmed up."
else
  echo "Some services failed to start — see FAIL lines above and their logs."
  echo "Common cause: a leftover process was already on that port and didn't"
  echo "die cleanly. Re-running this script again usually fixes it, since it"
  echo "force-frees every port before starting."
fi
echo ""
echo "python3 -m client.harness discover"
echo "Stop everything with: bash scripts/dev_down.sh"