#!/usr/bin/env bash
# Starts the whole backend stack (4 range servers + gateway) in the
# background in one command. Logs land in .dev-logs/, PIDs in .dev-pids
# so scripts/dev_down.sh can clean up after you.
#
# Run from the repo root:  bash scripts/dev_up.sh
set -e
cd "$(dirname "$0")/.."
mkdir -p .dev-logs
rm -f .dev-pids

start() {
  name="$1"; shift
  # setsid detaches the process from this script's process group so it
  # keeps running independently (matters in some sandboxed/CI shells;
  # harmless on a normal local machine). Falls back to plain nohup if
  # setsid isn't available (e.g. some macOS setups without coreutils).
  if command -v setsid > /dev/null 2>&1; then
    setsid nohup "$@" > ".dev-logs/${name}.log" 2>&1 < /dev/null &
  else
    nohup "$@" > ".dev-logs/${name}.log" 2>&1 < /dev/null &
  fi
  echo $! >> .dev-pids
  echo "  started $name (pid $!, log: .dev-logs/${name}.log)"
}

echo "Starting range servers..."
start server1_cmdinj   python3 -m uvicorn range.server1_cmdinj.server:server.app   --port 8001 --host 127.0.0.1
start server2_traversal python3 -m uvicorn range.server2_traversal.server:server.app --port 8002 --host 127.0.0.1
start server3_noauth    python3 -m uvicorn range.server3_noauth.server:server.app    --port 8003 --host 127.0.0.1
start server4_overpriv  python3 -m uvicorn range.server4_overpriv.server:server.app  --port 8004 --host 127.0.0.1

sleep 1
echo "Starting gateway..."
start gateway python3 -m uvicorn gateway.app:app --port 9000 --host 127.0.0.1

sleep 1
echo ""
echo "All services starting. Check:"
echo "  curl http://127.0.0.1:9000/healthz"
echo "  python3 -m client.harness discover"
echo ""
echo "Stop everything with: bash scripts/dev_down.sh"
