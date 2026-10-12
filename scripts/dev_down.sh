#!/usr/bin/env bash
# Stops everything scripts/dev_up.sh started.
# Run from the repo root:  bash scripts/dev_down.sh
cd "$(dirname "$0")/.."
if [ -f .dev-pids ]; then
  while read -r pid; do
    if kill "$pid" 2>/dev/null; then
      echo "stopped pid $pid"
    fi
  done < .dev-pids
  rm -f .dev-pids
  echo "done."
else
  echo "no .dev-pids file found — nothing to stop (did you run dev_up.sh?)"
fi
