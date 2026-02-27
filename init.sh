#!/usr/bin/env bash
set -euo pipefail

DEV_COMMAND=""
SMOKE_COMMAND=""

echo "[init.sh] pwd: $(pwd)"
if [[ -n "$DEV_COMMAND" ]]; then
  echo "[init.sh] running dev command: $DEV_COMMAND"
  eval "$DEV_COMMAND"
else
  echo "[init.sh] no dev command configured"
fi

if [[ -n "$SMOKE_COMMAND" ]]; then
  echo "[init.sh] running smoke command: $SMOKE_COMMAND"
  eval "$SMOKE_COMMAND"
else
  echo "[init.sh] no smoke command configured"
fi
