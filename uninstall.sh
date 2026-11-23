#!/bin/sh
# Removes the phantom launcher. Add --purge to also delete reports and feeds in ~/.d-moon.
set -eu
ROOT=$(cd "$(dirname "$0")" && pwd)
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
for BIN in "${PREFIX:-/nonexistent}/bin" "${HOME}/.local/bin"; do
  if [ -L "$BIN/phantom" ] && [ "$(readlink "$BIN/phantom")" = "$ROOT/bin/phantom" ]; then
    rm -f "$BIN/phantom"
    echo "[phantom] removed $BIN/phantom"
  fi
done
if [ "$PURGE" = 1 ]; then
  DATA="${PHANTOM_HOME:-$HOME/.d-moon}"
  printf 'Delete %s (reports, imported feeds)? [y/N] ' "$DATA"
  read -r ans
  if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then rm -rf "$DATA"; echo "[phantom] deleted $DATA"; fi
fi
echo "[phantom] the program files in $ROOT were left in place; delete that folder to finish."
