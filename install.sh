#!/bin/sh
# D-MOON PHANTOM installer for Termux (Android ARM64) and generic Linux.
# Usage: ./install.sh [--with-core]     (--with-core also builds the optional Rust core)
set -eu

ROOT=$(cd "$(dirname "$0")" && pwd)
WITH_CORE=0
for arg in "$@"; do
  case "$arg" in
    --with-core) WITH_CORE=1 ;;
    -h|--help) sed -n '2,3p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '[phantom] %s\n' "$*"; }

IS_TERMUX=0
case "${PREFIX:-}" in *com.termux*) IS_TERMUX=1 ;; esac

need() { command -v "$1" >/dev/null 2>&1; }

if [ "$IS_TERMUX" = 1 ]; then
  say "Termux detected ($(uname -m))"
  MISSING=""
  need python3 || need python || MISSING="$MISSING python"
  need ruby || MISSING="$MISSING ruby"
  [ "$WITH_CORE" = 1 ] && { need cargo || MISSING="$MISSING rust"; }
  if [ -n "$MISSING" ]; then
    say "installing:$MISSING"
    # shellcheck disable=SC2086
    pkg install -y $MISSING
  fi
else
  say "Linux/other platform ($(uname -m))"
  need python3 || { echo "python3 (3.8+) is required" >&2; exit 1; }
  need ruby || { echo "ruby (2.7+) is required" >&2; exit 1; }
fi

if [ "$WITH_CORE" = 1 ]; then
  need cargo || { echo "cargo not found; install Rust or omit --with-core" >&2; exit 1; }
  say "building Rust core (release)"
  (cd "$ROOT/core" && cargo build --release)
fi

chmod +x "$ROOT/bin/phantom"

if [ "$IS_TERMUX" = 1 ] && [ -n "${PREFIX:-}" ]; then
  BIN="$PREFIX/bin"
else
  BIN="${HOME}/.local/bin"
fi
mkdir -p "$BIN"
ln -sf "$ROOT/bin/phantom" "$BIN/phantom"
say "launcher: $BIN/phantom"
case ":$PATH:" in *":$BIN:"*) ;; *) say "add $BIN to your PATH" ;; esac

say "running diagnostics"
"$ROOT/bin/phantom" doctor || { say "doctor reported problems; see above"; exit 1; }
say "done. Try: phantom --help"
