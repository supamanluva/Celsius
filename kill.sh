#!/usr/bin/env bash
# Stop the celsius web app started by run.sh.
# Uses the PID file when present; falls back to matching the serve process.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDFILE="$DIR/.celsius-serve.pid"

stopped=0

if [ -f "$PIDFILE" ]; then
    PID="$(cat "$PIDFILE")"
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null && stopped=1
        # wait up to ~5s for a clean shutdown, then force.
        for _ in 1 2 3 4 5; do
            kill -0 "$PID" 2>/dev/null || break
            sleep 1
        done
        kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null || true
        echo "stopped celsius (PID $PID)"
    fi
    rm -f "$PIDFILE"
fi

# Fallback / cleanup of any stray serve process.
if pgrep -f 'celsius serve' >/dev/null 2>&1; then
    pkill -f 'celsius serve' 2>/dev/null && stopped=1
    echo "stopped stray 'celsius serve' process(es)"
fi

[ "$stopped" -eq 1 ] || echo "no running celsius server found"
