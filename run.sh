#!/usr/bin/env bash
# Start the secscan web app (detached). Configurable via env:
#   HOST (default 127.0.0.1), PORT (default 8000)
# Writes a PID file and logs next to this script.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
PY="$DIR/.venv/bin/python"
PIDFILE="$DIR/.secscan-serve.pid"
LOGFILE="$DIR/secscan-serve.log"

[ -x "$PY" ] || { echo "venv python not found at $PY — run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2; exit 1; }

# Already running?
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "secscan already running (PID $(cat "$PIDFILE")) on http://$HOST:$PORT"
    exit 0
fi

setsid "$PY" -m secscan serve --host "$HOST" --port "$PORT" > "$LOGFILE" 2>&1 < /dev/null &
PID=$!
echo "$PID" > "$PIDFILE"

# Give it a moment, then confirm it's up.
sleep 2
if kill -0 "$PID" 2>/dev/null; then
    echo "secscan started (PID $PID) on http://$HOST:$PORT"
    echo "logs: $LOGFILE"
else
    echo "secscan failed to start — see $LOGFILE" >&2
    rm -f "$PIDFILE"
    tail -n 15 "$LOGFILE" >&2 || true
    exit 1
fi
