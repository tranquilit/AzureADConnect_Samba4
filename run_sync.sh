#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -x "$PROJECT_DIR/.venv/bin/python3" ]; then
    exec "$PROJECT_DIR/.venv/bin/python3" "$PROJECT_DIR/run_sync.py" "$@"
fi

exec /usr/bin/python3 "$PROJECT_DIR/run_sync.py" "$@"
