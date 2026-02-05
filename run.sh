#!/bin/bash
# PII Buddy — start the folder watcher
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".venv" ]; then
    echo "Run ./setup.sh first."
    exit 1
fi

exec .venv/bin/python main.py "$@"
