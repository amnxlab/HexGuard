#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/hexstrike-ai"
VENV_DIR="$BACKEND_DIR/hexstrike-env"
PORT="${HEXSTRIKE_PORT:-8888}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to run the HexStrike backend." >&2
  exit 1
fi

if [[ ! -d "$BACKEND_DIR" ]]; then
  echo "Expected backend at $BACKEND_DIR but it was not found." >&2
  exit 1
fi

# Kill any stale process occupying the port before starting
if command -v fuser >/dev/null 2>&1; then
  fuser -k "${PORT}/tcp" 2>/dev/null || true
elif command -v lsof >/dev/null 2>&1; then
  lsof -ti :"${PORT}" | xargs -r kill -TERM 2>/dev/null || true
fi
sleep 1

cd "$BACKEND_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python3 -m pip install --upgrade pip >/dev/null
python3 -m pip install -r requirements.txt
exec python3 hexstrike_server.py --port "${PORT}"
