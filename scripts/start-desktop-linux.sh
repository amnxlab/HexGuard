#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
START_BACKEND="${START_HEXSTRIKE_BACKEND:-0}"
SKIP_SETUP="${SKIP_TOOL_SETUP:-0}"

# Some restricted Linux/container environments deny Chromium access to /tmp or /dev/shm.
# Use a private writable temp directory so Electron can launch reliably.
TMP_BASE="${HEXGUARD_TMPDIR:-$ROOT_DIR/.tmp}"
mkdir -p "$TMP_BASE"
export TMPDIR="$TMP_BASE"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$TMP_BASE/runtime}"
mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR" 2>/dev/null || true

# Chromium/Electron hardening flags for constrained Linux environments.
ELECTRON_FLAGS=(
  "--disable-dev-shm-usage"
  "--disable-gpu"
  "--disable-gpu-compositing"
  "--use-gl=swiftshader"
  "--enable-unsafe-swiftshader"
  "--no-sandbox"
  "--disable-setuid-sandbox"
)

if ! command -v node >/dev/null 2>&1; then
  echo "node is required. Run ./scripts/install-linux-prereqs.sh before launching the desktop app." >&2
  exit 1
fi

if ! command -v pnpm >/dev/null 2>&1; then
  echo "pnpm is required. Run ./scripts/install-linux-prereqs.sh before launching the desktop app." >&2
  exit 1
fi

# ── Auto-setup: install missing tools (venv, ffuf, sqlmap) ────────────────────
# Runs before Electron starts so the preflight checks see everything in place.
# Set SKIP_TOOL_SETUP=1 to bypass (useful if you already ran setup-tools.sh).
if [[ "$SKIP_SETUP" != "1" ]]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " HexGuard Hunt — Checking prerequisites..."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if ! bash "$ROOT_DIR/scripts/setup-tools.sh"; then
    echo ""
    echo "⚠ setup-tools.sh failed; continuing startup in degraded mode."
    echo "  You can re-run later with: SKIP_TOOL_SETUP=1 bash scripts/start-desktop-linux.sh"
  fi
  echo ""
fi

# Ensure ~/.local/bin is on PATH so tools installed there are visible
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  export PATH="$HOME/.local/bin:$PATH"
fi

if [[ "$START_BACKEND" == "1" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is not installed, so the HexStrike backend will be skipped." >&2
  else
    if pgrep -f "hexstrike_server.py --port 8888" >/dev/null 2>&1; then
      echo "HexStrike backend already running on port 8888."
    else
      echo "Starting HexStrike backend in a separate terminal..."
      if command -v gnome-terminal >/dev/null 2>&1; then
        gnome-terminal -- bash -lc "cd '$ROOT_DIR' && ./scripts/start-hexstrike-backend.sh; exec bash"
      elif command -v x-terminal-emulator >/dev/null 2>&1; then
        x-terminal-emulator -e bash -lc "cd '$ROOT_DIR' && ./scripts/start-hexstrike-backend.sh; exec bash"
      else
        echo "No GUI terminal detected. Run ./scripts/start-hexstrike-backend.sh in another shell if you want the backend locally." >&2
      fi
    fi
  fi
fi

cd "$ROOT_DIR"

# Clear stale Vite dev-server ports so the new instance always gets 5173
fuser -k 5173/tcp 2>/dev/null || true
fuser -k 5174/tcp 2>/dev/null || true

if [[ ! -d node_modules ]]; then
  pnpm install
fi

ELECTRON_BIN=$(find "$ROOT_DIR/node_modules/.pnpm" -name "electron" -path "*/electron/dist/electron" -type f 2>/dev/null | head -1)
if [[ -z "$ELECTRON_BIN" || ! -x "$ELECTRON_BIN" ]]; then
  echo "Electron binary not found. Running pnpm install to fetch it..."
  cd "$ROOT_DIR" && pnpm install
  ELECTRON_BIN=$(find "$ROOT_DIR/node_modules/.pnpm" -name "electron" -path "*/electron/dist/electron" -type f 2>/dev/null | head -1)
fi

if [[ -z "$ELECTRON_BIN" || ! -x "$ELECTRON_BIN" ]]; then
  echo "Electron is still unavailable after install. Check pnpm install logs above." >&2
  exit 1
fi

if [[ ! -d /dev/shm || ! -w /dev/shm || ! -x /dev/shm ]]; then
  echo "⚠ /dev/shm is not writable/executable in this environment."
  echo "  Electron will run with fallback flags, but system fix is recommended:"
  echo "    sudo chmod 1777 /dev/shm"
fi

pnpm --filter @hexguard/desktop build

exec pnpm exec concurrently -k -p "[{name}]" -n vite,electron \
  "pnpm --filter @hexguard/renderer exec vite --host 127.0.0.1 --port 5173" \
  "wait-on tcp:5173 && VITE_DEV_SERVER_URL=http://127.0.0.1:5173 '$ELECTRON_BIN' packages/desktop/dist/main/index.js ${ELECTRON_FLAGS[*]}"
