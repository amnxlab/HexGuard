#!/usr/bin/env bash
# =============================================================================
# setup-tools.sh — Auto-install all HexGuard Hunt prerequisites
#
# Runs automatically from start-desktop-linux.sh before Electron launches.
# Safe to run repeatedly: every step is idempotent (skips if already present).
#
# Tools handled:
#   1. Python 3 venv + hexstrike dependencies  (hexstrike-ai/hexstrike-env/)
#   2. ffuf             — endpoint discovery
#   3. sqlmap           — SQL injection testing
#
# Burp Suite is commercial and cannot be auto-installed. The startup screen
# will show a warning if its REST API is not reachable; it is non-critical.
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

ok()   { echo "${GREEN}  ✓${RESET}  $*"; }
warn() { echo "${YELLOW}  ⚠${RESET}  $*"; }
info() { echo "${CYAN}  →${RESET}  $*"; }
fail() { echo "${RED}  ✗${RESET}  $*" >&2; }
sep()  { echo "${BOLD}────────────────────────────────────────${RESET}"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/hexstrike-ai"
VENV_DIR="$BACKEND_DIR/hexstrike-env"

# Where we install downloaded binaries when we can't use apt
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"

# Add ~/.local/bin to PATH for the rest of this session if not already there
if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
  export PATH="$LOCAL_BIN:$PATH"
fi

sep
echo "${BOLD}HexGuard Hunt — Tool Setup${RESET}"
sep

# =============================================================================
# 1. Python 3
# =============================================================================
echo
echo "${BOLD}[1/3] Python 3${RESET}"

if ! command -v python3 &>/dev/null; then
  fail "python3 not found."
  info "Attempting to install via package manager..."

  if command -v apt-get &>/dev/null; then
    sudo apt-get install -y python3 python3-pip python3-venv 2>&1 | grep -E "^(Get:|Ign:|Err:|dpkg|Preparing|Unpacking|Setting|Processing)" || true
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y python3 python3-pip 2>&1 | grep -E "^(Installing|Upgraded|Complete)" || true
  elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm python python-pip 2>&1 | grep -E "^(installing|resolving|looking)" || true
  else
    fail "Cannot auto-install Python 3 — no supported package manager found."
    fail "Install Python 3.10+ manually, then re-run this script."
    exit 1
  fi

  if ! command -v python3 &>/dev/null; then
    fail "Python 3 install failed. Please install Python 3.10+ manually."
    exit 1
  fi
fi

PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
ok "python3 $PYTHON_VER found"

# Ensure venv module is available
if ! python3 -m venv --help &>/dev/null; then
  info "Installing python3-venv..."
  if command -v apt-get &>/dev/null; then
    sudo apt-get install -y "python3.${PYTHON_VER##*.}-venv" python3-venv 2>/dev/null || \
    sudo apt-get install -y python3-venv
  fi
fi

# =============================================================================
# 2. HexStrike Python venv + requirements
# =============================================================================
echo
echo "${BOLD}[2/3] HexStrike AI Backend${RESET}"

if [[ ! -d "$BACKEND_DIR" ]]; then
  fail "hexstrike-ai/ directory not found at $BACKEND_DIR"
  fail "This is part of the repository — run: git submodule update --init"
  exit 1
fi

# Create venv if missing
if [[ ! -d "$VENV_DIR" ]]; then
  info "Creating Python venv at hexstrike-ai/hexstrike-env/ ..."
  python3 -m venv "$VENV_DIR"
  ok "Venv created"
else
  ok "Venv already exists"
fi

VENV_PIP="$VENV_DIR/bin/pip"
VENV_PYTHON="$VENV_DIR/bin/python3"

# Upgrade pip silently
"$VENV_PIP" install --upgrade pip --quiet

# Install / sync requirements
if [[ -f "$BACKEND_DIR/requirements.txt" ]]; then
  info "Installing Python dependencies (this may take a minute on first run)..."
  "$VENV_PIP" install -r "$BACKEND_DIR/requirements.txt" --quiet \
    && ok "Python dependencies installed" \
    || { fail "pip install failed — check $BACKEND_DIR/requirements.txt"; exit 1; }
else
  warn "requirements.txt not found in $BACKEND_DIR — skipping pip install"
fi

# =============================================================================
# 3. ffuf — HTTP fuzzer / endpoint discovery
# =============================================================================
echo
echo "${BOLD}[3/4] ffuf${RESET}"

if command -v ffuf &>/dev/null; then
  ok "ffuf already installed at $(command -v ffuf)"
else
  INSTALLED=false

  # Try package manager first (Ubuntu 22.04+ has it in universe)
  if command -v apt-get &>/dev/null; then
    info "Trying apt-get install ffuf ..."
    if sudo apt-get install -y ffuf &>/dev/null 2>&1; then
      command -v ffuf &>/dev/null && INSTALLED=true
    fi
  elif command -v dnf &>/dev/null; then
    info "Trying dnf install ffuf ..."
    if sudo dnf install -y ffuf &>/dev/null 2>&1; then
      command -v ffuf &>/dev/null && INSTALLED=true
    fi
  elif command -v pacman &>/dev/null; then
    info "Trying pacman -Sy ffuf ..."
    if sudo pacman -Sy --noconfirm ffuf &>/dev/null 2>&1; then
      command -v ffuf &>/dev/null && INSTALLED=true
    fi
  fi

  # Fall back to downloading the release binary from GitHub
  if [[ "$INSTALLED" == false ]]; then
    info "Package manager did not find ffuf — downloading release binary..."

    ARCH=$(uname -m)
    case "$ARCH" in
      x86_64)  FFUF_ARCH="amd64" ;;
      aarch64) FFUF_ARCH="arm64" ;;
      armv7*)  FFUF_ARCH="armv6" ;;
      *)
        warn "Unknown architecture '$ARCH'. Cannot auto-download ffuf."
        warn "Install ffuf manually: https://github.com/ffuf/ffuf/releases"
        FFUF_ARCH=""
        ;;
    esac

    if [[ -n "$FFUF_ARCH" ]]; then
      # Resolve latest release tag via GitHub API (no auth needed for public repos)
      FFUF_VER=$(curl -fsSL "https://api.github.com/repos/ffuf/ffuf/releases/latest" \
        2>/dev/null | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/' || echo "")

      if [[ -z "$FFUF_VER" ]]; then
        # Hardcode a known good version as fallback if API call fails
        FFUF_VER="2.1.0"
        info "GitHub API unavailable — using known release v${FFUF_VER}"
      fi

      FFUF_URL="https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_${FFUF_ARCH}.tar.gz"
      FFUF_TMP=$(mktemp -d)
      trap 'rm -rf "$FFUF_TMP"' EXIT

      info "Downloading ffuf v${FFUF_VER} (${FFUF_ARCH}) ..."
      if curl -fsSL "$FFUF_URL" -o "$FFUF_TMP/ffuf.tar.gz"; then
        tar -xzf "$FFUF_TMP/ffuf.tar.gz" -C "$FFUF_TMP"
        cp "$FFUF_TMP/ffuf" "$LOCAL_BIN/ffuf"
        chmod +x "$LOCAL_BIN/ffuf"
        INSTALLED=true
      else
        warn "Download failed. Try manually: https://github.com/ffuf/ffuf/releases"
      fi
    fi
  fi

  if [[ "$INSTALLED" == true ]]; then
    ok "ffuf installed at $(command -v ffuf)"
  else
    warn "ffuf could not be installed automatically."
    warn "Endpoint discovery will fall back to a static path list."
    warn "Install manually: https://github.com/ffuf/ffuf/releases"
  fi
fi

# =============================================================================
# 4. sqlmap — SQL injection scanner
# =============================================================================
echo
echo "${BOLD}[4/5] sqlmap${RESET}"

if command -v sqlmap &>/dev/null; then
  ok "sqlmap already installed at $(command -v sqlmap)"
else
  INSTALLED=false

  # Try package manager
  if command -v apt-get &>/dev/null; then
    info "Trying apt-get install sqlmap ..."
    if sudo apt-get install -y sqlmap &>/dev/null 2>&1; then
      command -v sqlmap &>/dev/null && INSTALLED=true
    fi
  elif command -v dnf &>/dev/null; then
    info "Trying dnf install sqlmap ..."
    if sudo dnf install -y sqlmap &>/dev/null 2>&1; then
      command -v sqlmap &>/dev/null && INSTALLED=true
    fi
  elif command -v pacman &>/dev/null; then
    info "Trying pacman -Sy sqlmap ..."
    if sudo pacman -Sy --noconfirm sqlmap &>/dev/null 2>&1; then
      command -v sqlmap &>/dev/null && INSTALLED=true
    fi
  fi

  # Fall back: pip3 install sqlmap (works system-wide)
  if [[ "$INSTALLED" == false ]] && command -v pip3 &>/dev/null; then
    info "Trying pip3 install sqlmap ..."
    if pip3 install --user sqlmap --quiet 2>/dev/null; then
      # pip --user installs to ~/.local/bin
      if command -v sqlmap &>/dev/null; then
        INSTALLED=true
      fi
    fi
  fi

  # Fall back: clone from GitHub and create a wrapper
  if [[ "$INSTALLED" == false ]]; then
    SQLMAP_DIR="$HOME/.local/share/sqlmap-git"
    if [[ ! -d "$SQLMAP_DIR" ]]; then
      info "Cloning sqlmap from GitHub ..."
      if git clone --depth=1 https://github.com/sqlmapproject/sqlmap.git "$SQLMAP_DIR" --quiet; then
        # Create a wrapper script in LOCAL_BIN
        cat > "$LOCAL_BIN/sqlmap" << 'WRAPPER'
#!/usr/bin/env bash
exec python3 "$HOME/.local/share/sqlmap-git/sqlmap.py" "$@"
WRAPPER
        chmod +x "$LOCAL_BIN/sqlmap"
        INSTALLED=true
      fi
    else
      # Already cloned, just ensure wrapper exists
      if [[ ! -f "$LOCAL_BIN/sqlmap" ]]; then
        cat > "$LOCAL_BIN/sqlmap" << 'WRAPPER'
#!/usr/bin/env bash
exec python3 "$HOME/.local/share/sqlmap-git/sqlmap.py" "$@"
WRAPPER
        chmod +x "$LOCAL_BIN/sqlmap"
      fi
      (cd "$SQLMAP_DIR" && git pull --quiet 2>/dev/null || true)
      INSTALLED=true
    fi
  fi

  if [[ "$INSTALLED" == true ]]; then
    ok "sqlmap installed at $(command -v sqlmap)"
  else
    warn "sqlmap could not be installed automatically."
    warn "Install manually: sudo apt install sqlmap  OR  pip3 install sqlmap"
  fi
fi

# =============================================================================
# 5. OWASP ZAP — free web app security scanner (replaces Burp Suite)
# =============================================================================
echo
echo "${BOLD}[5/5] OWASP ZAP${RESET}"

if command -v zaproxy &>/dev/null || command -v zap.sh &>/dev/null; then
  ok "OWASP ZAP already installed"
else
  INSTALLED=false

  # Try snap (most reliable on Ubuntu/Debian-based distros)
  if command -v snap &>/dev/null; then
    info "Trying snap install zaproxy --classic ..."
    if sudo snap install zaproxy --classic &>/dev/null 2>&1; then
      command -v zaproxy &>/dev/null && INSTALLED=true
    fi
  fi

  # Try apt-get (some Kali/Parrot repos include ZAP)
  if [[ "$INSTALLED" == false ]] && command -v apt-get &>/dev/null; then
    info "Trying apt-get install zaproxy ..."
    if sudo apt-get install -y zaproxy &>/dev/null 2>&1; then
      command -v zaproxy &>/dev/null && INSTALLED=true
    fi
  fi

  if [[ "$INSTALLED" == true ]]; then
    ok "OWASP ZAP installed at $(command -v zaproxy 2>/dev/null || command -v zap.sh)"
  else
    warn "OWASP ZAP could not be installed automatically (it is ~600 MB)."
    warn "This is optional — active scan step will be skipped when ZAP is offline."
    warn "Install manually:"
    warn "  snap install zaproxy --classic"
    warn "  OR download from https://www.zaproxy.org/download/"
    warn "To start ZAP as a daemon:"
    warn "  zaproxy -daemon -port 8090 -host 127.0.0.1 -config api.disablekey=true"
  fi
fi

# =============================================================================
# Summary
# =============================================================================
sep
echo
echo "${BOLD}Tool setup complete.${RESET}"
echo
echo "  To persist PATH changes across sessions, add this to ~/.bashrc or ~/.zshrc:"
echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
echo
sep

# Ensure ~/.local/bin is added to shell rc if not already there
SHELL_RC=""
if [[ -f "$HOME/.zshrc" ]]; then
  SHELL_RC="$HOME/.zshrc"
elif [[ -f "$HOME/.bashrc" ]]; then
  SHELL_RC="$HOME/.bashrc"
fi

if [[ -n "$SHELL_RC" ]]; then
  if ! grep -q 'local/bin' "$SHELL_RC" 2>/dev/null; then
    echo '' >> "$SHELL_RC"
    echo '# Added by HexGuard Hunt setup-tools.sh' >> "$SHELL_RC"
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
    ok "PATH entry added to $SHELL_RC"
  fi
fi
