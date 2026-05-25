# HexGuard Hunt

A Linux desktop application for AI-driven REST API security testing. HexStrike AI orchestrates 150+ security tools through the Model Context Protocol (MCP), using Google Gemini for reasoning — endpoint discovery, vulnerability scanning, IDOR detection, and automated report generation, all in one workspace.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Clone the repository](#2-clone-the-repository)
3. [HexStrike AI backend](#3-hexstrike-ai-backend)
4. [Google Gemini API key](#4-google-gemini-api-key)
5. [Node dependencies and desktop build](#5-node-dependencies-and-desktop-build)
6. [Start the application](#6-start-the-application)
7. [Security tools](#7-security-tools)
8. [Verify everything works](#8-verify-everything-works)
9. [Ports reference](#9-ports-reference)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

Install these on your host system before anything else.

### Required

```bash
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-full pipx \
    ffmpeg \
    git curl
```

| What | Why it's needed |
|---|---|
| **Python 3.10+** (3.12 recommended) | HexStrike AI backend server |
| **python3-venv** | Creates the isolated backend virtual environment |
| **ffmpeg** | Audio decoding required by `faster-whisper` (voice transcription) |
| **git** | Cloning this repository |

### Node.js and pnpm

The project requires **Node.js 20 LTS minimum** (22 LTS recommended) and **pnpm 10.8.0 exactly** (the version is pinned in `package.json`).

```bash
# Install fnm (fast Node manager) — swap for nvm if you prefer
curl -fsSL https://fnm.vercel.app/install | bash
source ~/.bashrc

# Install and activate Node 22 LTS
fnm install 22
fnm use 22

# Install the pinned pnpm version
npm install -g pnpm@10.8.0
```

> Using a different pnpm version than 10.8.0 may fail silently due to the `packageManager` field in `package.json`.

### Go (optional — for nuclei and related tools)

Only needed if you want the extended scanning tools (nuclei, subfinder, httpx, katana, dalfox).

```bash
# Download from https://go.dev/dl/ then:
tar -C /usr/local -xzf go1.2x.x.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## 2. Clone the repository

```bash
git clone <repo-url> HexGuard-Hunt
cd HexGuard-Hunt
```

---

## 3. HexStrike AI Backend

The backend is a Flask server (`hexstrike-ai/hexstrike_server.py`) that handles all AI routing, Gemini calls, tool orchestration, and voice transcription. It must run alongside the desktop app.

### One-time setup (creates the Python virtual environment)

```bash
cd hexstrike-ai
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

This installs all 13 Python packages into an isolated environment. Nothing is installed system-wide.

### What gets installed

| Package | Purpose |
|---|---|
| `flask` | REST API server — `/ask`, `/health`, `/voice/transcribe` |
| `requests` | HTTP client, Gemini REST API calls |
| `psutil` | System metrics (CPU / memory monitoring) |
| `fastmcp` | MCP protocol framework |
| `faster-whisper` | **Voice transcription** — offline speech-to-text (requires `ffmpeg`) |
| `beautifulsoup4` | HTML parsing |
| `selenium` | Browser automation (requires Chrome/Chromium if used) |
| `webdriver-manager` | Auto-downloads ChromeDriver |
| `aiohttp` | Async HTTP for concurrent requests |
| `mitmproxy` | HTTP/HTTPS proxy interception |
| `pwntools` | Binary exploitation helpers |
| `angr` | Binary static analysis |
| `bcrypt==4.0.1` | Pinned — fixes pwntools/passlib compatibility |

> **First voice use**: `faster-whisper` downloads the Whisper `base` model (~145 MB from Hugging Face) on first use. An internet connection is required for this one-time download.

---

## 4. Google Gemini API Key

HexStrike uses Google Gemini for all AI reasoning. A free key works fine for development.

**Get your key**: [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)

**Configure it**: Open HexGuard Hunt → click **Settings** tab → paste key → click **Save & Connect**.

The key is stored only in your local app data folder. It is never written to disk in the repo and never transmitted anywhere except Google's API.

### Free-tier rate limits per model

| Model | Free RPM | Recommended for |
|---|---|---|
| `gemini-2.5-flash` | 10 | Deep analysis (use sparingly) |
| `gemini-2.5-flash-lite` | 30 | Good daily balance |
| `gemini-2.0-flash` | 15 | **Default** — fast and reliable |
| `gemini-2.0-flash-lite` | 30 | Best under heavy repeated use |
| `gemini-1.5-flash` | 15 | |
| `gemini-1.5-flash-8b` | 30 | Lightest option |
| `gemini-1.5-pro` | 2 | Highest capability, very limited free quota |

When quota is hit, the chat shows an amber **Gemini Quota Limit Reached** card with recovery instructions. Switch to a lighter model in Settings to continue immediately.

---

## 5. Node Dependencies and Desktop Build

From the **repo root**:

```bash
# Install all Node packages across all workspace packages
pnpm install

# Compile the Electron main process (TypeScript → JavaScript)
pnpm --filter @hexguard/desktop build
```

The renderer (React/Vite) is compiled on-the-fly in dev mode — you do not need to build it separately.

---

## 6. Start the Application

You need **two terminals running simultaneously**.

### Terminal 1 — HexStrike AI backend

```bash
cd hexstrike-ai
source hexstrike-env/bin/activate
python3 hexstrike_server.py
```

The server starts on `http://127.0.0.1:8888`. You should see:

```
 * Running on http://127.0.0.1:8888
```

Keep this terminal open. The desktop app connects to it on startup.

Optional flags:
```bash
python3 hexstrike_server.py --port 9000   # use a different port
python3 hexstrike_server.py --debug       # verbose logging
```

### Terminal 2 — Desktop application

```bash
cd scripts
./start-desktop-linux.sh
```

Or from the repo root:
```bash
pnpm dev:linux
```

The script handles Electron's sandbox/GPU flags automatically for Linux environments. If you see GPU or sandbox errors, they are suppressed by the startup flags — this is expected behaviour on headless or constrained systems.

---

## 7. Security Tools

HexGuard Hunt calls external CLI tools for scanning. They must be on your `$PATH`.

### Core tools — required for basic scanning

```bash
sudo apt install -y ffuf sqlmap nmap
```

| Tool | Purpose |
|---|---|
| **ffuf** | Endpoint and directory discovery |
| **sqlmap** | SQL injection detection |
| **nmap** | Port and service enumeration |

### Auto-installed tools — handled at first launch

These are installed automatically by the startup manager if missing:

| Tool | Purpose | Manual fallback |
|---|---|---|
| **wafw00f** | WAF detection | `pipx install wafw00f` |
| **nikto** | Web server scanner | `sudo apt install nikto` |
| **wapiti** | Web app vulnerability scanner | `pipx install wapiti3` |

### Extended tools — for full Auto/Hunt mode

```bash
# Apt packages
sudo apt install -y gobuster feroxbuster amass wpscan hydra john hashcat \
    zaproxy binwalk libimage-exiftool-perl

# pipx tools
pipx ensurepath && source ~/.bashrc
pipx install arjun
pipx install volatility3

# Go tools (requires Go 1.21+ on PATH)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest
```

| Tool | Purpose |
|---|---|
| **nuclei** | Template-based CVE and misconfiguration scanning |
| **gobuster** / **feroxbuster** | Recursive directory brute-force |
| **subfinder** / **amass** | Subdomain enumeration |
| **httpx** | HTTP probing and fingerprinting |
| **katana** | Web crawling |
| **dalfox** | XSS parameter scanning |
| **arjun** | Hidden HTTP parameter discovery |
| **wpscan** | WordPress security scanning |
| **zaproxy** | OWASP ZAP active scanner (daemon mode on port 8090) |
| **hydra** / **john** / **hashcat** | Credential and password attacks |
| **binwalk** | Firmware and binary extraction |
| **exiftool** | File metadata analysis |
| **volatility3** | Memory forensics |

> See [REQUIREMENTS.md](REQUIREMENTS.md) for the full tool reference including all version constraints and wordlist details.

---

## 8. Verify Everything Works

After both terminals are running:

1. **Settings tab** — should show a green **● connected** indicator next to "HexStrike AI"
2. **Send a message** — the reply bubble should show a green **HexStrike · gemini-x.x-flash** badge underneath
3. **Tool status** — scroll down in Settings to see which tools are online/offline
4. **Voice input** — click the mic icon, speak, click again to stop; transcript appears in the composer

Quick tool check from a terminal:
```bash
ffuf -V
sqlmap --version
nmap --version
nuclei -version       # if installed
wafw00f --version     # if installed
```

---

## 9. Ports Reference

| Service | Port | Notes |
|---|---|---|
| HexStrike AI backend | **8888** | Flask REST + MCP server |
| Vite dev server | **5173** | Renderer UI, bound to `127.0.0.1` only |
| OWASP ZAP daemon | **8090** | Optional, start manually: `zaproxy -daemon -port 8090 -host 127.0.0.1 -config api.disablekey=true` |

---

## 10. Troubleshooting

### "HexStrike not reachable" / no green indicator in Settings
The backend is not running. Start it in Terminal 1 first (see §6), then relaunch the app or wait ~10 seconds for the health check to retry.

### Amber quota card appears in chat
Your Gemini API key has hit the free-tier rate limit. Go to Settings, switch to a lighter model (e.g. `gemini-2.0-flash-lite` — 30 RPM free), and click Save & Connect.

### Mic button records but produces no transcript
The voice transcription endpoint (`/voice/transcribe`) runs inside the HexStrike backend. Make sure the backend is running. Also ensure `ffmpeg` is installed (`ffmpeg -version`).

### "Unsaved" orange dot stays in Settings after saving
Click **Save & Connect** — the dot disappears when the save is confirmed. If it reappears after restarting, the config file may not have write permissions in your app data directory.

### GPU / display / sandbox errors on launch
These are expected on Linux systems without a full desktop GPU stack. The `start-desktop-linux.sh` script already passes `--disable-gpu`, `--use-gl=swiftshader`, and `--no-sandbox` to Electron. The app runs correctly despite these log lines.

### `pnpm install` fails with version mismatch
The project requires pnpm **exactly** 10.8.0. Run `pnpm --version` and reinstall if needed:
```bash
npm install -g pnpm@10.8.0
```

### `pip install -r requirements.txt` fails on `angr` or `pwntools`
These packages require build tools. Install them first:
```bash
sudo apt install -y build-essential python3-dev libffi-dev
```
Then re-run `pip install -r requirements.txt` inside the activated venv.
