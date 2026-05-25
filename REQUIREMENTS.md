# HexGuard Hunt — Requirements

Complete dependency reference for HexGuard Hunt and the HexStrike AI backend.
For a step-by-step setup guide see [README.md](README.md).

---

## 1. System Prerequisites

These must be present on the host before anything else is installed.

| Dependency | Min version | Purpose | Install (Ubuntu/Debian) |
|---|---|---|---|
| **Node.js** | 20 LTS (22 rec.) | Electron + Vite build toolchain | `sudo apt install nodejs` or [nvm](https://github.com/nvm-sh/nvm) |
| **pnpm** | **10.8.0 exact** | Monorepo package manager | `npm install -g pnpm@10.8.0` |
| **Python** | **3.10+** (3.12 rec.) | HexStrike AI backend server | `sudo apt install python3` |
| **python3-venv** | matches Python | Creating the isolated backend env | `sudo apt install python3-venv` |
| **ffmpeg** | any | Audio decoding for voice transcription (faster-whisper) | `sudo apt install ffmpeg` |
| **Git** | any | Cloning the repository | `sudo apt install git` |
| **Go** | 1.21+ | Installing nuclei, subfinder, httpx, katana, dalfox | [go.dev/dl](https://go.dev/dl/) |
| **Chrome / Chromium** | any | Browser automation (optional — only for selenium tasks) | `sudo apt install chromium-browser` |

> **Note — pnpm version is pinned.** The project's `package.json` specifies `"packageManager": "pnpm@10.8.0"`. Using a different version may fail silently.

---

## 2. Node Packages

Managed automatically by pnpm. Run once from the repo root:

```bash
pnpm install
```

Key packages (installed automatically):

| Package | Version | Purpose |
|---|---|---|
| electron | ^35.7.5 | Desktop application shell |
| vite | ^6.3.0 | Renderer (React) build + dev server |
| react | ^19.0.0 | UI framework |
| framer-motion | ^12.10.0 | Animations |
| lucide-react | ^0.511.0 | Icons |
| simple-statistics | ^7.8.9 | Statistical helpers in the pipeline engine |
| concurrently | ^9.1.2 | Runs Vite + Electron in parallel in dev mode |
| wait-on | ^8.0.3 | Delays Electron launch until Vite is ready |
| typescript | ^5.8.3 | Type checking across all packages |

---

## 3. Python Packages (HexStrike AI Backend)

All installed into an isolated virtual environment inside `hexstrike-ai/`.

```bash
cd hexstrike-ai
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Full package table:

| Package | Version constraint | Purpose |
|---|---|---|
| **flask** | >=2.3.0,<4.0.0 | REST API server — all `/ask`, `/health`, `/voice/*` endpoints |
| **requests** | >=2.31.0,<3.0.0 | HTTP client; used for Gemini REST API calls |
| **psutil** | >=5.9.0,<6.0.0 | System metrics (CPU, memory, process monitoring) |
| **fastmcp** | >=0.2.0,<1.0.0 | MCP protocol framework for AI tool routing |
| **faster-whisper** | >=1.0.0 | Local offline speech-to-text (`/voice/transcribe` endpoint) — **requires ffmpeg** |
| **beautifulsoup4** | >=4.12.0,<5.0.0 | HTML parsing for web scraping tasks |
| **selenium** | >=4.15.0,<5.0.0 | Browser automation (requires Chrome/Chromium) |
| **webdriver-manager** | >=4.0.0,<5.0.0 | Automatically downloads and manages ChromeDriver |
| **aiohttp** | >=3.8.0,<4.0.0 | Async HTTP for concurrent tool requests |
| **mitmproxy** | >=9.0.0,<11.0.0 | HTTP/HTTPS proxy interception and traffic analysis |
| **pwntools** | >=4.10.0,<5.0.0 | Binary exploitation helpers (CTF / binary analysis mode) |
| **angr** | >=9.2.0,<10.0.0 | Binary static analysis and symbolic execution |
| **bcrypt** | ==4.0.1 | **Pinned** — fixes passlib compatibility issue introduced by pwntools |

> **Whisper model download**: On first use of voice transcription, `faster-whisper` downloads the `base` model (~145 MB) from Hugging Face. An internet connection is required the first time.

---

## 4. Google Gemini API Key

HexStrike uses Google Gemini for AI reasoning. A free API key is sufficient for development.

| | |
|---|---|
| **Get key** | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) |
| **Configure** | Open the app → **Settings** tab → paste key → **Save & Connect** |
| **Storage** | Stored only in local app data (`app.getPath("userData")`). Never transmitted except to Google. |

### Free-tier rate limits

| Model | Free RPM | Notes |
|---|---|---|
| gemini-2.5-flash | 10 | Most capable — use for complex analysis |
| gemini-2.5-flash-lite | 30 | Good balance |
| gemini-2.0-flash | 15 | Fast, reliable default |
| gemini-2.0-flash-lite | 30 | Best choice under heavy use |
| gemini-1.5-flash | 15 | |
| gemini-1.5-flash-8b | 30 | |
| gemini-1.5-pro | 2 | Very capable but lowest free RPM |

If you hit quota, the chat shows an amber **Gemini Quota Limit Reached** card. Switch to a lighter model in Settings to recover.

---

## 5. External Security Tools

HexGuard Hunt calls these CLI tools directly. They must be installed on the host and available on `$PATH`.

### Always required (core scanning)

| Tool | Purpose | Install |
|---|---|---|
| **ffuf** | Endpoint and directory discovery | `sudo apt install ffuf` or [github.com/ffuf/ffuf/releases](https://github.com/ffuf/ffuf/releases) |
| **sqlmap** | SQL injection detection and exploitation | `sudo apt install sqlmap` |
| **nmap** | Port and service enumeration | `sudo apt install nmap` |

### Auto-installed at first launch (if missing)

The startup manager attempts to install these automatically using `pipx` or `apt`:

| Tool | Purpose | Manual install fallback |
|---|---|---|
| **wafw00f** | WAF detection | `pipx install wafw00f` |
| **nikto** | Web server vulnerability scanner | `sudo apt install nikto` |
| **wapiti** | Web application vulnerability scanner | `pipx install wapiti3` |

### Extended tools (Auto/Hunt mode — full capability)

| Tool | Purpose | Install |
|---|---|---|
| **nuclei** | Template-based CVE and misconfiguration scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **gobuster** | Directory / DNS brute-force | `sudo apt install gobuster` |
| **feroxbuster** | Recursive directory enumeration | `sudo apt install feroxbuster` |
| **subfinder** | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **amass** | Attack surface mapping | `sudo apt install amass` |
| **httpx** | HTTP probing and fingerprinting | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **katana** | Web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| **dalfox** | XSS parameter scanner | `go install github.com/hahwul/dalfox/v2@latest` |
| **arjun** | Hidden HTTP parameter discovery | `pipx install arjun` |
| **wpscan** | WordPress security scanner | `sudo apt install wpscan` |
| **zaproxy / zap.sh** | OWASP ZAP active scanner | `snap install zaproxy --classic` |
| **hydra** | Login brute-force | `sudo apt install hydra` |
| **john** | Password cracking | `sudo apt install john` |
| **hashcat** | GPU-accelerated password cracking | `sudo apt install hashcat` |
| **binwalk** | Firmware and binary extraction | `sudo apt install binwalk` |
| **exiftool** | File metadata extraction | `sudo apt install libimage-exiftool-perl` |
| **checksec** | Binary hardening analysis | `pip3 install checksec` |
| **volatility3** | Memory forensics | `pipx install volatility3` |
| **ghidra** | Reverse engineering suite | [ghidra-sre.org](https://ghidra-sre.org/) |

---

## 6. Wordlists

Bundled in `wordlists/` at the repo root:

| File | Used for |
|---|---|
| `wordlists/raft-medium-directories.txt` | Deep directory enumeration (primary) |
| `wordlists/common.txt` | Common endpoint enumeration (fallback) |
| `wordlists/big.txt` | Large-scope enumeration |
| `wordlists/api-endpoints.txt` | REST API endpoint discovery |

SecLists (optional, used as secondary fallback if installed at `/usr/share/seclists/`):

```bash
sudo apt install seclists
```

---

## 7. Ports

| Service | Default port | Notes |
|---|---|---|
| HexStrike AI backend | **8888** | Flask REST + MCP. Change with `--port` flag |
| Vite dev server | **5173** | Renderer UI. Bound to `127.0.0.1` only |
| OWASP ZAP daemon | **8090** | Optional. Start with `zaproxy -daemon -port 8090 -host 127.0.0.1 -config api.disablekey=true` |

---

## 8. Quick-install Cheatsheet (Ubuntu / Debian / Kali)

Copy-paste block for a fresh machine:

```bash
# 1 — System tools
sudo apt update
sudo apt install -y \
    python3 python3-venv python3-full pipx \
    ffmpeg \
    ffuf sqlmap nikto nmap gobuster feroxbuster \
    zaproxy amass wpscan hydra john hashcat \
    binwalk libimage-exiftool-perl seclists \
    git curl

# 2 — pipx path fix
pipx ensurepath
source ~/.bashrc

# 3 — Python tools via pipx
pipx install wafw00f
pipx install wapiti3
pipx install arjun
pipx install volatility3

# 4 — Go tools (requires Go 1.21+ installed first — see go.dev/dl)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest

# 5 — Node + pnpm (using fnm — swap for nvm if preferred)
curl -fsSL https://fnm.vercel.app/install | bash
source ~/.bashrc
fnm install 22 && fnm use 22
npm install -g pnpm@10.8.0

# 6 — Repo + Node dependencies
git clone <repo-url> HexGuard-Hunt
cd HexGuard-Hunt
pnpm install

# 7 — HexStrike AI backend
cd hexstrike-ai
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cd ..
```
