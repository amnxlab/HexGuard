# HexGuard-Hunt — Codebase Walkthrough (initial)

## Executive Summary
- Purpose: HexGuard-Hunt (HexStrike) is a local security research workstation combining an Electron desktop UI, a Flask-based AI backend (`hexstrike-ai`), and an MCP agent (`hexstrike_mcp.py`) that exposes ~100 tool wrappers. The LLM integration primarily uses Google Generative Language (Gemini) via REST.

## Top-level components
- `hexstrike-ai/`: Python backend, FastMCP client, virtualenv, and AI/tool orchestration.
- `packages/desktop/`: Electron desktop app and services (UI, IPC, startup manager).
- `packages/renderer/`: Frontend UI built with Vite.
- `scripts/`: Helper scripts to set up environment and launch the backend/desktop.
- `wordlists/`: Wordlists used by scanners.

## Main entry points
- Backend server (Flask): [hexstrike-ai/hexstrike_server.py](hexstrike-ai/hexstrike_server.py)
- MCP client (FastMCP wrappers): [hexstrike-ai/hexstrike_mcp.py](hexstrike-ai/hexstrike_mcp.py)
- Desktop main process: [packages/desktop/src/main/index.ts](packages/desktop/src/main/index.ts)
- Desktop services (Gemini config + launcher): [packages/desktop/src/main/services/mcpClient.ts](packages/desktop/src/main/services/mcpClient.ts)
- Desktop startup manager (launches backend): [packages/desktop/src/main/services/startupManager.ts](packages/desktop/src/main/services/startupManager.ts)
- Example/demo server: [example/server.py](example/server.py)

## How AI is managed (summary)
- LLM wrapper `_call_gemini` is implemented in the backend and performs model fallback across a set of Gemini models. See the function in the backend: [hexstrike-ai/hexstrike_server.py#L9040-L9260](hexstrike-ai/hexstrike_server.py#L9040-L9260).
- The desktop stores Gemini credentials in an Electron `userData` JSON file (`hexguard-gemini.json`) and `startupManager` injects `GEMINI_API_KEY`/`GEMINI_MODEL` into the backend process environment when spawning it. See [packages/desktop/src/main/services/startupManager.ts#L210-L280](packages/desktop/src/main/services/startupManager.ts#L210-L280).
- The MCP client exposes many `@mcp.tool()` functions that call backend endpoints (e.g., `api/ai/generate_payload`, `api/vuln-intel/exploit-generate`). See the client: [hexstrike-ai/hexstrike_mcp.py](hexstrike-ai/hexstrike_mcp.py).

## Notable tool and AI integrations
- AI payload/exploit generation endpoints: `ai_generate_payload`, `generate_exploit_from_cve`, `generate_poc` exist and are reachable via MCP wrappers and backend endpoints.
  - MCP wrapper examples: [hexstrike-ai/hexstrike_mcp.py#L2770-L2850](hexstrike-ai/hexstrike_mcp.py#L2770-L2850) (AI payloads), [hexstrike-ai/hexstrike_mcp.py#L4020-L4088](hexstrike-ai/hexstrike_mcp.py#L4020-L4088) (exploit generation).
  - Backend functions coordinating these are in [hexstrike-ai/hexstrike_server.py](hexstrike-ai/hexstrike_server.py) (search `generate_exploit_from_cve`, `ai_generate_payload`).
- Many external CLI tools orchestrated via subprocess/spawn: `nmap`, `ffuf`, `sqlmap`, `nuclei`, `gobuster`, `pwntools`, `angr`, `mitmproxy`, `z3`, etc.

## Security & runtime notes (important)
- Sensitive capabilities: exploit generation, payload crafting, running privileged tools — these are present and should only be used in authorized, isolated environments.
- Secrets: Gemini API key is stored locally (`hexguard-gemini.json`) and passed into the backend env; ensure proper filesystem permissions.
- Network exposure: Example server binds 0.0.0.0; the backend defaults to 127.0.0.1 but desktop can spawn it — avoid exposing to public networks.
- Host-affecting operations: scripts and server code call `sudo`, `fuser`, `killall`, and execute arbitrary commands via `subprocess`/`spawn`. Audit before running in multi-tenant hosts.

## Files to inspect next (recommended order)
1. `hexstrike-ai/hexstrike_server.py` — LLM wrapper, `/ask`, and orchestration flows. ([open around `_call_gemini`](hexstrike-ai/hexstrike_server.py#L9040-L9260))
2. `hexstrike-ai/hexstrike_mcp.py` — enumerate `@mcp.tool` wrappers and note which backend endpoints they call.
3. `packages/desktop/src/main/services/startupManager.ts` — confirm how GEMINI_API_KEY is injected and how backend is spawned.
4. `packages/desktop/src/main/services/mcpClient.ts` — desktop ↔ backend HTTP helper functions and `gemini` config read/write.
5. `scripts/setup-tools.sh` & `scripts/start-hexstrike-backend.sh` — environment setup and safe launch steps.

## Next steps I will take (if you confirm)
- Produce a detailed, annotated walkthrough document (expanded) covering: LLM call flow, MCP tool list (with a brief description per tool), desktop integration details (exact env vars and file paths), and an annotated security triage. I'll write it into `docs/codebase_walkthrough.md` and update the TODO list.

---

*Document generated automatically as a starting point. Tell me if you want the full annotated walkthrough expanded now (includes excerpts and exact line references).*