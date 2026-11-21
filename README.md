# scanX

**Authorized attack-surface reconnaissance with AI analysis.**

scanX runs a proven Bash recon pipeline (`scanner/scanx.sh`: subfinder, assetfinder, chaos, crt, dnsx, httpx) from a web app, then lets an AI turn the results into an **attack-vector report** — using scanX's built-in AI, or your own AI agent over **MCP** or a **REST API**.

> Only scan domains you own or have written permission to test.

---

## What you can do

| | |
|---|---|
| **Scan a domain** | Paste a domain or URL; follow live scanner output; get subdomains, live hosts, HTTP status, titles, technologies, IPs and CNAMEs. |
| **Download results** | `subdomains.txt`, `live.txt`, `httpx.json`, the scanner log — or everything as one `.zip`. |
| **AI attack-vector report** | One click. The AI reads the scan with scanX's tools, maps attack vectors to MITRE ATT&CK, rates them, and saves a report with a **risk level** (Critical / High / Medium / Low). |
| **AI "what changed?"** | Compares a scan with the previous scan of the same domain and explains new exposures and what was fixed. |
| **Ask the report** | Follow-up questions on any report ("Which host do we fix first?"); the AI checks the scan data before answering. |
| **Live AI progress** | See each step the AI takes ("Reading live hosts…", "Comparing with the previous scan…") and a live timer. |
| **Bring your own agent** | Connect Claude, Cursor, VS Code Copilot or any MCP client — or call the REST API from any agent or script. Reports they save appear in **Reports**. |
| **History, organizations, assets** | Every scan grouped by organization, with technology and asset overviews. |

---

## Three ways to use AI

| Way | Whose AI | Setup |
|---|---|---|
| **scanX AI** | The server's (Claude, OpenAI or NVIDIA Nemotron — whichever key is configured) | None: **Generate AI report** on a scan, **New AI report** on Reports, or the box on **AI Analysis** |
| **MCP** | The user's own (Claude Desktop/Code, Cursor, VS Code…) | **AI Analysis → Connect** gives a token and ready-to-paste config for `https://<host>/api/mcp` |
| **REST API** | The user's own agent, framework or script | Same token; `GET /api/v1/tools`, `POST /api/v1/tools/<name>`, OpenAPI at `/api/v1/openapi.json` |

All three use the same tools: `get_organization`, `list_scans`, `get_scan`, `list_hosts`, `search_hosts`, `list_technologies`, `diff_scans`, `list_reports`, `save_report`. A token only sees **one organization's** scans. Full user guide: the **AI Analysis** page (`/mcp/`) in the app.

---

## Quick start (Linux / WSL)

```bash
git clone <repo-url> scanX && cd scanX
./scripts/install.sh        # venv, Python deps, Go recon tools, database
cp .env.example .env        # if install.sh didn't, then edit it (see below)
./scripts/start.sh          # web server + background worker
# open http://localhost:8000
```

Recon tools (installed by `install.sh` when Go is present):

| Tool | Install |
|---|---|
| subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| assetfinder | `go install github.com/tomnomnom/assetfinder@latest` |
| chaos | `go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest` (needs `CHAOS_API_KEY`) |
| crt | `go install github.com/cemulus/crt@latest` |
| dnsx | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| httpx | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| figlet | `sudo apt install figlet` |

Check them with `python manage.py check_tools --install-hints`.

---

## Configuration (`.env`)

`.env.example` lists every setting. The important ones:

```bash
DEBUG=False                      # keep False on a public server
SECRET_KEY=                      # empty = generated once into .secret_key
ALLOWED_HOSTS=scanx.example.com,203.0.113.7
CSRF_TRUSTED_ORIGINS=https://scanx.example.com
CHAOS_API_KEY=

# Built-in AI — set ONE key. A generic api_key also works; its prefix picks the provider
# (nvapi- = NVIDIA, sk-ant- = Anthropic, sk- = OpenAI).
AI_PROVIDER=nvidia               # anthropic | openai | nvidia (empty = first key found)
NVIDIA_API_KEY=nvapi-...
AI_MODEL_NVIDIA=nvidia/nemotron-3-ultra-550b-a55b
# ANTHROPIC_API_KEY= / AI_MODEL_ANTHROPIC=claude-opus-5-5
# OPENAI_API_KEY=    / AI_MODEL_OPENAI=gpt-5

# Limits (the app is public; these protect your AI bill and the scan queue)
AI_DAILY_LIMIT=30                # built-in reports per day
AI_SCAN_COOLDOWN_MINUTES=10      # per scan and report type
AI_QUESTION_DAILY_LIMIT=100
SCAN_QUEUE_LIMIT=5
```

`.env` is read at startup — restart (`./scripts/start.sh`) after changing it.

---

## How it works

```
 Browser ──► Django web (views, /api/mcp, /api/v1) ──► SQLite / PostgreSQL ◄── Worker (manage.py worker)
                                                                               ├─ scan queue → scanner/scanx.sh
                                                                               └─ AI thread  → reports, change analyses,
                                                                                               follow-up questions
 External agents ── MCP / REST + token ──► same tools (scanner/mcp_http.py)
 Built-in AI (scanner/ai_agent.py) ── same tools ──► Claude / OpenAI / NVIDIA NIM
```

- Scans run **only** in the worker, one at a time; a second worker refuses to start.
- Cancel and timeouts stop the scanner **and** every tool it started.
- Scan output: `SCANX_DATA_DIR/<scan_id>/<domain>/` plus `live.log`.
- AI report text is rendered from Markdown and sanitized, so agent output can't inject scripts.

---

## Production (VPS)

1. `DEBUG=False`, set `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` to your domain.
2. Web: `gunicorn scanx.wsgi:application --bind 127.0.0.1:8000 --workers 3` behind nginx with HTTPS. Static files are served by WhiteNoise.
3. Worker: run `python manage.py worker` as a systemd service (`Restart=always`). Exactly one worker.
4. Optional: PostgreSQL via `DATABASE_URL`, and a persistent `SCANX_DATA_DIR`.

---

## Security notes

- Domain input is validated (RFC 1035) and shell metacharacters are rejected; the scanner is called with an argument list, never `shell=True`.
- Each scan runs in its own directory; downloads are limited to a fixed list of files.
- MCP/API tokens are stored hashed and scoped to one organization; they can be disconnected any time.
- Secrets live only in `.env`; the AI key is never sent to the browser.
- The web UI itself has no login (it is a public competition demo) — anyone who can open it can see results. Put it behind authentication if you deploy it for private data.

---

## Development

```bash
python manage.py test scanner      # 139 tests
python manage.py check_tools --install-hints
python manage.py worker --interval 2
```

Project layout: `scanner/` (models, views, `services.py` scanner executor, `mcp_http.py` tools + MCP endpoint, `ai_agent.py` built-in AI, `risk.py`), `core/validators.py`, `templates/`, `static/`, `scripts/`.
