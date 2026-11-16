# scanX

**Portable, Django-based web application for authorized security reconnaissance.**

scanX wraps a battle-tested Bash reconnaissance script (`scanner/scanx.sh`) in a modern web interface with live log streaming, scan history, and artifact downloads.

---

## Features (Phase 1)

- **Dashboard** — Start new scans with domain validation and authorization confirmation
- **Live Logs** — Real-time streaming of scanner output via background worker
- **Scan History** — Paginated list of all scans with status, timestamps, and statistics
- **Artifact Downloads** — Download `alldomains.txt`, `live.txt`, `httpx.txt`, `report.txt`
- **Dark-first UI** — Lime-green accent, responsive design, theme toggle
- **Portable** — Works on any Linux device with configurable paths
- **Secure** — No shell injection, isolated scan directories, input validation

---

## Quick Start

```bash
# Clone and enter
git clone <repo-url> scanX
cd scanX

# Run installer (installs deps, sets up venv, Go tools, database)
./scripts/install.sh

# Edit .env with your Chaos API key
nano .env

# Start development server + background worker
./scripts/start.sh

# Open http://localhost:8000
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    scanX Django App                          │
├─────────────────────────────────────────────────────────────┤
│  Dashboard (scan form + history)                            │
│  Scan Detail (live logs + stats + downloads)                │
│  API: /scan/<id>/logs/ (polling for live output)            │
└──────────────────────────┬──────────────────────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
┌─────────────────────┐             ┌─────────────────────┐
│  Django Web Process │             │  Worker Process     │
│  (gunicorn/runserver)            │  (manage.py worker) │
│  - Handles HTTP     │             │  - Polls DB for     │
│  - Creates Scan     │             │    pending scans    │
│  - Serves UI        │             │  - Runs scanx.sh    │
└─────────────────────┘             └─────────────────────┘
                           │
                           ▼
              ┌─────────────────────────────┐
              │     Scan Data Directory     │
              │  (SCANX_DATA_DIR)           │
              │  scan_data/<scan_id>/       │
              │    ├── <domain>/            │
              │    │   ├── alldomains.txt   │
              │    │   ├── live.txt         │
              │    │   ├── httpx.txt        │
              │    │   └── report.txt       │
              │    └── live.log (streaming) │
              └─────────────────────────────┘
```

---

## External Tools Required

The Bash scanner (`scanner/scanx.sh`) depends on these tools:

| Tool | Purpose | Install |
|------|---------|---------|
| `figlet` | ASCII banner | `apt install figlet` |
| `subfinder` | Subdomain enum | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `assetfinder` | Subdomain enum | `go install -v github.com/tomnomnom/assetfinder@latest` |
| `chaos` | Chaos dataset | `go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest` |
| `crt` | Cert transparency | `go install -v github.com/projectdiscovery/crt/cmd/crt@latest` |
| `dnsx` | DNS resolution | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `httpx` | HTTP probing | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |

The installer script (`./scripts/install.sh`) attempts to install these automatically.

---

## Configuration

All settings via `.env` file (copy from `.env.example`):

```bash
# Django
DEBUG=True
SECRET_KEY=your-secret-key
ALLOWED_HOSTS=localhost,127.0.0.1

# Data directory (absolute path recommended for production)
SCANX_DATA_DIR=/var/lib/scanx

# Chaos API key (required for chaos tool)
CHAOS_API_KEY=your-key-from-chaos.projectdiscovery.io

# Additional PATH for Go tools
TOOLS_PATH=/usr/local/go/bin:$HOME/go/bin

# Scan timeout (seconds)
SCAN_TIMEOUT=3600

# Database (SQLite default, use PostgreSQL for production)
DATABASE_URL=sqlite:///db.sqlite3
```

---

## Running in Production

1. **Set `DEBUG=False` and strong `SECRET_KEY`**
2. **Use PostgreSQL**: `DATABASE_URL=postgres://user:pass@host:port/db`
3. **Set `SCANX_DATA_DIR` to persistent volume** (e.g., `/var/lib/scanx`)
4. **Run with Gunicorn**:
   ```bash
   gunicorn scanx.wsgi:application --bind 0.0.0.0:8000 --workers 3
   ```
5. **Run worker as systemd service**:
   ```ini
   # /etc/systemd/system/scanx-worker.service
   [Unit]
   Description=scanX Background Worker
   After=network.target

   [Service]
   Type=simple
   User=scanx
   WorkingDirectory=/opt/scanX
   EnvironmentFile=/opt/scanX/.env
   ExecStart=/opt/scanX/venv/bin/python manage.py worker
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```
6. **Reverse proxy** (Nginx) for static files and SSL

---

## Security

- **Authorization required**: Every scan needs explicit confirmation
- **Domain validation**: Strict RFC 1035 + shell metacharacter blocking
- **No shell injection**: Subprocess args passed as list, never `shell=True`
- **Isolated scan directories**: Each scan runs in own subdirectory
- **Secrets in env vars**: Never in code or logs
- **Rate limiting**: Configure at reverse proxy level

---

## Project Structure

```
scanX/
├── manage.py                 # Django CLI
├── scanx/                    # Project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── scanner/                  # Scanner app
│   ├── models.py             # Scan model
│   ├── views.py              # Dashboard, detail, logs API
│   ├── services.py           # ScanExecutor, log streaming
│   ├── management/commands/
│   │   ├── check_tools.py    # Dependency verification
│   │   └── worker.py         # Background worker
│   └── scanx.sh              # Original Bash scanner (source of truth)
├── core/                     # Shared utilities
│   └── validators.py         # Domain validation
├── templates/
│   ├── base.html             # Layout (from ui-reference.html)
│   ├── dashboard.html
│   ├── scan_detail.html
│   └── history.html
├── static/
│   ├── css/scanx.css         # Design system
│   └── js/scanx.js           # Live logs, theme toggle
├── scripts/
│   ├── install.sh            # Full installation
│   └── start.sh              # Dev server + worker
├── scan_data/                # Runtime scan outputs (gitignored)
├── .env.example              # Config template
├── requirements.txt
└── README.md
```

---

## Development

```bash
# Run tests
python manage.py test

# Check tools
python manage.py check_tools --install-hints

# Run worker only
python manage.py worker --interval 2

# Django shell
python manage.py shell

# Create superuser
python manage.py createsuperuser
```

---

## License

For authorized security testing only. See `AGENTS.md` for scope and rules.