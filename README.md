# AuditPilot

AuditPilot is a local code security audit prototype built with FastAPI, a static frontend, and an agent-style audit workflow. It supports uploading source files, directories, and archives, then generates findings and reports.

## Features

- User registration and login
- Normal user and administrator roles
- Bootstrap administrator account from `.env`
- Multi-file and directory upload
- Static and LLM-assisted review flow
- WebSocket progress events
- HTML, Markdown, and JSON reports
- Admin page for user control and auditing user tasks

## Project Layout

```text
backend/
  app/
    api/          FastAPI routes
    agent/        Audit workflow
    scanners/     Heuristic scanners
    services/     Auth, audit, reports, files, events
frontend/
  index.html      User console
  admin.html      Administrator console
  assets/
scripts/
  smoke_test.py
dev.py            Cross-platform dev stack controller
```

## Requirements

- Python 3.12+
- Windows, macOS, or Linux
- Optional: Redis
- Optional: DeepSeek API key for real LLM review

## Environment

Create `.env` from the example:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Important local settings:

```env
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000
FRONTEND_HOST=127.0.0.1
FRONTEND_PORT=3000
AUTH_SECRET_KEY=change-me-local-auth-secret
ADMIN_BOOTSTRAP_USERNAME=admin
ADMIN_BOOTSTRAP_EMAIL=admin@example.com
ADMIN_BOOTSTRAP_PASSWORD=Admin123456!
ADMIN_BOOTSTRAP_RESET_PASSWORD=false
```

The bootstrap admin is ensured on startup. Existing admin passwords are not overwritten unless `ADMIN_BOOTSTRAP_RESET_PASSWORD=true`.

## Start And Stop

Use the single cross-platform controller:

```bash
python dev.py start
python dev.py stop
python dev.py status
python dev.py restart
```

`dev.py` creates or reuses `.venv`, installs `requirements.txt`, generates `frontend/assets/runtime-config.js`, and starts the backend and frontend. The project uses `.venv` only; do not activate an old `venv` directory.

Optional overrides:

```bash
python dev.py start --backend-port 18000 --frontend-port 13000 --open-browser
```

Default URLs:

- Frontend: `http://127.0.0.1:3000`
- Admin page: `http://127.0.0.1:3000/admin.html`
- Backend: `http://127.0.0.1:8000`
- Swagger: `http://127.0.0.1:8000/docs`

## Smoke Test

Keep the stack running, then run:

```bash
.venv/bin/python scripts/smoke_test.py
```

On Windows:

```powershell
.\.venv\Scripts\python.exe scripts\smoke_test.py
```

The smoke test registers a temporary user, uploads the sample vulnerable file, starts an audit, waits for completion, and prints report information.

## Logs And Runtime Data

```text
backend/data/runtime/backend.out.log
backend/data/runtime/backend.err.log
backend/data/runtime/frontend.out.log
backend/data/runtime/frontend.err.log
backend/data/auditpilot.db
backend/data/uploads/
backend/data/projects/
backend/data/reports/
```

## Deployment Notes

For production-style deployment, run FastAPI behind a process manager and serve `frontend/` with Nginx, IIS, or another static file server. Configure `/api/`, `/docs`, `/openapi.json`, and `/api/v1/ws/` to proxy to the backend.
