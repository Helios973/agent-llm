# AuditPilot Local Quickstart

## Requirements

- Python 3.12+
- Windows, macOS, or Linux

## Prepare Environment

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Edit `.env` if you need custom ports, database, Redis, LLM, or the bootstrap admin account.

## Start And Stop

Use the single cross-platform controller:

```bash
python dev.py start
python dev.py stop
python dev.py status
python dev.py restart
```

`dev.py` will create or reuse `.venv`, install `requirements.txt`, generate `frontend/assets/runtime-config.js`, and start both services.

Default URLs:

- Frontend: `http://127.0.0.1:3000`
- Admin page: `http://127.0.0.1:3000/admin.html`
- Backend: `http://127.0.0.1:8000`
- Swagger: `http://127.0.0.1:8000/docs`

Optional port overrides:

```bash
python dev.py start --backend-port 18000 --frontend-port 13000 --open-browser
```

You can also set these in `.env`:

```env
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000
FRONTEND_HOST=127.0.0.1
FRONTEND_PORT=3000
```

## Smoke Test

Keep the stack running, then run:

```bash
.venv/bin/python scripts/smoke_test.py
```

On Windows:

```powershell
.\.venv\Scripts\python.exe scripts\smoke_test.py
```

## Logs

Runtime logs are written to:

```text
backend/data/runtime/backend.out.log
backend/data/runtime/backend.err.log
backend/data/runtime/frontend.out.log
backend/data/runtime/frontend.err.log
```
