# AuditPilot

AuditPilot is a local code security audit prototype built with FastAPI, a static frontend, and an agent-style audit workflow. It supports uploading source files, directories, and archives, then generates findings and reports.

## Features

- User registration and login
- Normal user and administrator roles
- Optional bootstrap administrator account from `.env`
- Multi-file and directory upload
- Static and LLM-assisted review flow
- Optional Java audit skill integration from `RuoJi6/java-audit-skills`
- WebSocket progress events
- HTML, Markdown, and JSON reports
- Admin page for user control and auditing user tasks
- Per-user OpenAI, DeepSeek, and OpenAI-compatible API settings with encrypted API-key storage
- Automatic model discovery from each user's configured OpenAI-compatible `/models` endpoint
- Admin stop control for queued or running ordinary-user audits
- Independent task-center tab with filtering, renaming, retry, single/bulk deletion, history restore, and baseline selection
- Restart recovery for persisted queued/running audits
- Provider adapters for OpenAI, DeepSeek, OpenAI-compatible, Azure OpenAI, and Ollama
- Incremental file scanning, finding comparison, and source-to-sink call-chain candidates
- Per-user monthly token quotas, usage accounting, login sessions, and administrator operation logs
- LLM usage analytics with period filters, streaks, activity heatmap, and per-model ranking
- Upload/file-count/archive-expansion/storage quota controls
- Alembic database migrations

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
AUTH_SECRET_KEY=
CREDENTIAL_ENCRYPTION_KEY=
ADMIN_BOOTSTRAP_USERNAME=
ADMIN_BOOTSTRAP_EMAIL=
ADMIN_BOOTSTRAP_PASSWORD=
ADMIN_BOOTSTRAP_RESET_PASSWORD=false
HUMAN_CHECK_CHALLENGE_TTL_SECONDS=300
HUMAN_CHECK_PROOF_TTL_SECONDS=300
HUMAN_CHECK_MIN_COMPLETION_MS=1200
JAVA_AUDIT_SKILLS_ENABLED=true
JAVA_AUDIT_SKILLS_ROOT=
```

## Database Migration

Back up the database, then apply the tracked schema revision:

```powershell
python -m alembic upgrade head
python -m alembic current
```

The first revision adopts existing tables, adds missing platform columns, and creates the session, usage, and administrator log tables. Runtime startup keeps a compatibility column check for older local databases.

## New API Surfaces

- `GET /api/v1/audit/tasks` — paginated personal task history
- `PATCH /api/v1/audit/{task_id}` — rename a task
- `POST /api/v1/audit/{task_id}/retry` — retry terminal tasks
- `DELETE /api/v1/audit/{task_id}` — remove task artifacts and data
- `GET /api/v1/audit/{task_id}/compare/{baseline_task_id}` — compare findings
- `GET /api/v1/auth/llm-usage` — current-month token usage
- `GET/DELETE /api/v1/auth/sessions` — list or revoke sessions
- `GET /api/v1/admin/audit-logs` — administrator action history
- `PATCH /api/v1/admin/users/{user_id}/llm-quota` — update a monthly token quota
- `POST /api/v1/admin/users/{user_id}/sessions/revoke` — revoke a user’s sessions

Set `AUTH_SECRET_KEY` explicitly if you want stable tokens across restarts. When it is empty, the backend falls back to a per-process secret so placeholder values cannot be abused.
For local use, the first API-key save automatically creates `backend/data/.credential_encryption_key` and reuses it across restarts. An explicit `CREDENTIAL_ENCRYPTION_KEY` takes precedence; existing deployments with only `AUTH_SECRET_KEY` keep using that value. The raw per-user key is never returned by the API or shown again in the UI.
Bootstrap admin creation is disabled by default and only runs when `ADMIN_BOOTSTRAP_USERNAME`, `ADMIN_BOOTSTRAP_EMAIL`, and a non-placeholder `ADMIN_BOOTSTRAP_PASSWORD` are all configured. Existing admin passwords are not overwritten unless `ADMIN_BOOTSTRAP_RESET_PASSWORD=true`.
The registration slider now requires a backend-issued, single-use proof token before account creation. This closes the old direct-API bypass for the frontend-only check, but an internet-facing deployment should still consider a managed bot-defense service such as Cloudflare Turnstile or hCaptcha.
If `JAVA_AUDIT_SKILLS_ROOT` is empty, the backend defaults to `~/.codex/skills` and will automatically append installed Java audit skill guidance for Java projects.
For Java projects, you can enable full-file review context and stricter heuristic corroboration to cut down false positives in uploaded code.

## Start And Stop

Use the single cross-platform controller:

```bash
python dev.py start
python dev.py stop
python dev.py status
python dev.py restart
```

`dev.py` creates or reuses `.venv`, installs `requirements.txt`, generates `frontend/assets/runtime-config.js`, and starts the backend and frontend. The project uses `.venv` only; do not activate an old `venv` directory.

## Linux 单脚本启动

把完整项目目录上传到 Linux 服务器后，只需要执行这一条命令：

```bash
cd /opt/auditpilot
sudo bash start-linux.sh
```

`start-linux.sh` 会自动安装 Python、Nginx、Redis 和项目依赖，创建独立服务用户、生成安全配置、写入 systemd 服务、配置 Nginx 反向代理、启动服务并完成健康检查。默认使用持久化 SQLite 数据库，访问入口为：

```text
http://服务器IP/
```

首次启动时脚本会在终端输出管理员账号和随机密码；运行配置保存于 `/etc/auditpilot/auditpilot.env`。指定域名、端口或固定管理员信息：

```bash
sudo env \
  PUBLIC_ORIGIN=https://audit.example.com \
  HTTP_PORT=80 \
  ADMIN_BOOTSTRAP_USERNAME=admin \
  ADMIN_BOOTSTRAP_EMAIL=admin@example.com \
  ADMIN_BOOTSTRAP_PASSWORD='StrongPassword-ChangeMe' \
  bash start-linux.sh
```

日常操作：

```bash
sudo bash start-linux.sh restart
sudo bash start-linux.sh stop
sudo bash start-linux.sh status
sudo bash start-linux.sh logs
```

## Linux Docker 一键部署

仓库内置 Linux 部署脚本，包含 Nginx、FastAPI、MySQL、Redis、数据库迁移、健康检查和持久卷：

```bash
cd /opt
git clone <YOUR_REPOSITORY_URL> auditpilot
cd auditpilot
sudo bash deploy-linux.sh
```

脚本会自动完成：

- 检查并安装 Docker Engine 与 Compose 插件；
- 生成权限为 `600` 的 `.env.docker`；
- 随机生成 MySQL、Token 签名和 API Key 加密密钥；
- 创建管理员账号密码；
- 构建镜像、迁移数据库并启动全部服务；
- 等待健康检查完成，然后输出访问地址和管理员密码。

首次部署前可通过环境变量指定地址、端口和管理员：

```bash
sudo env \
  PUBLIC_ORIGIN=http://192.0.2.10:8080 \
  HTTP_PORT=8080 \
  ADMIN_BOOTSTRAP_USERNAME=admin \
  ADMIN_BOOTSTRAP_EMAIL=admin@example.com \
  ADMIN_BOOTSTRAP_PASSWORD='Replace-With-A-Strong-Password' \
  bash deploy-linux.sh
```

常用运维命令：

```bash
sudo bash deploy-linux.sh status
sudo bash deploy-linux.sh logs
sudo bash deploy-linux.sh restart
sudo bash deploy-linux.sh update
sudo bash deploy-linux.sh stop
sudo bash deploy-linux.sh down
```

配置位于 `.env.docker`，业务上传、项目、报告、MySQL 和 Redis 数据保存在 Docker 持久卷中。修改 `.env.docker` 后执行：

```bash
sudo bash deploy-linux.sh update
```

如果通过域名和 HTTPS 对外服务，将 `PUBLIC_ORIGIN` 设置为最终的 `https://域名`，并在当前 Nginx 前配置证书终止或云负载均衡。

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

Feature integration checks:

```powershell
.\.venv\Scripts\python.exe scripts\test_user_llm_config_and_task_stop.py
```

The smoke test registers a temporary user, uploads the sample vulnerable file, starts an audit, waits for completion, and prints report information.

Frontend-only checks do not require pytest or a build step:

```bash
python scripts/check_frontend.py
node scripts/test_register_slider.js --url=http://127.0.0.1:3000 --browser=chrome
```

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
