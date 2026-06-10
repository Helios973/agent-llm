# 更新说明

更新时间：2026-06-10

本文档记录本轮已完成的主要改动，覆盖环境变量、启动方式、登录注册、用户权限、管理员管理页、默认管理员初始化、接口鉴权和验证情况。

## 1. 环境变量与运行配置

- 前端不再硬编码后端地址，改为由本地 `.env` 和启动脚本生成的运行时配置决定。
- `.env.example` 补充了前后端地址、端口、公开访问地址、认证密钥、Token 有效期、管理员初始化账号等配置项。
- 后端配置 `backend/app/core/config.py` 已改为读取 `.env`，并允许额外环境变量存在，避免部署时因为无关配置报错。
- CORS 配置会根据前端公开地址自动推导；如果显式配置 `CORS_ORIGINS`，则优先使用该值。
- 前端运行时配置文件由 `dev.py` 自动生成到 `frontend/assets/runtime-config.js`，该文件已加入 `.gitignore`。

主要相关变量：

- `BACKEND_SCHEME`
- `BACKEND_HOST`
- `BACKEND_PORT`
- `BACKEND_PUBLIC_URL`
- `FRONTEND_SCHEME`
- `FRONTEND_HOST`
- `FRONTEND_PORT`
- `FRONTEND_PUBLIC_URL`
- `FRONTEND_API_BASE_URL`
- `AUTH_SECRET_KEY`
- `AUTH_TOKEN_TTL_SECONDS`
- `ADMIN_BOOTSTRAP_USERNAME`
- `ADMIN_BOOTSTRAP_EMAIL`
- `ADMIN_BOOTSTRAP_PASSWORD`
- `ADMIN_BOOTSTRAP_RESET_PASSWORD`
- `PYTHON_EXECUTABLE`

部署前建议修改 `AUTH_SECRET_KEY` 和 `ADMIN_BOOTSTRAP_PASSWORD`。

## 2. 跨平台启动与停止

- 新增统一入口 `dev.py`，用于替代 Windows 专用的 `.ps1` / `.cmd` 启停脚本。
- 支持 Windows、macOS、Linux 使用同一套命令启动、停止、查看状态和重启服务。
- `dev.py` 会自动创建并使用项目根目录下的 `.venv`，不再依赖旧的 `venv` 目录。
- 启动时会检查依赖，必要时从 `requirements.txt` 安装。
- 启动时会同时拉起后端 FastAPI 服务和前端静态服务。
- 进程状态写入 `scripts/dev-processes.json`，日志写入 `backend/data/runtime/`。
- 已删除旧的冗余启动/停止脚本：
  - `start.ps1`
  - `stop.ps1`
  - `start.cmd`
  - `stop.cmd`
  - `scripts/start-dev.ps1`
  - `scripts/stop-dev.ps1`
- 已按要求删除旧 `venv/` 目录，当前只保留 `.venv/` 作为项目虚拟环境。

常用命令：

```powershell
python .\dev.py
python .\dev.py start
python .\dev.py status
python .\dev.py restart
python .\dev.py stop
```

默认访问地址：

- 前端：`http://127.0.0.1:3000/`
- 后端：`http://127.0.0.1:8000/`
- API 文档：`http://127.0.0.1:8000/docs`

## 3. 登录与注册

- 新增用户注册接口：`POST /api/v1/auth/register`
- 新增用户登录接口：`POST /api/v1/auth/login`
- 新增当前用户接口：`GET /api/v1/auth/me`
- 注册账号默认角色为普通用户 `user`。
- 密码使用 PBKDF2-HMAC-SHA256 加盐哈希保存，不再明文保存。
- 登录成功后返回 Bearer Token，前端保存到 `localStorage`。
- 前端请求会自动带上 `Authorization: Bearer <token>`。
- Token 失效或接口返回 401 时，前端会自动回到登录状态。

新增或修改的主要文件：

- `backend/app/api/routes/auth.py`
- `backend/app/schemas/auth.py`
- `backend/app/services/auth_service.py`
- `frontend/index.html`
- `frontend/assets/app.js`
- `frontend/assets/styles.css`

## 4. 普通用户与管理员权限

- 用户模型 `backend/app/models.py` 增加：
  - `password_hash`
  - `role`
  - `is_active`
- `role` 支持：
  - `user`：普通用户
  - `admin`：管理员
- 普通用户只能访问、审计和下载自己的任务内容。
- 管理员可以访问普通用户的任务、审计结果和报告。
- 管理员接口统一挂在 `/api/v1/admin` 下。
- 管理员无法禁用自己的管理员账号，也无法把自己降级为普通用户，避免锁死后台。

新增管理员接口：

- `GET /api/v1/admin/users`
- `PATCH /api/v1/admin/users/{user_id}`
- `GET /api/v1/admin/users/{user_id}/tasks`

新增或修改的主要文件：

- `backend/app/api/routes/admin.py`
- `backend/app/api/router.py`
- `backend/app/api/routes/upload.py`
- `backend/app/api/routes/audit.py`
- `backend/app/api/routes/report.py`
- `backend/app/api/routes/sandbox.py`

## 5. 管理员管理页面

- 新增独立管理员页面：`frontend/admin.html`
- 新增管理员页面脚本：`frontend/assets/admin.js`
- 管理员页面会校验当前登录用户是否为管理员。
- 管理员可以查看用户列表、用户角色、账号启用状态和任务数量。
- 管理员可以修改普通用户角色和启用状态。
- 管理员可以查看指定用户任务、启动审计、查看发现项、下载报告。
- 普通用户不会显示管理员入口，直接访问管理员页面也会被拦截。

## 6. 默认管理员初始化

- 数据库初始化时会确保存在一个管理员账号，避免模型迁移、数据库迁移或部署后管理员账户丢失。
- 默认管理员由 `.env` 中的 `ADMIN_BOOTSTRAP_*` 配置控制。
- 如果管理员不存在，启动时自动创建。
- 如果管理员已存在，会确保它保持 `admin` 角色且处于启用状态。
- 如果 `ADMIN_BOOTSTRAP_RESET_PASSWORD=true`，启动时会重置默认管理员密码。

相关文件：

- `backend/app/core/database.py`
- `backend/app/core/config.py`

## 7. 数据库兼容迁移

- 启动时会检查 `users` 表是否缺少认证相关字段。
- 如果旧数据库没有 `password_hash`、`role`、`is_active`，会自动补列。
- 这样可以让已有 SQLite 数据库继续运行，不需要手动删库。

相关文件：

- `backend/app/core/database.py`

## 8. 接口鉴权与任务归属

- 上传、审计、报告、沙箱相关接口都已接入登录校验。
- 上传任务时不再信任前端传入的 `user_id`，任务归属以当前登录用户为准。
- 审计结果、报告下载、沙箱操作都会校验任务归属。
- WebSocket 审计日志支持通过 `access_token` 查询参数认证，前端已自动拼接。
- 管理员可以跨用户访问任务；普通用户只能访问自己的任务。

相关文件：

- `backend/app/api/routes/upload.py`
- `backend/app/api/routes/audit.py`
- `backend/app/api/routes/report.py`
- `backend/app/api/routes/sandbox.py`
- `frontend/assets/app.js`
- `frontend/assets/admin.js`

## 9. 前端页面改动

- `frontend/index.html` 增加登录/注册入口，未登录时不能使用平台功能。
- 登录后显示主应用、当前账号信息、退出登录按钮。
- 管理员登录后显示管理员页面入口。
- `frontend/assets/app.js` 增加认证状态管理、注册登录流程、自动鉴权请求、401 处理和 WebSocket Token 拼接。
- `frontend/assets/styles.css` 增加登录页、账号区域、管理员表格和管理页布局样式。
- `frontend/README.md` 已同步改为使用 `python dev.py` 启动。

## 10. 文档与冒烟测试

- `README.md` 已更新为当前运行方式和认证/管理员说明。
- `docs/local-run.md` 已更新为跨平台 `dev.py` 启动流程。
- 删除旧的 `docs/local-run-review.md`，避免与当前启动方式重复。
- `scripts/smoke_test.py` 已改为：
  - 读取 `.env`
  - 自动注册临时用户
  - 登录获取 Token
  - 上传示例文件
  - 启动审计
  - 轮询结果
  - 输出报告信息

## 11. 当前验证情况

已完成的验证：

- `python .\dev.py` 可以启动前后端。
- `python .\dev.py status` 可以查看运行状态。
- 后端健康检查 `http://127.0.0.1:8000/api/v1/health` 正常返回。
- 前端首页 `http://127.0.0.1:3000/` 可访问。
- 管理员页面 `http://127.0.0.1:3000/admin.html` 可访问。
- 默认管理员可以登录。
- 普通用户注册后角色为 `user`。
- 普通用户访问管理员接口会返回 403。
- 管理员可以查看普通用户任务、启动审计并读取结果。
- 禁用普通用户后，旧 Token 会失效，登录也会被拒绝。
- 冒烟测试脚本已通过认证流程和基础审计流程。

已知情况：

- 旧 `venv/` 目录已删除，因此 `git status` 会显示大量 `venv/...` 删除记录；这是按要求清理旧虚拟环境导致的。
- 后续运行请使用 `.venv/`，如果 PowerShell 提示符仍显示 `(venv)`，可以先执行 `deactivate` 清掉旧激活状态。
- 之前运行完整单元测试时，存在两个与本次认证/启动改动无关的旧扫描器测试失败，原因是测试数据中缺少 `cwe_id` 字段。

