#!/usr/bin/env bash
# AuditPilot Linux 单脚本部署入口：Nginx + systemd + SQLite + Redis。
set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="auditpilot"
SERVICE_USER="auditpilot"
SERVICE_GROUP="auditpilot"
BACKEND_PORT="${BACKEND_PORT:-8000}"
HTTP_PORT="${HTTP_PORT:-80}"
ENV_DIR="/etc/${SERVICE_NAME}"
ENV_FILE="${ENV_DIR}/${SERVICE_NAME}.env"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
NGINX_FILE="/etc/nginx/conf.d/${SERVICE_NAME}.conf"
ACTION="${1:-start}"

green='\033[0;32m'
yellow='\033[1;33m'
red='\033[0;31m'
reset='\033[0m'

log() { printf "${green}[AuditPilot]${reset} %s\n" "$*"; }
warn() { printf "${yellow}[AuditPilot]${reset} %s\n" "$*"; }
die() { printf "${red}[AuditPilot]${reset} %s\n" "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "此脚本仅用于 Linux。"
[[ -f "${PROJECT_DIR}/requirements.txt" ]] || die "请把 start-linux.sh 放在 AuditPilot 项目根目录。"
command -v systemctl >/dev/null 2>&1 || die "此脚本需要 systemd。"
[[ "${HTTP_PORT}" =~ ^[0-9]{1,5}$ ]] && (( HTTP_PORT > 0 && HTTP_PORT < 65536 )) || die "HTTP_PORT 必须是 1-65535。"
[[ "${BACKEND_PORT}" =~ ^[0-9]{1,5}$ ]] && (( BACKEND_PORT > 0 && BACKEND_PORT < 65536 )) || die "BACKEND_PORT 必须是 1-65535。"

as_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "请使用 root 运行，或安装 sudo 后重新执行。"
  fi
}

as_app_user() {
  as_root runuser -u "${SERVICE_USER}" -- "$@"
}

random_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else
    od -An -N "$1" -tx1 /dev/urandom | tr -d ' \n'
  fi
}

detect_public_origin() {
  if [[ -n "${PUBLIC_ORIGIN:-}" ]]; then
    printf '%s' "${PUBLIC_ORIGIN%/}"
    return
  fi

  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  ip="${ip:-127.0.0.1}"
  if [[ "${HTTP_PORT}" == "80" ]]; then
    printf 'http://%s' "${ip}"
  else
    printf 'http://%s:%s' "${ip}" "${HTTP_PORT}"
  fi
}

install_system_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    as_root apt-get update
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip nginx redis-server curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y python3 python3-pip nginx redis curl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    as_root yum install -y python3 python3-pip nginx redis curl ca-certificates
  else
    die "仅识别 apt、dnf 或 yum 系统。"
  fi
}

ensure_service_user() {
  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    as_root useradd --system --create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
  fi
  as_root mkdir -p "${PROJECT_DIR}/backend/data" "${ENV_DIR}"
  as_root chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${PROJECT_DIR}" "${ENV_DIR}"
}

create_env_file() {
  if [[ -f "${ENV_FILE}" ]]; then
    log "复用已有运行配置：${ENV_FILE}"
    return
  fi

  local public_origin auth_secret credential_secret admin_password cors_json
  public_origin="$(detect_public_origin)"
  auth_secret="${AUTH_SECRET_KEY:-$(random_hex 32)}"
  credential_secret="${CREDENTIAL_ENCRYPTION_KEY:-$(random_hex 32)}"
  admin_password="${ADMIN_BOOTSTRAP_PASSWORD:-AP-$(random_hex 12)}"
  cors_json="[\"${public_origin}\"]"

  cat <<EOF | as_root tee "${ENV_FILE}" >/dev/null
APP_NAME=AuditPilot
API_V1_PREFIX=/api/v1
BACKEND_SCHEME=http
BACKEND_HOST=127.0.0.1
BACKEND_PORT=${BACKEND_PORT}
BACKEND_PUBLIC_URL=${public_origin}
FRONTEND_SCHEME=http
FRONTEND_HOST=127.0.0.1
FRONTEND_PORT=${HTTP_PORT}
FRONTEND_PUBLIC_URL=${public_origin}
FRONTEND_API_BASE_URL=${public_origin}/api/v1
CORS_ORIGINS=${cors_json}
AUTH_SECRET_KEY=${auth_secret}
CREDENTIAL_ENCRYPTION_KEY=${credential_secret}
ADMIN_BOOTSTRAP_USERNAME=${ADMIN_BOOTSTRAP_USERNAME:-admin}
ADMIN_BOOTSTRAP_EMAIL=${ADMIN_BOOTSTRAP_EMAIL:-admin@example.com}
ADMIN_BOOTSTRAP_PASSWORD=${admin_password}
ADMIN_BOOTSTRAP_RESET_PASSWORD=false
DATABASE_URL=sqlite:///${PROJECT_DIR}/backend/data/auditpilot.db
REDIS_URL=redis://127.0.0.1:6379/0
STORAGE_ROOT=${PROJECT_DIR}/backend/data
UPLOAD_MAX_FILE_BYTES=209715200
UPLOAD_MAX_TOTAL_BYTES=209715200
EOF
  as_root chmod 600 "${ENV_FILE}"
  as_root chown "${SERVICE_USER}:${SERVICE_GROUP}" "${ENV_FILE}"

  log "管理员账号：${ADMIN_BOOTSTRAP_USERNAME:-admin}"
  log "管理员密码：${admin_password}"
  warn "请立即保存管理员密码；它保存在 ${ENV_FILE}。"
}

install_python_dependencies() {
  if [[ ! -x "${PROJECT_DIR}/.venv/bin/python" ]]; then
    log "创建 Python 虚拟环境"
    as_app_user python3 -m venv "${PROJECT_DIR}/.venv"
  fi
  log "安装 Python 依赖"
  as_app_user "${PROJECT_DIR}/.venv/bin/python" -m pip install --upgrade pip
  as_app_user "${PROJECT_DIR}/.venv/bin/python" -m pip install -r "${PROJECT_DIR}/requirements.txt"
}

write_runtime_config() {
  cat <<'EOF' | as_root tee "${PROJECT_DIR}/frontend/assets/runtime-config.js" >/dev/null
window.AUDITPILOT_CONFIG = Object.freeze({
  apiBaseUrl: `${window.location.origin}/api/v1`,
  apiPrefix: "/api/v1",
  backendUrl: window.location.origin,
  docsUrl: `${window.location.origin}/docs`
});
EOF
  as_root chown "${SERVICE_USER}:${SERVICE_GROUP}" "${PROJECT_DIR}/frontend/assets/runtime-config.js"
}

write_systemd_service() {
  cat <<EOF | as_root tee "${SERVICE_FILE}" >/dev/null
[Unit]
Description=AuditPilot FastAPI service
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${PROJECT_DIR}/.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port ${BACKEND_PORT} --workers 1 --proxy-headers
Restart=always
RestartSec=3
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
}

write_nginx_config() {
  cat <<EOF | as_root tee "${NGINX_FILE}" >/dev/null
server {
    listen ${HTTP_PORT};
    listen [::]:${HTTP_PORT};
    server_name _;
    root ${PROJECT_DIR}/frontend;
    index index.html;
    client_max_body_size 220m;

    location /api/ {
        proxy_pass http://127.0.0.1:${BACKEND_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location = /docs { proxy_pass http://127.0.0.1:${BACKEND_PORT}/docs; }
    location = /openapi.json { proxy_pass http://127.0.0.1:${BACKEND_PORT}/openapi.json; }

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0";
    }
}
EOF
}

open_firewall_port() {
  if command -v firewall-cmd >/dev/null 2>&1 && as_root systemctl is-active --quiet firewalld; then
    as_root firewall-cmd --permanent --add-port="${HTTP_PORT}/tcp" >/dev/null
    as_root firewall-cmd --reload >/dev/null
  elif command -v ufw >/dev/null 2>&1 && as_root ufw status | grep -q "Status: active"; then
    as_root ufw allow "${HTTP_PORT}/tcp" >/dev/null
  fi
}

health_check() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${BACKEND_PORT}/api/v1/health" >/dev/null; then
      return
    fi
    sleep 1
  done
  as_root journalctl -u "${SERVICE_NAME}" -n 80 --no-pager || true
  die "服务启动后未通过健康检查。"
}

show_access_info() {
  local origin username
  origin="$(grep '^FRONTEND_PUBLIC_URL=' "${ENV_FILE}" | cut -d= -f2-)"
  username="$(grep '^ADMIN_BOOTSTRAP_USERNAME=' "${ENV_FILE}" | cut -d= -f2-)"
  log "部署完成：${origin}"
  log "API 文档：${origin}/docs"
  log "管理员账号：${username}"
  log "查看日志：sudo bash start-linux.sh logs"
}

deploy() {
  install_system_packages
  ensure_service_user
  create_env_file
  install_python_dependencies
  write_runtime_config
  write_systemd_service
  write_nginx_config
  as_root systemctl daemon-reload
  as_root systemctl enable --now redis-server 2>/dev/null \
    || as_root systemctl enable --now redis 2>/dev/null \
    || warn "Redis 未作为 systemd 服务启动，实时事件将使用进程内回退。"
  as_root systemctl enable --now "${SERVICE_NAME}"
  as_root nginx -t
  as_root systemctl enable --now nginx
  as_root systemctl reload nginx
  open_firewall_port
  health_check
  show_access_info
}

case "${ACTION}" in
  start|install|deploy) deploy ;;
  restart) as_root systemctl restart "${SERVICE_NAME}"; health_check; show_access_info ;;
  stop) as_root systemctl stop "${SERVICE_NAME}"; log "AuditPilot 已停止。" ;;
  status) as_root systemctl status "${SERVICE_NAME}" --no-pager ;;
  logs) as_root journalctl -u "${SERVICE_NAME}" -f ;;
  *)
    printf '用法：sudo bash start-linux.sh [start|restart|stop|status|logs]\n' >&2
    exit 2
    ;;
esac
