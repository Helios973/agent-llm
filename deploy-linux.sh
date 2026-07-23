#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env.docker"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
ACTION="${1:-deploy}"

color_green='\033[0;32m'
color_yellow='\033[1;33m'
color_red='\033[0;31m'
color_reset='\033[0m'

log() { printf "${color_green}[AuditPilot]${color_reset} %s\n" "$*"; }
warn() { printf "${color_yellow}[AuditPilot]${color_reset} %s\n" "$*"; }
die() { printf "${color_red}[AuditPilot] %s${color_reset}\n" "$*" >&2; exit 1; }

[[ "$(uname -s)" == "Linux" ]] || die "此脚本用于 Linux。"
[[ -f "${COMPOSE_FILE}" ]] || die "未找到 ${COMPOSE_FILE}"

run_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "安装 Docker 需要 root 权限，请使用 root 运行此脚本。"
  fi
}

random_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "${1:-32}"
  else
    head -c "${1:-32}" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    return
  fi
  log "安装 Docker Engine 与 Compose 插件..."
  command -v curl >/dev/null 2>&1 || {
    if command -v apt-get >/dev/null 2>&1; then
      run_root apt-get update && run_root apt-get install -y curl ca-certificates
    elif command -v dnf >/dev/null 2>&1; then
      run_root dnf install -y curl ca-certificates
    elif command -v yum >/dev/null 2>&1; then
      run_root yum install -y curl ca-certificates
    else
      die "请先安装 curl。"
    fi
  }
  local installer
  installer="$(mktemp)"
  curl -fsSL https://get.docker.com -o "${installer}"
  run_root sh "${installer}"
  rm -f "${installer}"
  run_root systemctl enable --now docker
}

select_docker_command() {
  if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
  elif command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
  else
    die "Docker 服务未正常启动。"
  fi
}

compose() {
  "${DOCKER[@]}" compose --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" "$@"
}

create_environment() {
  if [[ -f "${ENV_FILE}" ]]; then
    chmod 600 "${ENV_FILE}"
    return
  fi

  local host_ip public_origin admin_password http_port
  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  host_ip="${host_ip:-127.0.0.1}"
  http_port="${HTTP_PORT:-80}"
  if [[ -n "${PUBLIC_ORIGIN:-}" ]]; then
    public_origin="${PUBLIC_ORIGIN}"
  elif [[ "${http_port}" == "80" ]]; then
    public_origin="http://${host_ip}"
  else
    public_origin="http://${host_ip}:${http_port}"
  fi
  admin_password="${ADMIN_BOOTSTRAP_PASSWORD:-Audit!$(random_hex 12)}"

  umask 077
  cat >"${ENV_FILE}" <<EOF
PUBLIC_ORIGIN=${public_origin}
HTTP_PORT=${http_port}
TZ=${TZ:-Asia/Shanghai}

MYSQL_ROOT_PASSWORD=$(random_hex 32)
MYSQL_PASSWORD=$(random_hex 24)
AUTH_SECRET_KEY=$(random_hex 48)
CREDENTIAL_ENCRYPTION_KEY=$(random_hex 48)

ADMIN_BOOTSTRAP_USERNAME=${ADMIN_BOOTSTRAP_USERNAME:-admin}
ADMIN_BOOTSTRAP_EMAIL=${ADMIN_BOOTSTRAP_EMAIL:-admin@example.com}
ADMIN_BOOTSTRAP_PASSWORD=${admin_password}
ADMIN_BOOTSTRAP_RESET_PASSWORD=false

LLM_ENABLED=${LLM_ENABLED:-true}
DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY:-}
DEEPSEEK_BASE_URL=${DEEPSEEK_BASE_URL:-https://api.deepseek.com}
DEEPSEEK_MODEL=${DEEPSEEK_MODEL:-deepseek-chat}

UPLOAD_MAX_FILES=1000
UPLOAD_MAX_FILE_BYTES=209715200
UPLOAD_MAX_TOTAL_BYTES=209715200
EXTRACTION_MAX_FILES=10000
EXTRACTION_MAX_TOTAL_BYTES=524288000
USER_STORAGE_QUOTA_BYTES=2147483648

JAVA_AUDIT_SKILLS_ENABLED=${JAVA_AUDIT_SKILLS_ENABLED:-false}
JAVA_AUDIT_SKILLS_HOST_PATH=${JAVA_AUDIT_SKILLS_HOST_PATH:-./docker/empty-skills}
EOF
  chmod 600 "${ENV_FILE}"
  log "已生成 ${ENV_FILE}"
}

show_access_info() {
  local public_origin admin_username admin_password
  public_origin="$(grep '^PUBLIC_ORIGIN=' "${ENV_FILE}" | cut -d= -f2-)"
  admin_username="$(grep '^ADMIN_BOOTSTRAP_USERNAME=' "${ENV_FILE}" | cut -d= -f2-)"
  admin_password="$(grep '^ADMIN_BOOTSTRAP_PASSWORD=' "${ENV_FILE}" | cut -d= -f2-)"
  printf "\n"
  log "部署完成"
  printf "访问地址: %s\n" "${public_origin}"
  printf "API 文档: %s/docs\n" "${public_origin}"
  printf "管理员账号: %s\n" "${admin_username}"
  printf "管理员密码: %s\n" "${admin_password}"
  printf "配置文件: %s\n\n" "${ENV_FILE}"
}

deploy() {
  install_docker
  select_docker_command
  create_environment
  log "构建并启动 AuditPilot..."
  compose up -d --build --remove-orphans
  log "等待服务健康..."
  local attempt http_port
  http_port="$(grep '^HTTP_PORT=' "${ENV_FILE}" | cut -d= -f2-)"
  for attempt in {1..60}; do
    if compose ps --format json 2>/dev/null | grep -q '"Health":"healthy"'; then
      if curl -fsS "http://127.0.0.1:${http_port}/api/v1/health" >/dev/null 2>&1; then
        show_access_info
        compose ps
        return
      fi
    fi
    sleep 3
  done
  compose ps
  compose logs --tail=120 backend frontend
  die "服务健康检查超时，请查看上方日志。"
}

case "${ACTION}" in
  deploy|install|start)
    deploy
    ;;
  update)
    install_docker
    select_docker_command
    create_environment
    compose build --pull
    compose up -d --remove-orphans
    show_access_info
    ;;
  stop)
    select_docker_command
    create_environment
    compose stop
    ;;
  restart)
    select_docker_command
    create_environment
    compose restart
    ;;
  status)
    select_docker_command
    create_environment
    compose ps
    ;;
  logs)
    select_docker_command
    create_environment
    compose logs -f --tail=200
    ;;
  down)
    select_docker_command
    create_environment
    compose down
    ;;
  *)
    die "用法: ./deploy-linux.sh [deploy|update|stop|restart|status|logs|down]"
    ;;
esac
