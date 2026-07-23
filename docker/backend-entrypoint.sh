#!/usr/bin/env sh
set -eu

mkdir -p /app/backend/data
chown -R auditpilot:auditpilot /app/backend/data

echo "[AuditPilot] 等待数据库连接..."
python - <<'PY'
import os
import time

from sqlalchemy import create_engine, text

url = os.environ["DATABASE_URL"]
last_error = None
for attempt in range(1, 61):
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        engine.dispose()
        print("[AuditPilot] 数据库已就绪")
        break
    except Exception as exc:
        last_error = exc
        print(f"[AuditPilot] 数据库等待中 ({attempt}/60)")
        time.sleep(2)
else:
    raise SystemExit(f"数据库连接超时: {last_error}")
PY

echo "[AuditPilot] 执行数据库迁移..."
python -m alembic upgrade head

echo "[AuditPilot] 启动后端..."
exec gosu auditpilot uvicorn backend.app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 1 \
  --proxy-headers \
  --forwarded-allow-ips="*"
