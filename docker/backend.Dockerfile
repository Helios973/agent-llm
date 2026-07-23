FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git gosu graphviz \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 auditpilot \
    && useradd --uid 10001 --gid auditpilot --create-home --shell /usr/sbin/nologin auditpilot

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/requirements.txt

COPY alembic.ini /app/alembic.ini
COPY backend /app/backend
COPY examples /app/examples
COPY docker/backend-entrypoint.sh /usr/local/bin/auditpilot-entrypoint

RUN chmod +x /usr/local/bin/auditpilot-entrypoint \
    && mkdir -p /app/backend/data /opt/auditpilot/skills \
    && chown -R auditpilot:auditpilot /app/backend/data /opt/auditpilot/skills

EXPOSE 8000

ENTRYPOINT ["auditpilot-entrypoint"]
