"""platform foundations excluding finding disposition

Revision ID: 20260723_01
Revises:
Create Date: 2026-07-23
"""
from __future__ import annotations

from alembic import op
from sqlalchemy import inspect, text

from backend.app.core.database import Base
from backend.app import models  # noqa: F401


revision = "20260723_01"
down_revision = None
branch_labels = None
depends_on = None


def _add_missing_columns(table: str, definitions: dict[str, str]) -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if table not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns(table)}
    for name, ddl in definitions.items():
        if name not in existing:
            bind.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    _add_missing_columns("users", {"monthly_token_limit": "INTEGER NOT NULL DEFAULT 1000000"})
    _add_missing_columns(
        "user_llm_configs",
        {"monthly_token_limit": "INTEGER NOT NULL DEFAULT 1000000"},
    )
    _add_missing_columns(
        "audit_tasks",
        {
            "baseline_task_id": "VARCHAR(36)",
            "changed_files_json": "LONGTEXT" if bind.dialect.name == "mysql" else "TEXT",
            "source_digest": "VARCHAR(64)",
            "retry_count": "INTEGER NOT NULL DEFAULT 0",
            "error_message": "TEXT",
            "queued_at": "DATETIME",
        },
    )


def downgrade() -> None:
    # The first revision may adopt an existing database. Preserve business data
    # instead of attempting a destructive table rebuild.
    pass
