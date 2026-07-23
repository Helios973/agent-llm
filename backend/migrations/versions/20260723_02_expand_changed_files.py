"""expand audit task changed-file storage

Revision ID: 20260723_02
Revises: 20260723_01
Create Date: 2026-07-23
"""
from __future__ import annotations

from alembic import op
from sqlalchemy import text


revision = "20260723_02"
down_revision = "20260723_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "mysql":
        bind.execute(text("ALTER TABLE audit_tasks MODIFY COLUMN changed_files_json LONGTEXT NULL"))


def downgrade() -> None:
    # Keep LONGTEXT to avoid truncating existing changed-file inventories.
    pass
