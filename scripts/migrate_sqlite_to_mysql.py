from __future__ import annotations

import argparse
import os

from sqlalchemy import create_engine, func, inspect, select, text
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.database import Base
from backend.app.models import AuditTask, Finding, User


DEFAULT_SQLITE_URL = "sqlite:///./backend/data/auditpilot.db"


def build_session_factory(database_url: str) -> tuple[object, sessionmaker[Session]]:
    connect_args: dict[str, object] = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(database_url, future=True, connect_args=connect_args)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    return engine, factory


def ensure_source_auth_columns(engine: object) -> None:
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("users")}
    with engine.begin() as connection:
        if "password_hash" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)"))
        if "role" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'"))
        if "is_active" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1"))


def clone_row(instance: User | AuditTask | Finding) -> dict[str, object]:
    return {column.name: getattr(instance, column.name) for column in instance.__table__.columns}


def table_count(session: Session, model: type[User] | type[AuditTask] | type[Finding]) -> int:
    return int(session.scalar(select(func.count()).select_from(model)) or 0)


def migrate_table(source: Session, target: Session, model: type[User] | type[AuditTask] | type[Finding]) -> int:
    rows = source.scalars(select(model)).all()
    for row in rows:
        target.merge(model(**clone_row(row)))
    return len(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Copy AuditPilot data from SQLite into MySQL.")
    parser.add_argument("--sqlite-url", default=DEFAULT_SQLITE_URL, help="Source SQLite SQLAlchemy URL.")
    parser.add_argument(
        "--mysql-url",
        default=os.environ.get("DATABASE_URL", ""),
        help="Target MySQL SQLAlchemy URL. Defaults to DATABASE_URL from the environment.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    mysql_url = args.mysql_url.strip()
    if not mysql_url:
        raise SystemExit("Missing MySQL URL. Set DATABASE_URL or pass --mysql-url.")
    if not mysql_url.startswith("mysql"):
        raise SystemExit(f"Target must be a MySQL URL, got: {mysql_url!r}")

    source_engine, source_factory = build_session_factory(args.sqlite_url)
    target_engine, target_factory = build_session_factory(mysql_url)

    ensure_source_auth_columns(source_engine)
    Base.metadata.create_all(bind=target_engine)

    source = source_factory()
    target = target_factory()
    try:
        before = {
            "users": table_count(target, User),
            "audit_tasks": table_count(target, AuditTask),
            "findings": table_count(target, Finding),
        }

        migrated = {
            "users": migrate_table(source, target, User),
            "audit_tasks": migrate_table(source, target, AuditTask),
            "findings": migrate_table(source, target, Finding),
        }
        target.commit()

        after = {
            "users": table_count(target, User),
            "audit_tasks": table_count(target, AuditTask),
            "findings": table_count(target, Finding),
        }
    finally:
        source.close()
        target.close()

    print("Migration complete.")
    print(f"Target users: {before['users']} -> {after['users']} (merged {migrated['users']})")
    print(f"Target audit_tasks: {before['audit_tasks']} -> {after['audit_tasks']} (merged {migrated['audit_tasks']})")
    print(f"Target findings: {before['findings']} -> {after['findings']} (merged {migrated['findings']})")


if __name__ == "__main__":
    main()
