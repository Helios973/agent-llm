from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.app.core.config import settings


class Base(DeclarativeBase):
    pass


connect_args: dict[str, object] = {}
engine_kwargs: dict[str, object] = {
    "echo": settings.sql_echo,
    "future": True,
    "connect_args": connect_args,
}

if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False
elif settings.database_url.startswith("mysql"):
    # Avoid stale pooled MySQL connections causing intermittent 500s.
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_recycle"] = 1800

engine = create_engine(settings.database_url, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from backend.app.models import AdminAuditLog, AuditTask, AuthSession, Finding, LLMUsage, User, UserLLMConfig  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_auth_columns()
    _ensure_runtime_columns()
    _ensure_bootstrap_admin()


def _ensure_runtime_columns() -> None:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    statements: list[str] = []
    if "audit_tasks" in tables:
        inspected_task_columns = inspector.get_columns("audit_tasks")
        task_columns = {column["name"] for column in inspected_task_columns}
        additions = {
            "baseline_task_id": "VARCHAR(36)",
            "changed_files_json": "LONGTEXT" if engine.dialect.name == "mysql" else "TEXT",
            "source_digest": "VARCHAR(64)",
            "retry_count": "INTEGER NOT NULL DEFAULT 0",
            "error_message": "TEXT",
            "queued_at": "DATETIME",
        }
        statements.extend(
            f"ALTER TABLE audit_tasks ADD COLUMN {name} {definition}"
            for name, definition in additions.items()
            if name not in task_columns
        )
        changed_files_column = next(
            (column for column in inspected_task_columns if column["name"] == "changed_files_json"),
            None,
        )
        if (
            engine.dialect.name == "mysql"
            and changed_files_column is not None
            and "LONGTEXT" not in str(changed_files_column["type"]).upper()
        ):
            statements.append(
                "ALTER TABLE audit_tasks MODIFY COLUMN changed_files_json LONGTEXT NULL"
            )
    if "user_llm_configs" in tables:
        config_columns = {column["name"] for column in inspector.get_columns("user_llm_configs")}
        if "monthly_token_limit" not in config_columns:
            statements.append(
                "ALTER TABLE user_llm_configs ADD COLUMN monthly_token_limit INTEGER NOT NULL DEFAULT 1000000"
            )
    if statements:
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))


def _ensure_auth_columns() -> None:
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
        if "monthly_token_limit" not in columns:
            connection.execute(
                text("ALTER TABLE users ADD COLUMN monthly_token_limit INTEGER NOT NULL DEFAULT 1000000")
            )


def _ensure_bootstrap_admin() -> None:
    credentials = settings.bootstrap_admin_credentials
    if credentials is None:
        return
    username, email, password = credentials

    from backend.app.models import User
    from backend.app.services.auth_service import get_user_by_identifier, hash_password

    db = SessionLocal()
    try:
        user = get_user_by_identifier(db, username) or get_user_by_identifier(db, email)
        if user is None:
            import uuid

            user = User(
                id=str(uuid.uuid4()),
                username=username,
                email=email,
                password_hash=hash_password(password),
                role="admin",
                is_active=True,
            )
            db.add(user)
        else:
            user.role = "admin"
            user.is_active = True
            if settings.admin_bootstrap_reset_password or not user.password_hash:
                user.password_hash = hash_password(password)
        db.commit()
    finally:
        db.close()

