from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.app.core.config import settings


class Base(DeclarativeBase):
    pass


connect_args: dict[str, object] = {}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.database_url,
    echo=settings.sql_echo,
    future=True,
    connect_args=connect_args,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from backend.app.models import AuditTask, Finding, User  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_auth_columns()
    _ensure_bootstrap_admin()


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


def _ensure_bootstrap_admin() -> None:
    username = settings.admin_bootstrap_username.strip()
    email = settings.admin_bootstrap_email.strip().lower()
    password = settings.admin_bootstrap_password
    if not username or not email or not password:
        return

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

