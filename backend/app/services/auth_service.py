from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Depends, Header, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.models import AdminAuditLog, AuthSession, User


PASSWORD_SCHEME = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 210_000
TOKEN_PREFIX = "v1"
_fallback_auth_secret_key = secrets.token_bytes(32)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _secret_key() -> bytes:
    configured = settings.resolved_auth_secret_key
    if configured is not None:
        return configured.encode("utf-8")
    path = settings.local_auth_key_path
    try:
        if path.exists():
            stored = path.read_text(encoding="utf-8").strip()
            if stored:
                return stored.encode("utf-8")
        path.parent.mkdir(parents=True, exist_ok=True)
        generated = secrets.token_urlsafe(48)
        try:
            with path.open("x", encoding="utf-8") as handle:
                handle.write(generated)
        except FileExistsError:
            stored = path.read_text(encoding="utf-8").strip()
            if stored:
                return stored.encode("utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return generated.encode("utf-8")
    except OSError:
        return _fallback_auth_secret_key


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"{PASSWORD_SCHEME}${PASSWORD_ITERATIONS}${_b64encode(salt)}${_b64encode(digest)}"


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False

    try:
        scheme, iterations, encoded_salt, encoded_digest = password_hash.split("$", 3)
        if scheme != PASSWORD_SCHEME:
            return False
        salt = _b64decode(encoded_salt)
        expected = _b64decode(encoded_digest)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    except (ValueError, TypeError):
        return False

    return hmac.compare_digest(actual, expected)


def create_access_token(
    user: User,
    db: Session | None = None,
    *,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> str:
    now = int(time.time())
    session_id = str(uuid4())
    payload = {
        "sub": user.id,
        "sid": session_id,
        "iat": now,
        "exp": now + settings.auth_token_ttl_seconds,
    }
    encoded_payload = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(_secret_key(), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    if db is not None:
        db.add(
            AuthSession(
                id=session_id,
                user_id=user.id,
                user_agent=(user_agent or "")[:512] or None,
                ip_address=(ip_address or "")[:64] or None,
                expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.auth_token_ttl_seconds),
            )
        )
        db.commit()
    return f"{TOKEN_PREFIX}.{encoded_payload}.{_b64encode(signature)}"


def decode_access_token(token: str | None) -> dict[str, object] | None:
    if not token:
        return None

    try:
        prefix, encoded_payload, encoded_signature = token.split(".", 2)
        if prefix != TOKEN_PREFIX:
            return None

        expected_signature = hmac.new(_secret_key(), encoded_payload.encode("ascii"), hashlib.sha256).digest()
        actual_signature = _b64decode(encoded_signature)
        if not hmac.compare_digest(actual_signature, expected_signature):
            return None

        payload = json.loads(_b64decode(encoded_payload))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        subject = payload.get("sub")
        return payload if isinstance(subject, str) else None
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def verify_access_token(token: str | None) -> str | None:
    payload = decode_access_token(token)
    subject = payload.get("sub") if payload else None
    return subject if isinstance(subject, str) else None


def extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def get_user_by_identifier(db: Session, identifier: str) -> User | None:
    normalized = identifier.strip().lower()
    return db.execute(
        select(User).where(
            or_(
                func.lower(User.username) == normalized,
                func.lower(User.email) == normalized,
            )
        )
    ).scalar_one_or_none()


def username_or_email_exists(db: Session, username: str, email: str) -> bool:
    normalized_username = username.strip().lower()
    normalized_email = email.strip().lower()
    return (
        db.execute(
            select(User.id).where(
                or_(
                    func.lower(User.username) == normalized_username,
                    func.lower(User.email) == normalized_email,
                )
            )
        ).first()
        is not None
    )


def create_user(db: Session, username: str, email: str, password: str, role: str = "user") -> User:
    user = User(
        id=str(uuid4()),
        username=username.strip(),
        email=email.strip().lower(),
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, identifier: str, password: str) -> User | None:
    user = get_user_by_identifier(db, identifier)
    if user is None or not verify_password(password, user.password_hash):
        return None
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")
    return user


def get_user_from_token(db: Session, token: str | None) -> User | None:
    payload = decode_access_token(token)
    user_id = payload.get("sub") if payload else None
    if user_id is None:
        return None
    session_id = payload.get("sid") if payload else None
    if isinstance(session_id, str):
        session = db.get(AuthSession, session_id)
        if session is not None:
            if session.revoked_at is not None or session.expires_at.timestamp() < time.time():
                return None
            if (datetime.now(timezone.utc) - session.last_seen_at.replace(tzinfo=session.last_seen_at.tzinfo or timezone.utc)).total_seconds() > 60:
                session.last_seen_at = datetime.now(timezone.utc)
                db.commit()
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        return None
    return user


def get_current_user(
    access_token: str | None = Query(default=None),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    token = access_token or extract_bearer_token(authorization)
    user = get_user_from_token(db, token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user


def can_access_user_content(current_user: User, owner_id: str) -> bool:
    return current_user.role == "admin" or current_user.id == owner_id


def token_session_id(token: str | None) -> str | None:
    payload = decode_access_token(token)
    session_id = payload.get("sid") if payload else None
    return session_id if isinstance(session_id, str) else None


def revoke_session(db: Session, session_id: str, user_id: str | None = None) -> bool:
    session = db.get(AuthSession, session_id)
    if session is None or (user_id is not None and session.user_id != user_id):
        return False
    if session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc)
        db.commit()
    return True


def record_admin_action(
    db: Session,
    *,
    admin_user_id: str,
    action: str,
    target_type: str,
    target_id: str | None,
    details: dict[str, object] | None = None,
) -> None:
    db.add(
        AdminAuditLog(
            id=str(uuid4()),
            admin_user_id=admin_user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details_json=json.dumps(details or {}, ensure_ascii=False),
        )
    )
    db.commit()
