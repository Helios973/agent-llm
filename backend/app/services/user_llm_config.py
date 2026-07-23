from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models import UserLLMConfig
from backend.app.services.llm_providers import extract_model_ids, get_provider_adapter


@dataclass(frozen=True)
class LLMConnection:
    provider: str
    base_url: str
    model: str
    api_key: str


def _load_or_create_local_credential_secret() -> str:
    path = settings.local_credential_key_path
    try:
        if path.exists():
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                return existing

        path.parent.mkdir(parents=True, exist_ok=True)
        generated = secrets.token_urlsafe(48)
        try:
            with path.open("x", encoding="utf-8") as handle:
                handle.write(generated)
        except FileExistsError:
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return generated
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Credential key initialization failed: {exc.__class__.__name__}",
        ) from None


def _credential_secret() -> str:
    explicit = settings.resolved_explicit_credential_encryption_key
    if explicit:
        return explicit

    # Once an automatic local key exists it remains preferred across restarts,
    # even if AUTH_SECRET_KEY is configured later.
    path = settings.local_credential_key_path
    if path.exists():
        return _load_or_create_local_credential_secret()

    legacy_auth_secret = settings.resolved_auth_secret_key
    if legacy_auth_secret:
        return legacy_auth_secret
    return _load_or_create_local_credential_secret()


def _fernet() -> Fernet:
    secret = _credential_secret()
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def _normalize_base_url(base_url: str) -> str:
    normalized = base_url.strip().rstrip("/")
    suffix = "/chat/completions"
    if normalized.endswith(suffix):
        normalized = normalized[: -len(suffix)]
    return normalized.rstrip("/")


def serialize_user_llm_config(config: UserLLMConfig | None) -> dict[str, object]:
    if config is None:
        return {
            "provider": None,
            "base_url": None,
            "model": None,
            "api_key_configured": False,
            "updated_at": None,
            "monthly_token_limit": settings.llm_default_monthly_token_limit,
            "monthly_tokens_used": 0,
        }
    return {
        "provider": config.provider,
        "base_url": config.base_url,
        "model": config.model,
        "api_key_configured": bool(config.api_key_encrypted),
        "updated_at": config.updated_at,
        "monthly_token_limit": config.monthly_token_limit,
        "monthly_tokens_used": 0,
    }


def update_user_llm_config(
    db: Session,
    *,
    user_id: str,
    provider: str,
    base_url: str,
    model: str,
    api_key: str | None,
    clear_api_key: bool,
) -> UserLLMConfig:
    config = db.get(UserLLMConfig, user_id)
    if config is None:
        config = UserLLMConfig(
            user_id=user_id,
            provider=provider,
            base_url=_normalize_base_url(base_url),
            model=model,
            monthly_token_limit=settings.llm_default_monthly_token_limit,
        )
        db.add(config)
    else:
        config.provider = provider
        config.base_url = _normalize_base_url(base_url)
        config.model = model

    if clear_api_key:
        config.api_key_encrypted = None
    elif api_key is not None:
        config.api_key_encrypted = _fernet().encrypt(api_key.encode("utf-8")).decode("ascii")

    db.commit()
    db.refresh(config)
    return config


def get_user_llm_connection(db: Session, user_id: str) -> LLMConnection | None:
    config = db.get(UserLLMConfig, user_id)
    if config is None or (not config.api_key_encrypted and config.provider != "ollama"):
        return None
    api_key = ""
    if config.api_key_encrypted:
        try:
            api_key = _fernet().decrypt(config.api_key_encrypted.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Stored API key cannot be decrypted; update the provider configuration",
            ) from None
    return LLMConnection(
        provider=config.provider,
        base_url=config.base_url,
        model=config.model,
        api_key=api_key,
    )


async def discover_user_llm_models(
    db: Session,
    *,
    user_id: str,
    provider: str,
    base_url: str,
    api_key: str | None,
) -> tuple[str, list[str]]:
    normalized_base_url = _normalize_base_url(base_url)
    effective_api_key = api_key
    if effective_api_key is None:
        stored = get_user_llm_connection(db, user_id)
        effective_api_key = stored.api_key if stored is not None else None
    if not effective_api_key and provider != "ollama":
        raise HTTPException(status_code=400, detail="Enter an API key or save one before discovering models")

    adapter = get_provider_adapter(provider)

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(settings.llm_timeout_seconds), follow_redirects=True) as client:
            response = await client.get(
                adapter.models_url(normalized_base_url),
                headers={**adapter.auth_headers(effective_api_key or ""), "Accept": "application/json"},
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Model discovery request failed: {exc.__class__.__name__}") from None

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"API platform returned HTTP {response.status_code} during model discovery",
        )
    try:
        models = extract_model_ids(response.json())
    except ValueError:
        raise HTTPException(status_code=502, detail="API platform returned a non-JSON model list") from None
    if not models:
        raise HTTPException(status_code=502, detail="API platform returned no model identifiers")
    return normalized_base_url, models
