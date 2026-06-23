from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass

from fastapi import HTTPException, status

from backend.app.core.config import settings


CHALLENGE_TOKEN_PREFIX = "hc1"
PROOF_TOKEN_PREFIX = "hp1"
INVALID_DETAIL = "Human verification expired or invalid"
USED_DETAIL = "Human verification has already been used"
TOO_FAST_DETAIL = "Human verification completed too quickly"

_fallback_human_check_secret = secrets.token_bytes(32)
_used_state_lock = threading.Lock()
_used_challenge_ids: dict[str, int] = {}
_used_proof_ids: dict[str, int] = {}


@dataclass(frozen=True)
class HumanCheckChallenge:
    challenge_token: str
    expires_at: int
    min_completion_ms: int


@dataclass(frozen=True)
class HumanCheckProof:
    proof_token: str
    expires_at: int


def _secret_key() -> bytes:
    configured = settings.resolved_auth_secret_key
    if configured is not None:
        return configured.encode("utf-8")
    return _fallback_human_check_secret


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _now_seconds() -> int:
    return int(time.time())


def _now_milliseconds() -> int:
    return int(time.time() * 1000)


def _encode_token(prefix: str, payload: dict[str, object]) -> str:
    encoded_payload = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature_input = f"{prefix}.{encoded_payload}".encode("ascii")
    signature = hmac.new(_secret_key(), signature_input, hashlib.sha256).digest()
    return f"{prefix}.{encoded_payload}.{_b64encode(signature)}"


def _decode_token(token: str, *, expected_prefix: str) -> dict[str, object]:
    try:
        prefix, encoded_payload, encoded_signature = token.split(".", 2)
        if prefix != expected_prefix:
            raise ValueError("Unexpected token prefix")

        expected_signature = hmac.new(
            _secret_key(),
            f"{prefix}.{encoded_payload}".encode("ascii"),
            hashlib.sha256,
        ).digest()
        actual_signature = _b64decode(encoded_signature)
        if not hmac.compare_digest(actual_signature, expected_signature):
            raise ValueError("Signature mismatch")

        payload = json.loads(_b64decode(encoded_payload))
        if int(payload.get("exp", 0)) < _now_seconds():
            raise ValueError("Expired token")
        return payload
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_DETAIL) from exc


def _purge_expired(store: dict[str, int]) -> None:
    now = _now_seconds()
    expired_keys = [key for key, expires_at in store.items() if expires_at < now]
    for key in expired_keys:
        store.pop(key, None)


def _consume_once(store: dict[str, int], token_id: str, expires_at: int) -> None:
    with _used_state_lock:
        _purge_expired(store)
        if token_id in store:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=USED_DETAIL)
        store[token_id] = expires_at


def issue_human_check_challenge() -> HumanCheckChallenge:
    issued_at = _now_seconds()
    expires_at = issued_at + settings.human_check_challenge_ttl_seconds
    payload = {
        "typ": "human-check-challenge",
        "jti": secrets.token_urlsafe(18),
        "iat": issued_at,
        "exp": expires_at,
        "min_ms": settings.human_check_min_completion_ms,
    }
    return HumanCheckChallenge(
        challenge_token=_encode_token(CHALLENGE_TOKEN_PREFIX, payload),
        expires_at=expires_at,
        min_completion_ms=settings.human_check_min_completion_ms,
    )


def verify_human_check_challenge(challenge_token: str) -> HumanCheckProof:
    payload = _decode_token(challenge_token, expected_prefix=CHALLENGE_TOKEN_PREFIX)
    if payload.get("typ") != "human-check-challenge":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_DETAIL)

    challenge_id = str(payload.get("jti") or "").strip()
    if not challenge_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_DETAIL)

    issued_at = int(payload.get("iat", 0))
    min_completion_ms = int(payload.get("min_ms", settings.human_check_min_completion_ms))
    if (_now_milliseconds() - (issued_at * 1000)) < min_completion_ms:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=TOO_FAST_DETAIL)

    challenge_expires_at = int(payload.get("exp", 0))
    _consume_once(_used_challenge_ids, challenge_id, challenge_expires_at)

    proof_issued_at = _now_seconds()
    proof_expires_at = proof_issued_at + settings.human_check_proof_ttl_seconds
    proof_payload = {
        "typ": "human-check-proof",
        "jti": secrets.token_urlsafe(18),
        "challenge_jti": challenge_id,
        "iat": proof_issued_at,
        "exp": proof_expires_at,
    }
    return HumanCheckProof(
        proof_token=_encode_token(PROOF_TOKEN_PREFIX, proof_payload),
        expires_at=proof_expires_at,
    )


def consume_human_check_proof(proof_token: str) -> None:
    payload = _decode_token(proof_token, expected_prefix=PROOF_TOKEN_PREFIX)
    if payload.get("typ") != "human-check-proof":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_DETAIL)

    proof_id = str(payload.get("jti") or "").strip()
    if not proof_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_DETAIL)

    proof_expires_at = int(payload.get("exp", 0))
    _consume_once(_used_proof_ids, proof_id, proof_expires_at)


def reset_human_check_state() -> None:
    with _used_state_lock:
        _used_challenge_ids.clear()
        _used_proof_ids.clear()
