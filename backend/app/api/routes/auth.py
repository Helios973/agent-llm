from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import User
from backend.app.schemas.auth import (
    AuthResponse,
    HumanCheckChallengeResponse,
    HumanCheckVerifyRequest,
    HumanCheckVerifyResponse,
    AuthSessionResponse,
    LoginRequest,
    LLMUsageAnalyticsResponse,
    LLMUsageResponse,
    RegisterRequest,
    UserLLMConfigResponse,
    UserLLMConfigUpdateRequest,
    UserLLMModelDiscoverRequest,
    UserLLMModelDiscoverResponse,
    UserPublic,
)
from backend.app.models import AuthSession
from backend.app.services.auth_service import (
    authenticate_user,
    create_access_token,
    create_user,
    get_current_user,
    extract_bearer_token,
    revoke_session,
    token_session_id,
    username_or_email_exists,
)
from backend.app.services.human_check import (
    consume_human_check_proof,
    issue_human_check_challenge,
    verify_human_check_challenge,
)
from backend.app.services.user_llm_config import (
    discover_user_llm_models,
    serialize_user_llm_config,
    update_user_llm_config,
)
from backend.app.services.llm_usage import usage_analytics, usage_summary


router = APIRouter(prefix="/auth")


@router.post("/human-check/challenge", response_model=HumanCheckChallengeResponse)
def create_human_check_challenge() -> HumanCheckChallengeResponse:
    challenge = issue_human_check_challenge()
    return HumanCheckChallengeResponse(
        challenge_token=challenge.challenge_token,
        expires_at=challenge.expires_at,
        min_completion_ms=challenge.min_completion_ms,
    )


@router.post("/human-check/verify", response_model=HumanCheckVerifyResponse)
def verify_human_check(payload: HumanCheckVerifyRequest) -> HumanCheckVerifyResponse:
    proof = verify_human_check_challenge(payload.challenge_token)
    return HumanCheckVerifyResponse(proof_token=proof.proof_token, expires_at=proof.expires_at)


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    request: Request = None,
    db: Session = Depends(get_db),
) -> AuthResponse:
    consume_human_check_proof(payload.human_check_proof)
    if username_or_email_exists(db, payload.username, payload.email):
        raise HTTPException(status_code=409, detail="Username or email already exists")

    try:
        user = create_user(db, payload.username, payload.email, payload.password)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username or email already exists") from exc

    token = create_access_token(
        user,
        db,
        user_agent=request.headers.get("user-agent") if request else None,
        ip_address=request.client.host if request and request.client else None,
    )
    return AuthResponse(access_token=token, user=UserPublic.model_validate(user))


@router.post("/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    request: Request = None,
    db: Session = Depends(get_db),
) -> AuthResponse:
    user = authenticate_user(db, payload.username_or_email, payload.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username/email or password")

    token = create_access_token(
        user,
        db,
        user_agent=request.headers.get("user-agent") if request else None,
        ip_address=request.client.host if request and request.client else None,
    )
    return AuthResponse(access_token=token, user=UserPublic.model_validate(user))


@router.get("/me", response_model=UserPublic)
def me(current_user: User = Depends(get_current_user)) -> UserPublic:
    return UserPublic.model_validate(current_user)


@router.get("/sessions", response_model=list[AuthSessionResponse])
def list_sessions(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[AuthSessionResponse]:
    current_session_id = token_session_id(extract_bearer_token(authorization))
    sessions = db.execute(
        select(AuthSession)
        .where(AuthSession.user_id == current_user.id, AuthSession.revoked_at.is_(None))
        .order_by(AuthSession.last_seen_at.desc())
    ).scalars().all()
    return [
        AuthSessionResponse(
            id=item.id,
            user_agent=item.user_agent,
            ip_address=item.ip_address,
            created_at=item.created_at,
            last_seen_at=item.last_seen_at,
            expires_at=item.expires_at,
            current=item.id == current_session_id,
        )
        for item in sessions
    ]


@router.delete("/sessions/{session_id}", status_code=204)
def delete_session(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not revoke_session(db, session_id, current_user.id):
        raise HTTPException(status_code=404, detail="Session not found")
    return Response(status_code=204)


@router.post("/logout", status_code=204)
def logout(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    session_id = token_session_id(extract_bearer_token(authorization))
    if session_id:
        revoke_session(db, session_id, current_user.id)
    return Response(status_code=204)


@router.get("/llm-config", response_model=UserLLMConfigResponse)
def get_llm_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserLLMConfigResponse:
    payload = serialize_user_llm_config(current_user.llm_config)
    usage = usage_summary(db, current_user.id)
    payload["monthly_token_limit"] = usage["monthly_token_limit"]
    payload["monthly_tokens_used"] = usage["total_tokens"]
    return UserLLMConfigResponse.model_validate(payload)


@router.put("/llm-config", response_model=UserLLMConfigResponse)
def save_llm_config(
    payload: UserLLMConfigUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserLLMConfigResponse:
    config = update_user_llm_config(
        db,
        user_id=current_user.id,
        provider=payload.provider,
        base_url=payload.base_url,
        model=payload.model,
        api_key=payload.api_key,
        clear_api_key=payload.clear_api_key,
    )
    response = serialize_user_llm_config(config)
    usage = usage_summary(db, current_user.id)
    response["monthly_token_limit"] = usage["monthly_token_limit"]
    response["monthly_tokens_used"] = usage["total_tokens"]
    return UserLLMConfigResponse.model_validate(response)


@router.get("/llm-usage", response_model=LLMUsageResponse)
def get_llm_usage(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LLMUsageResponse:
    return LLMUsageResponse.model_validate(usage_summary(db, current_user.id))


@router.get("/llm-usage/analytics", response_model=LLMUsageAnalyticsResponse)
def get_llm_usage_analytics(
    period: str = Query(default="all", pattern="^(all|30d|7d)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> LLMUsageAnalyticsResponse:
    return LLMUsageAnalyticsResponse.model_validate(usage_analytics(db, current_user.id, period))


@router.post("/llm-models/discover", response_model=UserLLMModelDiscoverResponse)
async def discover_llm_models(
    payload: UserLLMModelDiscoverRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserLLMModelDiscoverResponse:
    base_url, models = await discover_user_llm_models(
        db,
        user_id=current_user.id,
        provider=payload.provider,
        base_url=payload.base_url,
        api_key=payload.api_key,
    )
    return UserLLMModelDiscoverResponse(provider=payload.provider, base_url=base_url, models=models)
