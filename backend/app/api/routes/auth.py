from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import User
from backend.app.schemas.auth import (
    AuthResponse,
    HumanCheckChallengeResponse,
    HumanCheckVerifyRequest,
    HumanCheckVerifyResponse,
    LoginRequest,
    RegisterRequest,
    UserLLMConfigResponse,
    UserLLMConfigUpdateRequest,
    UserLLMModelDiscoverRequest,
    UserLLMModelDiscoverResponse,
    UserPublic,
)
from backend.app.services.auth_service import (
    authenticate_user,
    create_access_token,
    create_user,
    get_current_user,
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
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> AuthResponse:
    consume_human_check_proof(payload.human_check_proof)
    if username_or_email_exists(db, payload.username, payload.email):
        raise HTTPException(status_code=409, detail="Username or email already exists")

    try:
        user = create_user(db, payload.username, payload.email, payload.password)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username or email already exists") from exc

    return AuthResponse(access_token=create_access_token(user), user=UserPublic.model_validate(user))


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> AuthResponse:
    user = authenticate_user(db, payload.username_or_email, payload.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username/email or password")

    return AuthResponse(access_token=create_access_token(user), user=UserPublic.model_validate(user))


@router.get("/me", response_model=UserPublic)
def me(current_user: User = Depends(get_current_user)) -> UserPublic:
    return UserPublic.model_validate(current_user)


@router.get("/llm-config", response_model=UserLLMConfigResponse)
def get_llm_config(
    current_user: User = Depends(get_current_user),
) -> UserLLMConfigResponse:
    return UserLLMConfigResponse.model_validate(serialize_user_llm_config(current_user.llm_config))


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
    return UserLLMConfigResponse.model_validate(serialize_user_llm_config(config))


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
