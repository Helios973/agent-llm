from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models import User
from backend.app.schemas.auth import AuthResponse, LoginRequest, RegisterRequest, UserPublic
from backend.app.services.auth_service import (
    authenticate_user,
    create_access_token,
    create_user,
    get_current_user,
    username_or_email_exists,
)


router = APIRouter(prefix="/auth")


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> AuthResponse:
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
