from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    human_check_proof: str = Field(min_length=1, max_length=2048)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Username is required")
        if any(character.isspace() for character in normalized):
            raise ValueError("Username cannot contain whitespace")
        return normalized

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized or "." not in normalized.rsplit("@", 1)[-1]:
            raise ValueError("A valid email address is required")
        return normalized


class LoginRequest(BaseModel):
    username_or_email: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


class HumanCheckChallengeResponse(BaseModel):
    challenge_token: str
    expires_at: int
    min_completion_ms: int


class HumanCheckVerifyRequest(BaseModel):
    challenge_token: str = Field(min_length=1, max_length=2048)


class HumanCheckVerifyResponse(BaseModel):
    proof_token: str
    expires_at: int


class UserLLMConfigResponse(BaseModel):
    provider: str | None = None
    base_url: str | None = None
    model: str | None = None
    api_key_configured: bool = False
    updated_at: datetime | None = None


class UserLLMConfigUpdateRequest(BaseModel):
    provider: str = Field(min_length=2, max_length=40)
    base_url: str = Field(min_length=8, max_length=2048)
    model: str = Field(min_length=1, max_length=255)
    api_key: str | None = Field(default=None, max_length=4096)
    clear_api_key: bool = False

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"openai", "deepseek", "openai-compatible"}:
            raise ValueError("Provider must be openai, deepseek, or openai-compatible")
        return normalized

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        from urllib.parse import urlparse

        normalized = value.strip().rstrip("/")
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("Base URL must be an http(s) API address without embedded credentials")
        return normalized

    @field_validator("model")
    @classmethod
    def validate_model(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Model is required")
        return normalized

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("API key cannot be empty; use clear_api_key to remove it")
        return normalized

    @model_validator(mode="after")
    def validate_key_operation(self) -> "UserLLMConfigUpdateRequest":
        if self.api_key is not None and self.clear_api_key:
            raise ValueError("Set an API key or clear it, not both")
        return self


class UserLLMModelDiscoverRequest(BaseModel):
    provider: str = Field(min_length=2, max_length=40)
    base_url: str = Field(min_length=8, max_length=2048)
    api_key: str | None = Field(default=None, max_length=4096)

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"openai", "deepseek", "openai-compatible"}:
            raise ValueError("Provider must be openai, deepseek, or openai-compatible")
        return normalized

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        from urllib.parse import urlparse

        normalized = value.strip().rstrip("/")
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("Base URL must be an http(s) API address without embedded credentials")
        return normalized

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("API key cannot be empty")
        return normalized


class UserLLMModelDiscoverResponse(BaseModel):
    provider: str
    base_url: str
    models: list[str]


class AdminUserSummary(UserPublic):
    task_count: int = 0


class AdminUserUpdateRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value not in {"user", "admin"}:
            raise ValueError("Role must be user or admin")
        return value


class AdminTaskSummary(BaseModel):
    id: str
    user_id: str
    task_name: str
    status: str
    upload_name: str | None = None
    language: str | None = None
    framework: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    finding_count: int = 0
