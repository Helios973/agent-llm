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
    monthly_token_limit: int = 0
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
    monthly_token_limit: int = 0
    monthly_tokens_used: int = 0


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
        if normalized not in {"openai", "deepseek", "openai-compatible", "ollama", "azure-openai"}:
            raise ValueError("Unsupported provider")
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
        if normalized not in {"openai", "deepseek", "openai-compatible", "ollama", "azure-openai"}:
            raise ValueError("Unsupported provider")
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


class LLMUsageResponse(BaseModel):
    monthly_token_limit: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    request_count: int


class LLMUsageHeatmapDay(BaseModel):
    date: str
    total_tokens: int
    request_count: int
    level: int = Field(ge=0, le=4)


class LLMUsageModelStat(BaseModel):
    provider: str
    model: str
    request_count: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    percentage: float


class LLMUsageAnalyticsResponse(BaseModel):
    period: str
    sessions: int
    messages: int
    total_tokens: int
    active_days: int
    current_streak: int
    longest_streak: int
    peak_hour: int | None = None
    favorite_model: str | None = None
    heatmap: list[LLMUsageHeatmapDay] = Field(default_factory=list)
    models: list[LLMUsageModelStat] = Field(default_factory=list)


class AuthSessionResponse(BaseModel):
    id: str
    user_agent: str | None = None
    ip_address: str | None = None
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    current: bool = False


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


class AdminQuotaUpdateRequest(BaseModel):
    monthly_token_limit: int = Field(ge=0, le=1_000_000_000)


class AdminAuditLogResponse(BaseModel):
    id: str
    admin_user_id: str
    action: str
    target_type: str
    target_id: str | None = None
    details: dict[str, object] = Field(default_factory=dict)
    created_at: datetime


class AdminAuditLogClearRequest(BaseModel):
    ids: list[str] = Field(default_factory=list, max_length=500)
    clear_all: bool = False

    @model_validator(mode="after")
    def validate_selection(self) -> "AdminAuditLogClearRequest":
        if not self.clear_all and not self.ids:
            raise ValueError("Select at least one log entry or clear all logs")
        return self


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
