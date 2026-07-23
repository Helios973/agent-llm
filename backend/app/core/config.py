from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parents[2]
INSECURE_AUTH_SECRET_KEYS = frozenset({"change-me-local-auth-secret"})
INSECURE_BOOTSTRAP_PASSWORDS = frozenset({"Admin123456!"})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "AuditPilot Local"
    api_v1_prefix: str = "/api/v1"
    backend_scheme: str = "http"
    backend_host: str = "127.0.0.1"
    backend_port: int = 8000
    backend_public_url: str | None = None
    frontend_scheme: str = "http"
    frontend_host: str = "127.0.0.1"
    frontend_port: int = 3000
    frontend_public_url: str | None = None
    frontend_api_base_url: str | None = None
    auth_secret_key: str | None = None
    credential_encryption_key: str | None = None
    auth_token_ttl_seconds: int = 604800
    admin_bootstrap_username: str | None = None
    admin_bootstrap_email: str | None = None
    admin_bootstrap_password: str | None = None
    admin_bootstrap_reset_password: bool = False
    human_check_challenge_ttl_seconds: int = 300
    human_check_proof_ttl_seconds: int = 300
    human_check_min_completion_ms: int = 1200
    database_url: str = "sqlite:///./backend/data/auditpilot.db"
    redis_url: str = "redis://127.0.0.1:6379/0"
    sql_echo: bool = False
    default_user_id: str = "00000000-0000-0000-0000-000000000001"
    report_history_limit: int = 200
    upload_max_files: int = 1000
    upload_max_file_bytes: int = 200 * 1024 * 1024
    upload_max_total_bytes: int = 200 * 1024 * 1024
    extraction_max_files: int = 10000
    extraction_max_total_bytes: int = 500 * 1024 * 1024
    extraction_max_ratio: float = 200.0
    user_storage_quota_bytes: int = 2 * 1024 * 1024 * 1024
    llm_enabled: bool = True
    deepseek_api_key: str | None = None
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-v4-flash"
    deepseek_reasoning_effort: str = "high"
    deepseek_thinking_enabled: bool = True
    llm_timeout_seconds: int = 60
    llm_max_output_tokens: int = 4096
    llm_max_review_files: int = 6
    llm_max_file_chars: int = 6000
    llm_max_findings: int = 8
    llm_default_monthly_token_limit: int = 1_000_000
    llm_context_index_max_files: int = 160
    llm_context_reference_limit: int = 3
    java_audit_skills_enabled: bool = True
    java_audit_skills_root: Path | None = Field(default_factory=lambda: Path.home() / ".codex" / "skills")
    java_llm_full_file_context: bool = True
    java_llm_max_review_files: int = 4
    java_heuristic_requires_corroboration: bool = True
    java_corroboration_line_radius: int = 8
    cors_origins: list[str] = Field(default_factory=list)
    storage_root: Path = BACKEND_DIR / "data"

    @property
    def resolved_frontend_public_url(self) -> str:
        if self.frontend_public_url:
            return self.frontend_public_url.rstrip("/")
        return f"{self.frontend_scheme}://{self.frontend_host}:{self.frontend_port}"

    @property
    def resolved_auth_secret_key(self) -> str | None:
        candidate = (self.auth_secret_key or "").strip()
        if not candidate or candidate in INSECURE_AUTH_SECRET_KEYS:
            return None
        return candidate

    @property
    def resolved_credential_encryption_key(self) -> str | None:
        """Return the stable secret used to encrypt per-user provider API keys."""
        candidate = (self.credential_encryption_key or self.auth_secret_key or "").strip()
        if not candidate or candidate in INSECURE_AUTH_SECRET_KEYS:
            return None
        return candidate

    @property
    def resolved_explicit_credential_encryption_key(self) -> str | None:
        candidate = (self.credential_encryption_key or "").strip()
        if not candidate or candidate in INSECURE_AUTH_SECRET_KEYS:
            return None
        return candidate

    @property
    def local_credential_key_path(self) -> Path:
        return self.storage_root / ".credential_encryption_key"

    @property
    def local_auth_key_path(self) -> Path:
        return self.storage_root / ".auth_secret_key"

    @property
    def bootstrap_admin_credentials(self) -> tuple[str, str, str] | None:
        username = (self.admin_bootstrap_username or "").strip()
        email = (self.admin_bootstrap_email or "").strip().lower()
        password = self.admin_bootstrap_password or ""
        if not username or not email or not password:
            return None
        if password in INSECURE_BOOTSTRAP_PASSWORDS:
            return None
        return username, email, password

    @property
    def resolved_cors_origins(self) -> list[str]:
        if self.cors_origins:
            return self.cors_origins

        origins = [self.resolved_frontend_public_url]
        if self.frontend_host == "127.0.0.1":
            origins.append(f"{self.frontend_scheme}://localhost:{self.frontend_port}")
        return origins

    @property
    def upload_root(self) -> Path:
        return self.storage_root / "uploads"

    @property
    def project_root(self) -> Path:
        return self.storage_root / "projects"

    @property
    def report_root(self) -> Path:
        return self.storage_root / "reports"

    @property
    def vulnerability_library_root(self) -> Path:
        return self.storage_root / "vulnerability_library"

    @property
    def default_vulnerability_library_path(self) -> Path:
        return self.vulnerability_library_root / "default.json"

    @property
    def custom_vulnerability_library_root(self) -> Path:
        return self.vulnerability_library_root / "custom"

    @property
    def template_root(self) -> Path:
        return BACKEND_DIR / "app" / "templates"

    def ensure_directories(self) -> None:
        for path in (
            self.storage_root,
            self.upload_root,
            self.project_root,
            self.report_root,
            self.vulnerability_library_root,
            self.custom_vulnerability_library_root,
            self.template_root,
        ):
            path.mkdir(parents=True, exist_ok=True)


settings = Settings()
