from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parents[2]


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
    auth_secret_key: str = "change-me-local-auth-secret"
    auth_token_ttl_seconds: int = 604800
    admin_bootstrap_username: str = "admin"
    admin_bootstrap_email: str = "admin@example.com"
    admin_bootstrap_password: str = "Admin123456!"
    admin_bootstrap_reset_password: bool = False
    database_url: str = "sqlite:///./backend/data/auditpilot.db"
    redis_url: str = "redis://127.0.0.1:6379/0"
    sql_echo: bool = False
    default_user_id: str = "00000000-0000-0000-0000-000000000001"
    report_history_limit: int = 200
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
