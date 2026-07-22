"""Integration check for isolated user LLM configuration and admin task stopping."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["DATABASE_URL"] = f"sqlite:///./tmp/user-llm-stop-{uuid4().hex}.db"
os.environ["AUTH_SECRET_KEY"] = "test-auth-secret-for-user-config"
os.environ["CREDENTIAL_ENCRYPTION_KEY"] = "test-encryption-secret-for-user-config"

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.core.database import SessionLocal  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import AuditTask, UserLLMConfig  # noqa: E402
from backend.app.services.auth_service import create_access_token, create_user  # noqa: E402
from backend.app.services import user_llm_config as llm_config_service  # noqa: E402


class _FakeModelResponse:
    status_code = 200

    @staticmethod
    def json() -> dict[str, object]:
        return {"data": [{"id": "model-beta"}, {"id": "model-alpha"}, {"id": "model-alpha"}]}


class _FakeAsyncClient:
    def __init__(self, **_: object) -> None:
        pass

    async def __aenter__(self) -> "_FakeAsyncClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def get(self, url: str, *, headers: dict[str, str]) -> _FakeModelResponse:
        assert url == "https://api.deepseek.com/models"
        assert headers["Authorization"] == "Bearer sk-user-private-key"
        return _FakeModelResponse()


def main() -> None:
    with TestClient(app) as client:
        db = SessionLocal()
        try:
            admin = create_user(db, "admin-test", "admin-test@example.local", "Password-123", role="admin")
            user = create_user(db, "user-test", "user-test@example.local", "Password-123")
            other_user = create_user(db, "other-user", "other-user@example.local", "Password-123")
            db.add(AuditTask(id="task-stop-test", user_id=user.id, task_name="running task", status="running"))
            db.commit()
            admin_headers = {"Authorization": f"Bearer {create_access_token(admin)}"}
            user_headers = {"Authorization": f"Bearer {create_access_token(user)}"}
        finally:
            db.close()

        response = client.get("/api/v1/auth/llm-config", headers=user_headers)
        assert response.status_code == 200 and response.json()["api_key_configured"] is False, response.text

        response = client.put(
            "/api/v1/auth/llm-config",
            headers=user_headers,
            json={
                "provider": "openai",
                "base_url": "https://api.openai.com/v1",
                "model": "gpt-4.1-mini",
                "api_key": "sk-user-private-key",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["api_key_configured"] is True and "api_key" not in response.json(), response.text

        response = client.put(
            "/api/v1/auth/llm-config",
            headers=user_headers,
            json={
                "provider": "deepseek",
                "base_url": "https://api.deepseek.com/chat/completions",
                "model": "deepseek-chat",
            },
        )
        assert response.status_code == 200 and response.json()["api_key_configured"] is True, response.text
        assert response.json()["base_url"] == "https://api.deepseek.com", response.text

        original_async_client = llm_config_service.httpx.AsyncClient
        llm_config_service.httpx.AsyncClient = _FakeAsyncClient
        try:
            response = client.post(
                "/api/v1/auth/llm-models/discover",
                headers=user_headers,
                json={"provider": "deepseek", "base_url": "https://api.deepseek.com"},
            )
        finally:
            llm_config_service.httpx.AsyncClient = original_async_client
        assert response.status_code == 200, response.text
        assert response.json()["models"] == ["model-alpha", "model-beta"], response.text

        other_headers = {"Authorization": f"Bearer {create_access_token(other_user)}"}
        response = client.get("/api/v1/auth/llm-config", headers=other_headers)
        assert response.status_code == 200 and response.json()["api_key_configured"] is False, response.text

        db = SessionLocal()
        try:
            config = db.get(UserLLMConfig, user.id)
            assert config is not None and config.api_key_encrypted != "sk-user-private-key"
        finally:
            db.close()

        assert client.post("/api/v1/admin/tasks/task-stop-test/stop", headers=user_headers).status_code == 403
        response = client.post("/api/v1/admin/tasks/task-stop-test/stop", headers=admin_headers)
        assert response.status_code == 200 and response.json()["status"] == "stopped", response.text
        response = client.get(f"/api/v1/admin/users/{user.id}/tasks", headers=admin_headers)
        assert response.status_code == 200 and response.json()[0]["status"] == "stopped", response.text

    print("User LLM configuration and admin task-stop integration test passed.")


if __name__ == "__main__":
    main()
