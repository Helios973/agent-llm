"""Integration check for isolated user LLM configuration and admin task stopping."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
TEST_DB_PATH = Path("tmp") / f"user-llm-stop-{uuid4().hex}.db"
os.environ["DATABASE_URL"] = f"sqlite:///./{TEST_DB_PATH.as_posix()}"
os.environ["AUTH_SECRET_KEY"] = "test-auth-secret-for-user-config"
os.environ["CREDENTIAL_ENCRYPTION_KEY"] = "test-encryption-secret-for-user-config"

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.core.database import SessionLocal, engine  # noqa: E402
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
            admin_headers = {"Authorization": f"Bearer {create_access_token(admin, db)}"}
            user_headers = {"Authorization": f"Bearer {create_access_token(user, db)}"}
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

        db = SessionLocal()
        try:
            other_headers = {"Authorization": f"Bearer {create_access_token(other_user, db)}"}
        finally:
            db.close()
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

        response = client.patch(
            f"/api/v1/admin/users/{user.id}/llm-quota",
            headers=admin_headers,
            json={"monthly_token_limit": 123456},
        )
        assert response.status_code == 200 and response.json()["monthly_token_limit"] == 123456, response.text
        response = client.get("/api/v1/auth/sessions", headers=user_headers)
        assert response.status_code == 200 and len(response.json()) == 1, response.text
        db = SessionLocal()
        try:
            db.add_all(
                [
                    AuditTask(id="bulk-delete-ready", user_id=user.id, task_name="delete me", status="completed"),
                    AuditTask(id="bulk-delete-active", user_id=user.id, task_name="keep me", status="running"),
                ]
            )
            db.commit()
        finally:
            db.close()
        response = client.post(
            "/api/v1/audit/tasks/bulk-delete",
            headers=user_headers,
            json={"task_ids": ["bulk-delete-ready", "bulk-delete-active", "missing-task"]},
        )
        assert response.status_code == 200, response.text
        assert response.json()["deleted_ids"] == ["bulk-delete-ready"], response.text
        assert response.json()["skipped_ids"] == ["bulk-delete-active", "missing-task"], response.text
        response = client.post(f"/api/v1/admin/users/{user.id}/sessions/revoke", headers=admin_headers)
        assert response.status_code == 204, response.text
        assert client.get("/api/v1/auth/me", headers=user_headers).status_code == 401
        response = client.get("/api/v1/admin/audit-logs", headers=admin_headers)
        assert response.status_code == 200 and len(response.json()) >= 3, response.text

    engine.dispose()
    TEST_DB_PATH.unlink(missing_ok=True)
    print("User LLM configuration and admin task-stop integration test passed.")


if __name__ == "__main__":
    main()
