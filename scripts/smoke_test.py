from __future__ import annotations

import os
import time
from pathlib import Path
from uuid import uuid4

import httpx


ROOT = Path(__file__).resolve().parents[1]


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        os.environ.setdefault(key, value)


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def env_int(name: str, default: int) -> int:
    raw = env(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    return value if value > 0 else default


def client_host(host: str) -> str:
    return "127.0.0.1" if host in {"0.0.0.0", "::", "[::]"} else host


def join_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def api_base_url() -> str:
    load_dotenv(ROOT / ".env")

    explicit_api_base = env("FRONTEND_API_BASE_URL")
    if explicit_api_base:
        return explicit_api_base.rstrip("/")

    backend_public_url = env("BACKEND_PUBLIC_URL")
    if not backend_public_url:
        scheme = env("BACKEND_SCHEME", "http")
        host = client_host(env("BACKEND_HOST", "127.0.0.1"))
        port = env("BACKEND_PORT", "8000")
        backend_public_url = f"{scheme}://{host}:{port}"

    api_prefix = env("API_V1_PREFIX", "/api/v1")
    return join_url(backend_public_url, api_prefix)


def main() -> None:
    api_base = api_base_url()
    poll_seconds = env_int("SMOKE_TEST_MAX_WAIT_SECONDS", 120)
    sample_file = ROOT / "examples" / "vulnerable_python_app" / "app.py"
    if not sample_file.exists():
        raise FileNotFoundError(f"Sample file not found: {sample_file}")

    print(f"Using API base: {api_base}")
    print(f"Smoke test timeout: {poll_seconds} seconds")

    with httpx.Client(timeout=30.0) as client:
        username = f"smoke-{uuid4().hex[:10]}"
        auth_payload = {
            "username": username,
            "email": f"{username}@example.com",
            "password": "SmokeTest123!",
        }
        response = client.post(f"{api_base}/auth/register", json=auth_payload)
        response.raise_for_status()
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print("Registered smoke-test user:", username)

        with sample_file.open("rb") as handle:
            response = client.post(
                f"{api_base}/upload",
                files={"file": (sample_file.name, handle, "text/x-python")},
                data={"task_name": "demo-audit"},
                headers=headers,
            )
        response.raise_for_status()
        upload_data = response.json()
        task_id = upload_data["task_id"]
        print("Upload succeeded:", upload_data)

        response = client.post(f"{api_base}/audit/start", json={"task_id": task_id}, headers=headers)
        response.raise_for_status()
        print("Audit started:", response.json())

        task = None
        for index in range(poll_seconds):
            time.sleep(1)
            response = client.get(f"{api_base}/audit/{task_id}", headers=headers)
            response.raise_for_status()
            task = response.json()
            if index % 5 == 0 or task["status"] in {"completed", "failed"}:
                print("Current status:", task["status"], "findings:", len(task["findings"]))
            if task["status"] in {"completed", "failed"}:
                break

        if not task or task["status"] != "completed":
            raise RuntimeError(f"Audit did not complete successfully: {task}")

        report = client.get(f"{api_base}/report/{task_id}", headers=headers)
        report.raise_for_status()
        print("Report info:", report.json())


if __name__ == "__main__":
    main()
