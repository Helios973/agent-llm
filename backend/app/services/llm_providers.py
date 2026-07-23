from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.app.core.config import settings


SUPPORTED_PROVIDERS = {"openai", "deepseek", "openai-compatible", "ollama", "azure-openai"}


@dataclass(frozen=True)
class ProviderAdapter:
    name: str

    def auth_headers(self, api_key: str) -> dict[str, str]:
        if self.name == "azure-openai":
            return {"api-key": api_key, "Content-Type": "application/json"}
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def chat_url(self, base_url: str) -> str:
        normalized = base_url.rstrip("/")
        if normalized.endswith("/chat/completions"):
            return normalized
        return f"{normalized}/chat/completions"

    def models_url(self, base_url: str) -> str:
        normalized = base_url.rstrip("/")
        if normalized.endswith("/models"):
            return normalized
        return f"{normalized}/models"

    def build_chat_payload(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        user_identifier: str,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "temperature": 0.2,
            "max_tokens": settings.llm_max_output_tokens,
        }
        if self.name not in {"ollama"}:
            payload["response_format"] = {"type": "json_object"}
        if self.name == "openai":
            payload["user"] = user_identifier
        if self.name == "deepseek":
            payload["reasoning_effort"] = settings.deepseek_reasoning_effort
            payload["thinking"] = {"type": "enabled" if settings.deepseek_thinking_enabled else "disabled"}
        return payload


def get_provider_adapter(provider: str) -> ProviderAdapter:
    normalized = provider.strip().lower()
    if normalized not in SUPPORTED_PROVIDERS:
        normalized = "openai-compatible"
    return ProviderAdapter(normalized)


def extract_model_ids(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    raw_models = payload.get("data", payload.get("models", []))
    if not isinstance(raw_models, list):
        return []
    model_ids: set[str] = set()
    for item in raw_models:
        if isinstance(item, str):
            model_id = item.strip()
        elif isinstance(item, dict):
            model_id = str(item.get("id") or item.get("name") or item.get("model") or "").strip()
        else:
            model_id = ""
        if model_id:
            model_ids.add(model_id)
    return sorted(model_ids, key=str.casefold)
