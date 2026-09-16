from __future__ import annotations

import json
from typing import Any

import httpx

from app.core.config import settings
from app.services.llm.base import LLMProvider


class OpenAIProvider(LLMProvider):
    def __init__(self, provider: str = "openai"):
        self.provider = provider.lower()

    async def explain(self, alert: dict[str, Any]) -> str:
        api_key = settings.openai_api_key if self.provider == "openai" else settings.gemini_api_key
        if not api_key:
            raise ValueError(f"{self.provider.upper()} API key is not configured")

        base_url = (
            settings.openai_base_url
            if self.provider == "openai"
            else "https://generativelanguage.googleapis.com/v1beta/openai"
        )
        model = settings.openai_model if self.provider == "openai" else settings.gemini_model

        system_prompt = (
            "You are a cybersecurity SOC explanation assistant. "
            "SentinelFlow is passive and operates strictly in ALERT_ONLY mode. "
            "Explain the alert using ONLY supplied telemetry evidence. "
            "Do NOT claim blocking, mitigation, payload inspection, or active response."
        )

        headers = {"Authorization": f"Bearer {api_key}"}
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(alert)},
            ],
        }

        async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
            response = await client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
