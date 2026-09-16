from __future__ import annotations

import logging
from typing import Any

from app.core.config import settings
from app.services.llm.base import LLMProvider
from app.services.llm.fallback import FallbackProvider
from app.services.llm.ollama import OllamaProvider
from app.services.llm.openai_provider import OpenAIProvider

logger = logging.getLogger("sentinelflow.llm_service")

FORBIDDEN_ACTIVE_TERMS = [
    "blocked the attacker",
    "firewall blocked",
    "ip was banned",
    "connection terminated",
    "rst packet injected",
    "process killed",
    "quarantined endpoint",
    "blackholed traffic",
    "payload decrypted",
    "active scan",
    "mitigation applied",
]


def sanitize_active_mitigation(text: str) -> str:
    """Removes or neutralizes any active mitigation claims."""
    sanitized = text
    for term in FORBIDDEN_ACTIVE_TERMS:
        if term in sanitized.lower():
            sanitized = sanitized.replace(term, "passively alerted on")
    return sanitized


class LLMService:
    def __init__(self) -> None:
        self.fallback = FallbackProvider()

    def _get_provider(self) -> LLMProvider:
        provider_name = settings.llm_provider.lower()
        if provider_name == "ollama":
            return OllamaProvider()
        elif provider_name in ("openai", "gemini"):
            return OpenAIProvider(provider=provider_name)
        else:
            return self.fallback

    async def explain(self, alert: dict[str, Any]) -> dict[str, Any]:
        provider = self._get_provider()
        provider_name = settings.llm_provider.lower()

        # If already configured as fallback, call directly
        if provider_name == "fallback":
            fallback_text = await self.fallback.explain(alert)
            return {
                "provider": "fallback",
                "model": None,
                "status": "fallback",
                "explanation": sanitize_active_mitigation(fallback_text),
            }

        try:
            raw_explanation = await provider.explain(alert)
            if not raw_explanation:
                raise ValueError("Empty explanation returned from LLM provider")

            sanitized = sanitize_active_mitigation(raw_explanation)
            return {
                "provider": provider_name,
                "model": getattr(settings, "llm_model", "llama3.2"),
                "status": "success",
                "explanation": sanitized,
            }
        except Exception as exc:
            logger.warning(
                "Primary LLM provider '%s' failed: %s. Reverting to deterministic fallback.",
                provider_name,
                exc,
            )
            fallback_text = await self.fallback.explain(alert)
            return {
                "provider": "fallback",
                "model": None,
                "status": "fallback",
                "explanation": sanitize_active_mitigation(fallback_text),
            }


llm_service = LLMService()
