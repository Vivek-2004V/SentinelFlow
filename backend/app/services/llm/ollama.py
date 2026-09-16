from __future__ import annotations

from typing import Any

import httpx

from app.core.config import settings
from app.services.llm.base import LLMProvider


class OllamaProvider(LLMProvider):
    async def explain(self, alert: dict[str, Any]) -> str:
        prompt = f"""
You are a cybersecurity SOC explanation assistant.

Explain the following SentinelFlow alert using ONLY
the supplied evidence.

Do not:
- invent facts
- claim payload inspection
- claim decryption
- claim active scanning
- claim blocking
- claim mitigation
- modify severity
- modify threat classification

The system is strictly passive and ALERT_ONLY.

Alert:
{alert}

Return:
1. What was detected
2. Evidence
3. Why it matters
4. Analyst investigation guidance
"""
        payload = {
            "model": settings.llm_model,
            "prompt": prompt,
            "stream": False,
        }

        base_url = (getattr(settings, "ollama_base_url", None) or settings.ollama_url).rstrip("/")
        async with httpx.AsyncClient(timeout=settings.llm_timeout_seconds) as client:
            response = await client.post(
                f"{base_url}/api/generate",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")
