from __future__ import annotations

from typing import Any
from app.services.llm.base import LLMProvider


class FallbackProvider(LLMProvider):
    async def explain(
        self,
        alert: dict[str, Any],
    ) -> str:
        threat = alert.get("threat_class", "UNKNOWN")
        severity = alert.get("severity", "UNKNOWN")
        evidence = alert.get("evidence", [])

        evidence_items: list[str] = []
        for item in evidence:
            if isinstance(item, dict):
                desc = item.get("description") or item.get("reason") or f"{item.get('feature')}: {item.get('value')}"
                evidence_items.append(str(desc))
            else:
                evidence_items.append(str(item))

        evidence_text = "; ".join(p for p in evidence_items if p) or "Baseline distribution anomaly"

        return (
            f"SentinelFlow detected {threat} activity "
            f"with {severity} severity. "
            f"Evidence: {evidence_text}. "
            f"No active response was performed because "
            f"the system operates in ALERT_ONLY mode."
        )
