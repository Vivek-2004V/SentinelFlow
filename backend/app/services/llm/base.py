from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class LLMProvider(ABC):
    @abstractmethod
    async def explain(
        self,
        alert: dict[str, Any],
    ) -> str:
        """Generate an explanation for an existing alert."""
        raise NotImplementedError
