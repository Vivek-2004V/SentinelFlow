from __future__ import annotations

from collections import defaultdict, deque
from statistics import mean, pstdev


class AdaptiveBaseline:
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.history: dict[str, deque[float]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )

    def update(
        self,
        entity: str,
        value: float,
    ) -> None:
        self.history[entity].append(value)

    def deviation(
        self,
        entity: str,
        value: float,
    ) -> float:

        values = self.history[entity]

        if len(values) < 5:
            return 0.0

        average = mean(values)
        deviation = pstdev(values)

        if deviation == 0:
            return 0.0

        return abs(value - average) / deviation
