"""
Temporal Threat Relation.

Tracks threats across temporal windows to observe progression or persistent activity.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from app.schemas.detection import FusedThreat


class TemporalTracker:
    def __init__(self, window_minutes: int = 15):
        self.window_minutes = window_minutes
        self.history: dict[str, list[FusedThreat]] = defaultdict(list)

    def record_and_correlate(self, threat: FusedThreat) -> list[FusedThreat]:
        """
        Adds threat to temporal history and purges expired entries outside the window.
        Returns all related recent threats for this src_ip.
        """
        cutoff = datetime.utcnow() - timedelta(minutes=self.window_minutes)

        # Append new threat
        self.history[threat.src_ip].append(threat)

        # Filter expired
        self.history[threat.src_ip] = [
            t for t in self.history[threat.src_ip] if t.window_end >= cutoff
        ]

        return self.history[threat.src_ip]


# Global temporal tracker
temporal_tracker = TemporalTracker()
