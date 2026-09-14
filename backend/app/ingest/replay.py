"""
SentinelFlow In-Process Replay Engine (backend/app/ingest/replay.py)

Streams demo flows from data/sample/demo_flows.csv directly through:
1. Feature Engine
2. Hybrid Triad Detectors (Static Rules + RF + IsolationForest)
3. Threat Fusion Engine
4. Attack-Chain Temporal Correlation
5. Emitted Live Alerts
"""
from __future__ import annotations

import csv
import logging
import time
from pathlib import Path
from typing import Generator, List

from app.schemas.alert import StandardAlert
from app.schemas.flow import RawFlow
from app.services.pipeline import pipeline_orchestrator

logger = logging.getLogger("sentinelflow.ingest.replay")

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SAMPLE_CSV = PROJECT_ROOT / "data" / "sample" / "demo_flows.csv"


class FlowReplayEngine:
    def __init__(self, source_path: Path | str = DEFAULT_SAMPLE_CSV):
        self.source_path = Path(source_path)

    def load_flows(self) -> List[RawFlow]:
        """Loads and parses flow records from the canonical CSV fixture."""
        raw_flows: List[RawFlow] = []
        if not self.source_path.exists():
            logger.warning(f"Replay file {self.source_path} not found.")
            return raw_flows

        with open(self.source_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                try:
                    duration = float(row.get("duration", 0.05))
                    tot_bytes = int(float(row.get("bytes", 120)))
                    tot_pkts = int(float(row.get("packets", 2)))

                    rf = RawFlow(
                        src_ip=row.get("src_ip", "10.0.0.15"),
                        dst_ip=row.get("dst_ip", "10.0.0.20"),
                        src_port=int(row.get("src_port") or 49152),
                        dst_port=int(row.get("dst_port") or 80),
                        proto=row.get("protocol", "TCP"),
                        bytes_sent=tot_bytes // 2,
                        bytes_recv=tot_bytes // 2,
                        pkts_sent=max(1, tot_pkts // 2),
                        pkts_recv=max(0, tot_pkts // 2),
                        duration_seconds=max(0.001, duration),
                        sensor_id="replay-engine",
                        source_format="replay_demo_csv",
                    )
                    raw_flows.append(rf)
                except Exception as e:
                    logger.debug(f"Skipping malformed replay row {i}: {e}")
                    continue

        return raw_flows

    def replay_all(self) -> List[StandardAlert]:
        """Synchronously processes all sample flows through the full pipeline."""
        flows = self.load_flows()
        emitted_alerts: List[StandardAlert] = []
        for flow in flows:
            alert = pipeline_orchestrator.process_flow(flow)
            if alert:
                emitted_alerts.append(alert)
        return emitted_alerts

    def stream_replay(self, delay_seconds: float = 0.05) -> Generator[StandardAlert | None, None, None]:
        """Generator that yields alerts sequentially with a temporal pacing delay."""
        flows = self.load_flows()
        for flow in flows:
            alert = pipeline_orchestrator.process_flow(flow)
            if delay_seconds > 0:
                time.sleep(delay_seconds)
            yield alert


replay_engine = FlowReplayEngine()


if __name__ == "__main__":
    print("=== SentinelFlow In-Process Replay Engine ===")
    print(f"[*] Loading demo flows from {DEFAULT_SAMPLE_CSV}...")
    alerts = replay_engine.replay_all()
    print(f"[+] Replay complete. Processed {len(replay_engine.load_flows())} flows -> Emitted {len(alerts)} alerts.")
