"""
SQLite Database Layer for SentinelFlow.

Provides lightweight, zero-configuration local persistence for:
- StandardAlert records (Section 12 Final Schema)
- Flow telemetry archives
- Statistical baselines
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.schemas.alert import EvidenceItem, SeverityLevel, StandardAlert
from app.schemas.flow import RawFlow

DB_PATH = Path(__file__).resolve().parent.parent.parent / "sentinelflow.db"


class Database:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = str(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            # Check if old alerts table needs migration to Section 12 schema
            cursor = conn.execute("PRAGMA table_info(alerts)")
            columns = [row[1] for row in cursor.fetchall()]
            if columns and "flow_id" not in columns:
                conn.execute("DROP TABLE alerts")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    flow_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT,
                    threat_class TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    attack_chain_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    action TEXT DEFAULT 'ALERT_ONLY'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_threat_class ON alerts(threat_class)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    proto TEXT NOT NULL,
                    bytes_sent INTEGER NOT NULL,
                    bytes_recv INTEGER NOT NULL,
                    pkts_sent INTEGER NOT NULL,
                    pkts_recv INTEGER NOT NULL,
                    duration_seconds REAL NOT NULL,
                    dns_query TEXT,
                    tls_sni TEXT,
                    ja3_hash TEXT,
                    sensor_id TEXT,
                    source_format TEXT
                )
            """)
            conn.commit()

    def save_alert(self, alert: StandardAlert) -> None:
        evidence_list = [e.model_dump() for e in alert.evidence]
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    flow_id, timestamp, src_ip, dst_ip, threat_class,
                    severity, confidence, attack_chain_json, evidence_json, action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.flow_id,
                    alert.timestamp.isoformat(),
                    alert.src_ip,
                    alert.dst_ip,
                    alert.threat_class,
                    alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                    alert.confidence,
                    json.dumps(alert.attack_chain),
                    json.dumps(evidence_list),
                    alert.action,
                ),
            )
            conn.commit()

    def save_flow(self, flow: RawFlow) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO flows (
                    created_at, src_ip, dst_ip, src_port, dst_port, proto,
                    bytes_sent, bytes_recv, pkts_sent, pkts_recv,
                    duration_seconds, dns_query, tls_sni, ja3_hash,
                    sensor_id, source_format
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow.start_time.isoformat() if flow.start_time else datetime.utcnow().isoformat(),
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    flow.proto,
                    flow.bytes_sent,
                    flow.bytes_recv,
                    flow.pkts_sent,
                    flow.pkts_recv,
                    flow.duration_seconds,
                    flow.dns_query,
                    flow.tls_sni,
                    flow.ja3_hash,
                    flow.sensor_id,
                    flow.source_format,
                ),
            )
            conn.commit()

    def get_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
    ) -> List[StandardAlert]:
        query = "SELECT * FROM alerts"
        params: list[Any] = []
        conditions = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if threat_type:
            conditions.append("threat_class = ?")
            params.append(threat_type)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        alerts: List[StandardAlert] = []
        for row in rows:
            evidence_data = json.loads(row["evidence_json"])
            attack_chain_data = json.loads(row["attack_chain_json"]) if row["attack_chain_json"] else []

            timestamp_dt = datetime.fromisoformat(row["timestamp"])

            alert = StandardAlert(
                timestamp=timestamp_dt,
                flow_id=row["flow_id"],
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                threat_class=row["threat_class"],
                severity=SeverityLevel(row["severity"]),
                confidence=row["confidence"],
                attack_chain=attack_chain_data,
                evidence=[EvidenceItem(**e) for e in evidence_data],
                action=row["action"] if "action" in row.keys() else "ALERT_ONLY",
            )
            alerts.append(alert)

        return alerts

    def get_alert_by_id(self, alert_id: str) -> Optional[StandardAlert]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM alerts WHERE flow_id = ?", (alert_id,))
            row = cursor.fetchone()

        if not row:
            return None

        evidence_data = json.loads(row["evidence_json"])
        attack_chain_data = json.loads(row["attack_chain_json"]) if row["attack_chain_json"] else []

        return StandardAlert(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            flow_id=row["flow_id"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            threat_class=row["threat_class"],
            severity=SeverityLevel(row["severity"]),
            confidence=row["confidence"],
            attack_chain=attack_chain_data,
            evidence=[EvidenceItem(**e) for e in evidence_data],
            action=row["action"] if "action" in row.keys() else "ALERT_ONLY",
        )

    def get_alert_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
            ).fetchall()
            by_severity = {s.value: 0 for s in SeverityLevel}
            for row in sev_rows:
                by_severity[row[0]] = row[1]

            threat_rows = conn.execute(
                "SELECT threat_class, COUNT(*) FROM alerts GROUP BY threat_class"
            ).fetchall()
            by_threat: Dict[str, int] = {}
            for row in threat_rows:
                by_threat[row[0]] = row[1]

            recent_critical = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'"
            ).fetchone()[0]

        return {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_threat_type": by_threat,
            "recent_critical_count": recent_critical,
        }

    def clear_alerts(self) -> None:
        with self._get_connection() as conn:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM flows")
            conn.commit()


# Global database singleton
db = Database()
