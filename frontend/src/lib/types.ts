export type SeverityLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ConnectionMode = "ONLINE" | "DEMO" | "DEGRADED" | "OFFLINE";

export interface AlertEvidence {
  feature: string;
  value: string | number;
  description: string;
}

export interface ThreatAlert {
  timestamp: string;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port?: number | string | null;
  dst_port?: number | string | null;
  protocol: string;
  threat_class: string;
  severity: SeverityLevel;
  confidence: number;
  evidence: AlertEvidence[];
  attack_chain: string[];
  detector: string;
  action: "ALERT_ONLY";
}

export interface AttackChainNode {
  stage: string;
  threat_class: string;
  confidence: number;
  timestamp: string;
  summary: string;
  indicator: string;
}

export interface AttackChainStory {
  id: string;
  title: string;
  source_ip: string;
  target_ip: string;
  assessment: string;
  overall_confidence: number;
  severity: SeverityLevel;
  time_window: string;
  nodes: AttackChainNode[];
}

export interface TrafficDataPoint {
  time: string;
  flows_sec: number;
  pkts_sec: number;
  bytes_sec: number;
  anomaly_score: number;
}

export interface ThreatDistributionItem {
  name: string;
  threat_class: string;
  count: number;
  percentage: number;
  color: string;
}

export interface SeverityCount {
  severity: SeverityLevel;
  count: number;
  percentage: number;
  color: string;
}

export interface SystemStatusData {
  status: string;
  ingest_mode: string;
  response_mode: string;
  payload_decryption: boolean;
  return_path: boolean;
  active_sensor?: string;
  version?: string;
}

export interface DashboardMetrics {
  flow_rate: number;
  flow_rate_trend: number;
  active_threats: number;
  high_severity_count: number;
  critical_alerts: number;
  critical_timeframe: string;
  avg_confidence: number;
  is_live: boolean;
}
