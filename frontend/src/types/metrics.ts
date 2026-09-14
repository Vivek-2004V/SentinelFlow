import { SeverityLevel } from "./alert";

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

export interface DashboardMetrics {
  flows_analyzed: number;
  threats_detected: number;
  high_severity: number;
  critical_severity: number;
  active_chains: number;
  flow_rate: number;
  flow_rate_trend: number;
  active_threats: number;
  high_severity_count: number;
  critical_alerts: number;
  critical_timeframe: string;
  avg_confidence: number;
  is_live: boolean;
  threat_distribution?: ThreatDistributionItem[];
  severity_summary?: SeverityCount[];
}
