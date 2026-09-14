import {
  AttackChainStory,
  DashboardMetrics,
  SeverityCount,
  SystemStatusData,
  ThreatAlert,
  ThreatDistributionItem,
  TrafficDataPoint,
} from "./types";

export const DEMO_METRICS: DashboardMetrics = {
  flow_rate: 24820,
  flow_rate_trend: 8.4,
  active_threats: 47,
  high_severity_count: 12,
  critical_alerts: 6,
  critical_timeframe: "last 24 hours",
  avg_confidence: 94.2,
  is_live: false,
};

export const DEMO_SYSTEM_STATUS: SystemStatusData = {
  status: "operational",
  ingest_mode: "passive",
  response_mode: "alert-only",
  payload_decryption: false,
  return_path: false,
  active_sensor: "TAP-01-CORE-NORTH",
  version: "1.0.0-soc-release",
};

export const DEMO_THREAT_DISTRIBUTION: ThreatDistributionItem[] = [
  { name: "DDoS Flood", threat_class: "DDOS", count: 18, percentage: 28, color: "#EF4444" },
  { name: "C2 Beacon", threat_class: "C2_BEACON", count: 15, percentage: 24, color: "#F97316" },
  { name: "Reconnaissance", threat_class: "RECON", count: 12, percentage: 19, color: "#38BDF8" },
  { name: "DGA Domain", threat_class: "DGA", count: 9, percentage: 15, color: "#A855F7" },
  { name: "DNS Tunneling", threat_class: "DNS_TUNNEL", count: 6, percentage: 9, color: "#06B6D4" },
  { name: "Data Exfiltration", threat_class: "EXFIL", count: 4, percentage: 6, color: "#EC4899" },
  { name: "TLS Anomaly", threat_class: "TLS_ANOMALY", count: 3, percentage: 5, color: "#6366F1" },
];

export const DEMO_SEVERITY_SUMMARY: SeverityCount[] = [
  { severity: "CRITICAL", count: 6, percentage: 13, color: "#EF4444" },
  { severity: "HIGH", count: 14, percentage: 30, color: "#F97316" },
  { severity: "MEDIUM", count: 20, percentage: 42, color: "#EAB308" },
  { severity: "LOW", count: 7, percentage: 15, color: "#38BDF8" },
];

export const DEMO_ATTACK_CHAIN: AttackChainStory = {
  id: "chain-8042",
  title: "Multi-Stage Infrastructure Infiltration & Exfiltration",
  source_ip: "10.0.0.15",
  target_ip: "203.0.113.88",
  assessment: "LIKELY_COMPROMISED_HOST",
  overall_confidence: 0.96,
  severity: "CRITICAL",
  time_window: "3m 06s total duration",
  nodes: [
    {
      stage: "Stage 1",
      threat_class: "RECON",
      confidence: 0.82,
      timestamp: "10:01:04",
      summary: "Port & Host Discovery Scan",
      indicator: "unique_dst_ports = 187 (horizontal fan-out)",
    },
    {
      stage: "Stage 2",
      threat_class: "DGA",
      confidence: 0.76,
      timestamp: "10:01:17",
      summary: "Algorithmically Generated Domain Query",
      indicator: "dns_entropy = 4.18 (Shannon entropy threshold)",
    },
    {
      stage: "Stage 3",
      threat_class: "C2_BEACON",
      confidence: 0.91,
      timestamp: "10:01:29",
      summary: "Command & Control Heartbeat",
      indicator: "periodicity_score = 0.94 (30.0s interval ±0.2s)",
    },
    {
      stage: "Stage 4",
      threat_class: "EXFIL",
      confidence: 0.88,
      timestamp: "10:04:10",
      summary: "Bulk Outbound Telemetry Drain",
      indicator: "outbound_inbound_ratio = 8.4 (52.4 MB egress)",
    },
  ],
};

export const DEMO_ALERTS: ThreatAlert[] = [
  {
    timestamp: "2026-09-14T10:04:10Z",
    flow_id: "F-10041",
    src_ip: "10.0.0.15",
    dst_ip: "203.0.113.88",
    src_port: 52341,
    dst_port: 443,
    protocol: "TCP",
    threat_class: "LIKELY_COMPROMISED_HOST",
    severity: "CRITICAL",
    confidence: 0.96,
    attack_chain: ["RECON", "DGA", "C2_BEACON", "EXFIL"],
    detector: "attack_chain_engine_v1",
    action: "ALERT_ONLY",
    evidence: [
      {
        feature: "attack_chain_progression",
        value: "4 stages confirmed",
        description: "Sequential kill-chain progression observed within 186 seconds",
      },
      {
        feature: "periodicity_score",
        value: 0.96,
        description: "C2_BEACON: Highly regular communication interval (autocorrelation = 0.96)",
      },
      {
        feature: "outbound_inbound_ratio",
        value: 8.4,
        description: "EXFIL: Massive outbound traffic asymmetry exceeding host historical baseline",
      },
      {
        feature: "dns_entropy",
        value: 4.18,
        description: "DGA: Shannon entropy score exceeding pseudorandom domain threshold",
      },
    ],
  },
  {
    timestamp: "2026-09-14T10:01:29Z",
    flow_id: "F-10038",
    src_ip: "10.0.0.15",
    dst_ip: "198.51.100.24",
    src_port: 49152,
    dst_port: 443,
    protocol: "TCP",
    threat_class: "C2_BEACON",
    severity: "HIGH",
    confidence: 0.93,
    attack_chain: ["RECON", "C2_BEACON"],
    detector: "c2_detector_v1",
    action: "ALERT_ONLY",
    evidence: [
      {
        feature: "periodicity_score",
        value: 0.94,
        description: "Periodic beacon timing: mean IAT 30.01s, std dev 0.04s",
      },
      {
        feature: "adaptive_baseline_zscore",
        value: "+3.84σ",
        description: "Communication frequency deviates significantly from host 24h baseline",
      },
    ],
  },
  {
    timestamp: "2026-09-14T09:58:45Z",
    flow_id: "F-10029",
    src_ip: "192.168.4.112",
    dst_ip: "10.0.0.1",
    src_port: 60234,
    dst_port: 80,
    protocol: "TCP",
    threat_class: "DDOS",
    severity: "CRITICAL",
    confidence: 0.98,
    attack_chain: [],
    detector: "ddos_detector_v1",
    action: "ALERT_ONLY",
    evidence: [
      {
        feature: "pkts_per_second",
        value: 48500,
        description: "Extreme packet rate surge exceeding volumetric threshold by 12x",
      },
      {
        feature: "bytes_per_second",
        value: "38.8 MB/s",
        description: "High bandwidth utilization on inbound interface",
      },
    ],
  },
  {
    timestamp: "2026-09-14T09:45:12Z",
    flow_id: "F-10015",
    src_ip: "10.10.2.88",
    dst_ip: "1.1.1.1",
    src_port: 53120,
    dst_port: 53,
    protocol: "UDP",
    threat_class: "DNS_TUNNEL",
    severity: "HIGH",
    confidence: 0.89,
    attack_chain: [],
    detector: "dns_tunnel_detector_v1",
    action: "ALERT_ONLY",
    evidence: [
      {
        feature: "dns_query_length",
        value: 142,
        description: "Anomalous TXT/NULL record query payload length",
      },
      {
        feature: "dns_entropy",
        value: 4.62,
        description: "High Shannon entropy indicating Base64/Hex encoded data chunk",
      },
    ],
  },
  {
    timestamp: "2026-09-14T09:30:00Z",
    flow_id: "F-09982",
    src_ip: "10.0.0.99",
    dst_ip: "10.0.0.0/24",
    src_port: 39120,
    dst_port: "multi",
    protocol: "TCP",
    threat_class: "RECON",
    severity: "MEDIUM",
    confidence: 0.84,
    attack_chain: [],
    detector: "recon_detector_v1",
    action: "ALERT_ONLY",
    evidence: [
      {
        feature: "unique_dst_ports",
        value: 124,
        description: "Vertical port probing across common administrative ports",
      },
      {
        feature: "unique_dst_hosts",
        value: 18,
        description: "Subnet horizontal sweep pattern detected",
      },
    ],
  },
  {
    timestamp: "2026-09-14T09:12:33Z",
    flow_id: "F-09871",
    src_ip: "172.16.0.45",
    dst_ip: "104.244.42.1",
    src_port: 58210,
    dst_port: 443,
    protocol: "TCP",
    threat_class: "TLS_ANOMALY",
    severity: "MEDIUM",
    confidence: 0.78,
    attack_chain: [],
    detector: "tls_anomaly_detector_v1",
    action: "ALERT_ONLY",
    evidence: [
      {
        feature: "ja3_hash",
        value: "e7d705a3286e19ea42f587b344ee6865",
        description: "Uncommon client cipher suite order matching evasion framework",
      },
      {
        feature: "tls_sni_length",
        value: 0,
        description: "Direct IP TLS handshake without Server Name Indication header",
      },
    ],
  },
];

export function generateTrafficHistory(range: "1m" | "5m" | "15m" | "1h"): TrafficDataPoint[] {
  const points: TrafficDataPoint[] = [];
  const count = range === "1m" ? 20 : range === "5m" ? 30 : range === "15m" ? 45 : 60;
  const now = Date.now();
  const stepMs = (range === "1m" ? 60 : range === "5m" ? 300 : range === "15m" ? 900 : 3600) * 1000 / count;

  const baseFlows = 24000;
  for (let i = count; i >= 0; i--) {
    const timeObj = new Date(now - i * stepMs);
    const timeStr = timeObj.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

    // Smooth baseline variance with an intentional spike corresponding to attack window
    const progress = 1 - i / count;
    const spike = progress > 0.65 && progress < 0.85 ? 12000 * Math.sin((progress - 0.65) / 0.2 * Math.PI) : 0;
    const noise = (Math.sin(i * 0.4) + Math.cos(i * 0.7)) * 1200;

    const flows_sec = Math.round(baseFlows + spike + noise);
    const pkts_sec = Math.round(flows_sec * 3.8);
    const bytes_sec = Math.round(pkts_sec * 840);
    const anomaly_score = Number((0.08 + (spike > 0 ? (spike / 15000) * 0.75 : Math.random() * 0.05)).toFixed(2));

    points.push({
      time: timeStr,
      flows_sec,
      pkts_sec,
      bytes_sec,
      anomaly_score,
    });
  }

  return points;
}
