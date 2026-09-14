export type SeverityLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface AlertEvidence {
  feature: string;
  value: unknown;
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

export interface AttackChainStageItem {
  stage: string;
  tactic: string;
  technique_id: string;
  threat_class: string;
  status: string;
  timestamp?: string | null;
}

export interface HostAttackChain {
  chain_id: string;
  target_ip: string;
  pattern_name: string;
  stages: string[];
  threat_classes: string[];
  confidence: number;
  severity: string;
  action: "ALERT_ONLY";
  details: AttackChainStageItem[];
}

export interface AttackChainResponse {
  total_active_chains: number;
  chains: HostAttackChain[];
}
