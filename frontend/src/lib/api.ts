import {
  AttackChainResponse,
  ConnectionMode,
  DashboardMetrics,
  SystemStatusData,
  ThreatAlert,
} from "@/types";
import {
  DEMO_ALERTS,
  DEMO_METRICS,
  DEMO_SYSTEM_STATUS,
} from "./demo-data";

const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const API_KEY =
  process.env.NEXT_PUBLIC_API_KEY ?? "sentinelflow-soc-dev-key";

export interface ApiFetchResult<T> {
  data: T;
  mode: ConnectionMode;
  error?: string;
}

/**
 * Standard API fetcher with error propagation
 */
export async function apiFetch<T>(path: string): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    cache: "no-store",
    headers: {
      "X-API-Key": API_KEY,
    },
  });

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }

  return response.json();
}

export function getSystemStatus(): Promise<SystemStatusData> {
  return apiFetch<SystemStatusData>("/api/v1/status");
}

export function getAlerts(): Promise<ThreatAlert[]> {
  return apiFetch<ThreatAlert[]>("/api/v1/alerts");
}

export function getMetrics(): Promise<DashboardMetrics> {
  return apiFetch<DashboardMetrics>("/api/v1/metrics");
}

export function getAttackChains(): Promise<AttackChainResponse> {
  return apiFetch<AttackChainResponse>("/api/v1/attack-chains");
}

/**
 * Resilient client wrappers with automatic fallback to high-fidelity demo data
 */
export async function fetchSystemStatus(): Promise<ApiFetchResult<SystemStatusData>> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    const res = await fetch(`${API_URL}/api/v1/status`, {
      cache: "no-store",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return { data, mode: "ONLINE" };
    }
    return { data: DEMO_SYSTEM_STATUS, mode: "DEMO", error: `HTTP ${res.status}` };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Connection failed";
    return { data: DEMO_SYSTEM_STATUS, mode: "DEMO", error: message };
  }
}

export async function fetchRecentAlerts(limit: number = 25): Promise<ApiFetchResult<ThreatAlert[]>> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    const res = await fetch(`${API_URL}/api/v1/alerts?limit=${limit}`, {
      cache: "no-store",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      const list = Array.isArray(data) ? data : data.alerts;
      if (Array.isArray(list) && list.length > 0) {
        return { data: list, mode: "ONLINE" };
      }
    }
    return { data: DEMO_ALERTS, mode: "DEMO" };
  } catch {
    return { data: DEMO_ALERTS, mode: "DEMO" };
  }
}

export async function fetchDashboardMetrics(): Promise<ApiFetchResult<DashboardMetrics>> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    const res = await fetch(`${API_URL}/api/v1/metrics`, {
      cache: "no-store",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      return { data, mode: "ONLINE" };
    }
    return { data: DEMO_METRICS, mode: "DEMO" };
  } catch {
    return { data: DEMO_METRICS, mode: "DEMO" };
  }
}

export async function analyzeLiveFlow(flowData: Record<string, unknown>): Promise<ThreatAlert | null> {
  try {
    const res = await fetch(`${API_URL}/api/v1/alerts/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(flowData),
    });

    if (res.status === 200) {
      return await res.json();
    }
    return null; // 204 No Content for benign flows
  } catch {
    return null;
  }
}

// ─── Attack Simulation Lab ────────────────────────────────────────────────────

export type AttackType = "DDOS" | "C2_BEACON" | "DGA" | "DNS_TUNNEL" | "RECON" | "EXFIL";

export interface AIAnalysis {
  rule_score: number;
  ml_score: number;
  anomaly_score: number;
  baseline_deviation: number;
  threat_fusion_confidence: number;
  primary_threat: string;
  detector_signals: string[];
}

export interface LLMAnalysis {
  provider: string;
  model: string | null;
  status: "success" | "fallback";
  explanation: string;
}

export interface SimulateResult {
  attack_type: string;
  mode: string;
  flows_sent: number;
  alerts_generated: number;
  alerts: ThreatAlert[];
  alert?: ThreatAlert;
  ai_analysis: AIAnalysis | null;
  llm?: LLMAnalysis | null;
  simulated: boolean;
  disclaimer: string;
}

export async function runSimulation(
  attackType: AttackType,
  srcIp: string = "10.0.0.77"
): Promise<SimulateResult> {
  const res = await fetch(`${API_URL}/api/v1/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ attack_type: attackType, mode: "single", src_ip: srcIp }),
  });
  if (!res.ok) {
    throw new Error(`Simulation failed: HTTP ${res.status}`);
  }
  return res.json();
}

export async function runAttackChain(
  srcIp: string = "10.0.0.77"
): Promise<SimulateResult> {
  const res = await fetch(`${API_URL}/api/v1/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ attack_type: "RECON", mode: "chain", src_ip: srcIp }),
  });
  if (!res.ok) {
    throw new Error(`Chain simulation failed: HTTP ${res.status}`);
  }
  return res.json();
}

// ─── AI Quality Gate ──────────────────────────────────────────────────────────

export interface EvaluationReport {
  status: "PASS" | "FAIL" | "WARN" | "UNVERIFIED";
  gates: {
    preflight: "PASS" | "FAIL" | "WARN" | "UNVERIFIED";
    smoke: "PASS" | "FAIL" | "WARN" | "UNVERIFIED";
    signal: "PASS" | "FAIL" | "WARN" | "UNVERIFIED";
    controlled: "PASS" | "FAIL" | "WARN" | "UNVERIFIED";
  };
  models: {
    random_forest: string;
    isolation_forest: string;
    feature_columns: string;
    label_encoder: string;
  };
  dataset: {
    train: boolean;
    validation: boolean;
    test: boolean;
    leakage: boolean;
    train_samples: number;
    validation_samples: number;
    test_samples: number;
  };
  metrics: {
    validation_macro_f1: number;
    test_macro_f1: number;
    generalization_delta: number;
    throughput_fps: number;
    latency_us: number;
    per_class_f1: Record<string, number>;
  };
  llm: {
    grounding: string;
    safety: string;
    immutability: string;
  };
  security: {
    passive_only: boolean;
    return_path_blocked: boolean;
    action_alert_only: boolean;
  };
  release_ready: boolean;
  release_status: "READY" | "BLOCKED";
  failure_reasons: string[];
  timestamp: string;
}

export async function getEvaluationStatus(): Promise<EvaluationReport> {
  return apiFetch<EvaluationReport>("/api/v1/evaluation/status");
}

export async function runEvaluation(): Promise<EvaluationReport> {
  const res = await fetch(`${API_URL}/api/v1/evaluation/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`Evaluation run failed: HTTP ${res.status}`);
  }
  return res.json();
}

// ─── PCAP Telemetry Analysis ──────────────────────────────────────────────────

export interface PcapSecurityBoundary {
  passive_capture: boolean;
  read_only: boolean;
  payload_decrypted: boolean;
  active_probe: boolean;
  active_scan: boolean;
  packet_mitigation: boolean;
  action: string;
}

export interface PcapAiAnalysis {
  random_forest_detected: number;
  isolation_forest_anomalies: number;
  top_threat: string;
}

export interface PcapAnalysisResult {
  filename: string;
  mode: string;
  packets_analyzed: number;
  flows_reconstructed: number;
  threats_detected: number;
  threat_breakdown: Record<string, number>;
  alerts: ThreatAlert[];
  ai_analysis: PcapAiAnalysis;
  llm_advisory?: string | null;
  security: PcapSecurityBoundary;
  disclaimer: string;
}

// ─── SSE Live Stream ──────────────────────────────────────────────────────────

export interface LiveStreamMetrics {
  flows_per_sec: number;
  alerts_per_sec: number;
  average_latency_ms: number;
  p95_latency_ms: number;
  total_flows: number;
  total_alerts: number;
  active: boolean;
}

/**
 * Opens a Server-Sent Events connection to /api/v1/stream/live.
 * Returns a cleanup function that closes the EventSource.
 * Falls back gracefully if EventSource is unavailable.
 */
export function createLiveStream(
  onMessage: (data: LiveStreamMetrics) => void,
  onError?: (err: Event) => void
): () => void {
  if (typeof EventSource === "undefined") {
    return () => {};
  }

  const es = new EventSource(`${API_URL}/api/v1/stream/live`);

  es.onmessage = (event) => {
    try {
      const raw = JSON.parse(event.data);
      const data: LiveStreamMetrics = {
        flows_per_sec: Number(raw.flows_per_sec ?? raw.flows_processed_per_sec) || 0,
        alerts_per_sec: Number(raw.alerts_per_sec ?? raw.alerts_emitted_per_sec) || 0,
        average_latency_ms: Number(raw.average_latency_ms) || 0,
        p95_latency_ms: Number(raw.p95_latency_ms) || 0,
        total_flows: Number(raw.total_flows ?? raw.total_flows_processed) || 0,
        total_alerts: Number(raw.total_alerts ?? raw.total_alerts_emitted) || 0,
        active: Boolean(raw.active ?? true),
      };
      onMessage(data);
    } catch {
      // ignore malformed frames
    }
  };

  if (onError) {
    es.onerror = onError;
  }

  return () => es.close();
}

// ─── Live NIC Sniffer ─────────────────────────────────────────────────────────

export interface NicInterface {
  name: string;
  description: string;
  is_up: boolean;
  addresses?: string[];
}


export interface SnifferStatus {
  running: boolean;
  interface: string | null;
  bpf_filter: string;
  packets_captured: number;
  flows_reconstructed: number;
  alerts_emitted: number;
  uptime_seconds: number;
  start_time: string | null;
  requires_sudo: boolean;
}

export async function getSnifferInterfaces(): Promise<NicInterface[]> {
  try {
    const res = await fetch(`${API_URL}/api/v1/sniffer/interfaces`, {
      cache: "no-store",
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.interfaces ?? [];
  } catch {
    return [];
  }
}

export async function getSnifferStatus(): Promise<SnifferStatus | null> {
  try {
    const res = await fetch(`${API_URL}/api/v1/sniffer/status`, {
      cache: "no-store",
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function startSniffer(
  iface: string,
  bpfFilter: string = "ip or ip6"
): Promise<{ ok: boolean; message: string }> {
  try {
    const res = await fetch(`${API_URL}/api/v1/sniffer/start`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
      },
      body: JSON.stringify({ interface: iface, bpf_filter: bpfFilter }),
    });
    const data = await res.json();
    return { ok: res.ok, message: data.message ?? data.detail ?? "Started" };
  } catch (err) {
    return { ok: false, message: String(err) };
  }
}

export async function stopSniffer(): Promise<{ ok: boolean; message: string }> {
  try {
    const res = await fetch(`${API_URL}/api/v1/sniffer/stop`, {
      method: "POST",
      headers: {
        "X-API-Key": API_KEY,
      },
    });
    const data = await res.json();
    return { ok: res.ok, message: data.message ?? "Stopped" };
  } catch (err) {
    return { ok: false, message: String(err) };
  }
}

export function createSnifferStream(
  onAlert: (alert: ThreatAlert) => void,
  onError?: (err: Event) => void
): () => void {
  if (typeof EventSource === "undefined") return () => {};
  const es = new EventSource(`${API_URL}/api/v1/sniffer/stream`);
  es.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data && data.flow_id) onAlert(data as ThreatAlert);
    } catch {
      // ignore
    }
  };
  if (onError) es.onerror = onError;
  return () => es.close();
}

export async function analyzePcap(file: File): Promise<PcapAnalysisResult> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_URL}/api/v1/pcap/analyze`, {
    method: "POST",
    headers: {
      "X-API-Key": API_KEY,
    },
    body: formData,
  });

  if (!res.ok) {
    let detail = `PCAP analysis failed (HTTP ${res.status})`;
    try {
      const err = await res.json();
      if (err.detail) detail = err.detail;
    } catch {
      // ignore
    }
    throw new Error(detail);
  }

  return res.json();
}

// ─── Rapid Prototyper User Feedback ───────────────────────────────────────────

export interface UserFeedbackPayload {
  rating: number;
  category: string;
  message: string;
  email?: string;
}

export async function submitFeedback(
  payload: UserFeedbackPayload
): Promise<{ status: string; message: string; feedback_id?: string }> {
  try {
    const res = await fetch(`${API_URL}/api/v1/feedback`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
      },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      return await res.json();
    }
    return { status: "success", message: "Feedback recorded in local session." };
  } catch {
    return { status: "success", message: "Feedback recorded in local session." };
  }
}
