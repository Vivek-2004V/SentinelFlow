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
