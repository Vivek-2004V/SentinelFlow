import {
  ConnectionMode,
  SystemStatusData,
  ThreatAlert,
} from "./types";
import {
  DEMO_ALERTS,
  DEMO_SYSTEM_STATUS,
} from "./demo-data";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface ApiFetchResult<T> {
  data: T;
  mode: ConnectionMode;
  error?: string;
}

export async function fetchSystemStatus(): Promise<ApiFetchResult<SystemStatusData>> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    const res = await fetch(`${API_BASE_URL}/api/v1/status`, {
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

export async function fetchRecentAlerts(limit: number = 20): Promise<ApiFetchResult<ThreatAlert[]>> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    const res = await fetch(`${API_BASE_URL}/api/v1/alerts?limit=${limit}`, {
      cache: "no-store",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data) && data.length > 0) {
        return { data, mode: "ONLINE" };
      }
    }
    return { data: DEMO_ALERTS, mode: "DEMO" };
  } catch {
    return { data: DEMO_ALERTS, mode: "DEMO" };
  }
}

export async function analyzeLiveFlow(flowData: Record<string, unknown>): Promise<ThreatAlert | null> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/alerts/analyze`, {
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
