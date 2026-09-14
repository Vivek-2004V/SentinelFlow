export type ConnectionMode = "ONLINE" | "DEMO" | "DEGRADED" | "OFFLINE";

export interface SystemStatusData {
  status: string;
  ingest_mode: string;
  response_mode: string;
  payload_decryption: boolean;
  return_path: boolean;
  active_sensor?: string;
  version?: string;
}
