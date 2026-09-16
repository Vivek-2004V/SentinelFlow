"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import { ThreatAlert } from "@/lib/types";
import {
  createSnifferStream,
  getSnifferInterfaces,
  getSnifferStatus,
  NicInterface,
  SnifferStatus,
  startSniffer,
  stopSniffer,
} from "@/lib/api";
import { ForensicExport } from "./ForensicExport";

interface LiveNicSnifferProps {
  onAlertsGenerated?: (alerts: ThreatAlert[]) => void;
}

export function LiveNicSniffer({ onAlertsGenerated }: LiveNicSnifferProps) {
  const [interfaces, setInterfaces] = useState<NicInterface[]>([]);
  const [selectedIface, setSelectedIface] = useState<string>("");
  const [bpfFilter, setBpfFilter] = useState("ip or ip6");
  const [status, setStatus] = useState<SnifferStatus | null>(null);
  const [liveAlerts, setLiveAlerts] = useState<ThreatAlert[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [apiAvailable, setApiAvailable] = useState(true);
  const sseCleanupRef = useRef<(() => void) | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Load interfaces on mount
  useEffect(() => {
    getSnifferInterfaces().then((ifaces) => {
      if (ifaces.length === 0) {
        setApiAvailable(false);
        return;
      }
      setInterfaces(ifaces);
      const upIface = ifaces.find((i) => i.is_up);
      if (upIface) setSelectedIface(upIface.name);
    });

    // Poll status every 3s when running
    pollRef.current = setInterval(() => {
      getSnifferStatus().then((s) => {
        if (s) setStatus(s);
      });
    }, 3000);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      sseCleanupRef.current?.();
    };
  }, []);

  const handleStart = useCallback(async () => {
    setErrorMsg(null);
    setLoading(true);
    const result = await startSniffer(selectedIface, bpfFilter);
    setLoading(false);

    if (!result.ok) {
      setErrorMsg(result.message);
      return;
    }

    setLiveAlerts([]);

    // Open SSE stream for real-time alerts
    const cleanup = createSnifferStream(
      (alert) => {
        setLiveAlerts((prev) => [alert, ...prev].slice(0, 100));
        onAlertsGenerated?.([alert]);
      },
      () => setErrorMsg("SSE stream disconnected.")
    );
    sseCleanupRef.current = cleanup;
  }, [selectedIface, bpfFilter, onAlertsGenerated]);

  const handleStop = useCallback(async () => {
    setLoading(true);
    await stopSniffer();
    setLoading(false);
    sseCleanupRef.current?.();
    sseCleanupRef.current = null;
    // Refresh final status
    const s = await getSnifferStatus();
    if (s) setStatus(s);
  }, []);

  const isRunning = status?.running ?? false;

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Header */}
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center mb-5">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold tracking-tight text-white">
              Live NIC Sniffer
            </h2>
            <span
              className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold border ${
                isRunning
                  ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30 animate-pulse"
                  : apiAvailable
                  ? "bg-slate-800 text-slate-400 border-slate-700"
                  : "bg-amber-500/10 text-amber-400 border-amber-500/30"
              }`}
            >
              {isRunning ? "● CAPTURING" : apiAvailable ? "IDLE" : "API OFFLINE"}
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-400">
            Passive read-only packet capture from authorised NIC or TAP/SPAN port
          </p>
        </div>

        {/* Sudo warning badge */}
        <div className="flex items-center gap-1.5 rounded-lg border border-amber-500/20 bg-amber-950/20 px-3 py-1.5">
          <svg className="h-3.5 w-3.5 text-amber-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
          </svg>
          <span className="font-mono text-[10px] text-amber-300">
            Requires <strong>sudo</strong> / CAP_NET_RAW
          </span>
        </div>
      </div>

      {!apiAvailable ? (
        <div className="rounded-xl border border-dashed border-slate-700 p-8 text-center">
          <p className="font-mono text-xs text-slate-400 uppercase tracking-wider">Sniffer API Unavailable</p>
          <p className="text-xs text-slate-500 mt-1">Start the backend to enable live capture controls.</p>
        </div>
      ) : (
        <>
          {/* Controls */}
          <div className="flex flex-wrap items-end gap-3 mb-5">
            {/* Interface selector */}
            <div className="flex-1 min-w-[140px]">
              <label className="block font-mono text-[10px] text-slate-400 uppercase tracking-wider mb-1.5">
                Interface
              </label>
              <select
                value={selectedIface}
                onChange={(e) => setSelectedIface(e.target.value)}
                disabled={isRunning}
                className="w-full rounded-lg border border-slate-700 bg-[#070D1C] px-3 py-2 font-mono text-xs text-slate-200 focus:border-cyan-500/50 focus:outline-none disabled:opacity-50"
              >
                <option value="default">Default Route</option>
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name} {iface.is_up ? "↑" : "↓"}{" "}
                    {iface.addresses?.[0] ? `(${iface.addresses[0]})` : ""}
                  </option>
                ))}
              </select>
            </div>

            {/* BPF Filter */}
            <div className="flex-1 min-w-[140px]">
              <label className="block font-mono text-[10px] text-slate-400 uppercase tracking-wider mb-1.5">
                BPF Filter
              </label>
              <input
                type="text"
                value={bpfFilter}
                onChange={(e) => setBpfFilter(e.target.value)}
                disabled={isRunning}
                placeholder="ip or ip6"
                className="w-full rounded-lg border border-slate-700 bg-[#070D1C] px-3 py-2 font-mono text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500/50 focus:outline-none disabled:opacity-50"
              />
            </div>

            {/* Start / Stop */}
            {isRunning ? (
              <button
                id="sniffer-stop-btn"
                onClick={handleStop}
                disabled={loading}
                className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-5 py-2 font-mono text-xs font-bold text-rose-300 transition-all hover:bg-rose-950/60 disabled:opacity-50"
              >
                {loading ? "Stopping..." : "■ Stop Capture"}
              </button>
            ) : (
              <button
                id="sniffer-start-btn"
                onClick={handleStart}
                disabled={loading || !selectedIface}
                className="rounded-lg border border-emerald-500/40 bg-emerald-950/30 px-5 py-2 font-mono text-xs font-bold text-emerald-300 transition-all hover:bg-emerald-950/60 disabled:opacity-50"
              >
                {loading ? "Starting..." : "▶ Start Capture"}
              </button>
            )}
          </div>

          {/* Error message */}
          {errorMsg && (
            <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-950/20 px-4 py-2.5 font-mono text-xs text-rose-300 flex items-start gap-2">
              <svg className="h-4 w-4 shrink-0 mt-0.5 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
              </svg>
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Stats Row */}
          {status && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
              {[
                { label: "Packets", value: status.packets_captured.toLocaleString(), color: "text-cyan-400" },
                { label: "Flows", value: status.flows_reconstructed.toLocaleString(), color: "text-purple-400" },
                { label: "Alerts", value: status.alerts_emitted.toLocaleString(), color: "text-rose-400" },
                { label: "Uptime", value: `${Math.floor(status.uptime_seconds)}s`, color: "text-emerald-400" },
              ].map(({ label, value, color }) => (
                <div key={label} className="rounded-xl border border-slate-800/80 bg-[#060A14] p-3 text-center">
                  <p className={`font-mono text-xl font-bold ${color}`}>{value}</p>
                  <p className="font-mono text-[10px] text-slate-500 uppercase tracking-wider mt-0.5">{label}</p>
                </div>
              ))}
            </div>
          )}

          {/* Live Alert Feed */}
          <div>
            <div className="flex items-center justify-between mb-2.5">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[11px] text-slate-300 uppercase font-semibold tracking-wider">
                  Live Alert Stream
                </span>
                <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-400">
                  {liveAlerts.length} captured
                </span>
              </div>
              {liveAlerts.length > 0 && (
                <ForensicExport
                  report={{ alerts: liveAlerts, capture_session: status }}
                  filename="live_capture_session"
                  label=""
                />
              )}
            </div>

            {liveAlerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 py-10 text-center">
                {isRunning ? (
                  <>
                    <div className="h-8 w-8 rounded-full border-2 border-cyan-500/30 border-t-cyan-400 animate-spin mb-3" />
                    <p className="font-mono text-xs text-slate-400">Listening for threats...</p>
                    <p className="text-[11px] text-slate-500 mt-1">Alerts will appear here as flows are reconstructed</p>
                  </>
                ) : (
                  <>
                    <svg className="h-8 w-8 text-slate-600 mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z" />
                    </svg>
                    <p className="font-mono text-xs text-slate-400">No captures yet</p>
                    <p className="text-[11px] text-slate-500 mt-0.5">Select an interface and start capturing</p>
                  </>
                )}
              </div>
            ) : (
              <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                {liveAlerts.map((alert, i) => {
                  const badgeStyle =
                    alert.severity === "CRITICAL"
                      ? "bg-rose-500/15 text-rose-400 border-rose-500/30"
                      : alert.severity === "HIGH"
                      ? "bg-orange-500/15 text-orange-400 border-orange-500/30"
                      : alert.severity === "MEDIUM"
                      ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
                      : "bg-cyan-500/15 text-cyan-400 border-cyan-500/30";

                  return (
                    <div
                      key={`${alert.flow_id}-${i}`}
                      className="flex items-center justify-between gap-3 rounded-xl border border-slate-800/80 bg-[#070D1C] px-3.5 py-2.5 text-xs font-mono"
                    >
                      <span className={`rounded border px-2 py-0.5 text-[10px] font-bold ${badgeStyle}`}>
                        {alert.severity}
                      </span>
                      <span className="font-bold text-white flex-1">{alert.threat_class}</span>
                      <span className="text-cyan-300">{alert.src_ip}</span>
                      <span className="text-slate-500">→</span>
                      <span className="text-slate-300">{alert.dst_ip}</span>
                      <span className="text-emerald-400">{(alert.confidence * 100).toFixed(0)}%</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}

      {/* Passive constraint footer */}
      <div className="mt-5 rounded-lg border border-cyan-500/10 bg-cyan-950/10 px-3 py-2 flex items-center gap-2">
        <svg className="h-3.5 w-3.5 text-cyan-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
        </svg>
        <p className="font-mono text-[10px] text-slate-400">
          PASSIVE READ-ONLY capture — zero packet injection · zero active probing · ALERT_ONLY action authority
        </p>
      </div>
    </div>
  );
}
