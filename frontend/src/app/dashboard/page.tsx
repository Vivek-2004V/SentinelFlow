"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";
import { ThreatAlert, DashboardMetrics, SystemStatusData, ConnectionMode } from "@/lib/types";
import { DEMO_ALERTS, DEMO_METRICS, DEMO_SYSTEM_STATUS } from "@/lib/demo-data";
import {
  fetchDashboardMetrics,
  fetchRecentAlerts,
  fetchSystemStatus,
  createLiveStream,
  LiveStreamMetrics,
} from "@/lib/api";
import { LiveIntelligence } from "@/components/dashboard/LiveIntelligence";
import { TrafficChart } from "@/components/dashboard/TrafficChart";
import { ThreatDistribution } from "@/components/dashboard/ThreatDistribution";
import { SeveritySummary } from "@/components/dashboard/SeveritySummary";
import { NetworkTopology } from "@/components/dashboard/NetworkTopology";
import { AttackChain } from "@/components/dashboard/AttackChain";
import { MLIntelligence } from "@/components/dashboard/MLIntelligence";
import { SensorStatus } from "@/components/dashboard/SensorStatus";
import { AdaptiveBaseline } from "@/components/dashboard/AdaptiveBaseline";

const SEV_CONFIG: Record<string, { color: string; dot: string; label: string }> = {
  CRITICAL: { color: "border-rose-500/30 bg-rose-950/20 text-rose-400", dot: "bg-rose-500 animate-pulse", label: "Critical" },
  HIGH: { color: "border-orange-500/30 bg-orange-950/20 text-orange-400", dot: "bg-orange-500", label: "High" },
  MEDIUM: { color: "border-amber-500/30 bg-amber-950/20 text-amber-400", dot: "bg-amber-500", label: "Medium" },
  LOW: { color: "border-slate-700 bg-slate-800/30 text-slate-400", dot: "bg-slate-500", label: "Low" },
};

export default function DashboardPage() {
  const [alerts, setAlerts] = useState<ThreatAlert[]>(DEMO_ALERTS);
  const [metrics, setMetrics] = useState<DashboardMetrics>(DEMO_METRICS);
  const [status, setStatus] = useState<SystemStatusData>(DEMO_SYSTEM_STATUS);
  const [mode, setMode] = useState<ConnectionMode>("DEMO");
  const [lastUpdated, setLastUpdated] = useState("just now");
  const [isLoading, setIsLoading] = useState(false);
  const [sseOk, setSseOk] = useState(false);
  const sseCleanup = useRef<(() => void) | null>(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [s, a, m] = await Promise.all([
        fetchSystemStatus(),
        fetchRecentAlerts(50),
        fetchDashboardMetrics(),
      ]);
      setStatus(s.data);
      setMode(s.mode);
      if (a.data?.length) setAlerts(a.data);
      if (m.data) setMetrics(m.data);
      setLastUpdated(new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
    } catch (_) {
      setMode("DEMO");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const cleanup = createLiveStream(
      (data: LiveStreamMetrics) => {
        setSseOk(true);
        const incomingRate = Number(data.flows_per_sec) || 0;
        setMetrics((prev) => {
          const prevTotal = Number(prev.flows_analyzed) || 18420;
          return {
            ...prev,
            flow_rate: Math.round(incomingRate),
            flows_analyzed: incomingRate > 0 ? prevTotal + Math.round(incomingRate) : prevTotal,
            is_live: data.active,
          };
        });
        setLastUpdated(new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
      },
      () => setSseOk(false)
    );
    sseCleanup.current = cleanup;
    const poll = setInterval(() => {
      fetchRecentAlerts(50).then((r) => { if (r.data?.length) setAlerts(r.data); });
    }, 15000);
    return () => { cleanup(); clearInterval(poll); };
  }, []);

  const criticalAlerts = alerts.filter((a) => a.severity === "CRITICAL");
  const highAlerts = alerts.filter((a) => a.severity === "HIGH");

  return (
    <div className="mx-auto max-w-7xl px-4 py-6 md:px-8 space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">📊 Live Dashboard</h1>
          <p className="text-sm text-slate-400">Real-time network threat monitoring and alerts</p>
        </div>
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold ${
            mode === "ONLINE"
              ? "border-emerald-500/30 bg-emerald-950/30 text-emerald-300"
              : "border-amber-500/30 bg-amber-950/30 text-amber-300"
          }`}>
            <span className={`h-2 w-2 rounded-full animate-pulse ${mode === "ONLINE" ? "bg-emerald-400" : "bg-amber-400"}`} />
            {mode === "ONLINE" ? "Live Data" : "Demo Mode"}
          </div>
          <button
            onClick={loadData}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700/60 transition-colors disabled:opacity-50"
          >
            <svg className={`h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Refresh
          </button>
        </div>
      </div>

      {/* Critical Alert Banner */}
      {criticalAlerts.length > 0 && (
        <div className="flex items-center gap-3 rounded-xl border border-rose-500/40 bg-rose-950/25 px-4 py-3">
          <span className="h-3 w-3 rounded-full bg-rose-500 animate-pulse shrink-0" />
          <span className="text-sm font-semibold text-rose-300">
            🔴 {criticalAlerts.length} CRITICAL threat{criticalAlerts.length > 1 ? "s" : ""} detected
            {highAlerts.length > 0 && ` + ${highAlerts.length} HIGH severity`}
          </span>
          <span className="ml-auto text-[11px] text-rose-400/70 font-mono">Updated {lastUpdated}</span>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          {
            icon: (
              <svg className="h-5 w-5 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
              </svg>
            ),
            label: "Threats Detected",
            value: (metrics.threats_detected ?? metrics.active_threats ?? 0),
            sub: `${metrics.high_severity_count ?? metrics.high_severity ?? 0} high severity`,
            gradient: "from-rose-500/15 to-rose-500/5",
            border: "border-rose-500/20",
            valueColor: "text-rose-400",
          },
          {
            icon: (
              <svg className="h-5 w-5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
              </svg>
            ),
            label: "Flows Analyzed",
            value: (Number(metrics.flows_analyzed) || 18420).toLocaleString(),
            sub: `${(((Number(metrics.flow_rate) || 0)) / 1000).toFixed(1)}K flows/sec`,
            gradient: "from-cyan-500/15 to-cyan-500/5",
            border: "border-cyan-500/20",
            valueColor: "text-cyan-400",
          },
          {
            icon: (
              <svg className="h-5 w-5 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
              </svg>
            ),
            label: "Attack Chains",
            value: metrics.active_chains ?? 8,
            sub: "Multi-stage sequences",
            gradient: "from-purple-500/15 to-purple-500/5",
            border: "border-purple-500/20",
            valueColor: "text-purple-400",
          },
          {
            icon: (
              <svg className="h-5 w-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" />
              </svg>
            ),
            label: "AI Confidence",
            value: `${(metrics.avg_confidence ?? 94.2).toFixed(1)}%`,
            sub: "Average detection accuracy",
            gradient: "from-emerald-500/15 to-emerald-500/5",
            border: "border-emerald-500/20",
            valueColor: "text-emerald-400",
          },
        ].map((card, i) => (
          <div
            key={card.label}
            className={`stat-card border bg-gradient-to-br ${card.gradient} ${card.border} animate-fade-in-up stagger-${i + 1}`}
          >
            <div className="mb-3 inline-flex rounded-lg border border-white/8 bg-white/5 p-2">
              {card.icon}
            </div>
            <div className={`text-2xl font-extrabold tracking-tight ${card.valueColor}`}>{card.value}</div>
            <div className="text-sm font-semibold text-slate-300 mt-1">{card.label}</div>
            <div className="text-xs text-slate-500 mt-0.5">{card.sub}</div>
          </div>
        ))}
      </div>


      {/* Traffic + Threat Distribution */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <TrafficChart />
        </div>
        <ThreatDistribution alerts={alerts} />
      </div>

      {/* Live Alerts Feed + Severity Summary */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <LiveIntelligence alerts={alerts} />
        </div>
        <div className="space-y-6">
          <SeveritySummary alerts={alerts} />
          <AdaptiveBaseline status="LEARNING" deviationPercent={78} />
        </div>
      </div>

      {/* Attack Chain */}
      <AttackChain />

      {/* Network Topology */}
      <NetworkTopology alerts={alerts} />

      {/* ML + Sensor Status */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <MLIntelligence />
        <SensorStatus status={status} mode={mode} />
      </div>
    </div>
  );
}
