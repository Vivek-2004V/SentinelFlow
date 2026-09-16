"use client";

import React, { useEffect, useState, useCallback } from "react";
import { Header } from "@/components/layout/Header";
import { NavSection, Sidebar } from "@/components/layout/Sidebar";
import { HeroDataFlow } from "@/components/dashboard/HeroDataFlow";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { TrafficChart } from "@/components/dashboard/TrafficChart";
import { ThreatDistribution } from "@/components/dashboard/ThreatDistribution";
import { SeveritySummary } from "@/components/dashboard/SeveritySummary";
import { AttackChain } from "@/components/dashboard/AttackChain";
import { LiveIntelligence } from "@/components/dashboard/LiveIntelligence";
import { SecurityBoundary } from "@/components/dashboard/SecurityBoundary";
import { SensorStatus } from "@/components/dashboard/SensorStatus";
import { MLIntelligence } from "@/components/dashboard/MLIntelligence";
import { AdaptiveBaseline } from "@/components/dashboard/AdaptiveBaseline";
import { AttackSimulationLab } from "@/components/dashboard/AttackSimulationLab";
import { AIQualityGate } from "@/components/dashboard/AIQualityGate";
import {
  ConnectionMode,
  DashboardMetrics,
  SystemStatusData,
  ThreatAlert,
} from "@/lib/types";
import {
  DEMO_ALERTS,
  DEMO_METRICS,
  DEMO_SYSTEM_STATUS,
} from "@/lib/demo-data";
import { fetchDashboardMetrics, fetchRecentAlerts, fetchSystemStatus } from "@/lib/api";

export default function Home() {
  const [activeSection, setActiveSection] = useState<NavSection>("overview");
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(false);
  const [connectionMode, setConnectionMode] = useState<ConnectionMode>("DEMO");
  const [apiConnected, setApiConnected] = useState<boolean>(true);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatusData>(DEMO_SYSTEM_STATUS);
  const [alerts, setAlerts] = useState<ThreatAlert[]>(DEMO_ALERTS);
  const [metrics, setMetrics] = useState<DashboardMetrics>(DEMO_METRICS);
  const [lastUpdated, setLastUpdated] = useState<string>("just now");


  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [statusRes, alertsRes, metricsRes] = await Promise.all([
        fetchSystemStatus(),
        fetchRecentAlerts(25),
        fetchDashboardMetrics(),
      ]);

      setSystemStatus(statusRes.data);
      setConnectionMode(statusRes.mode);
      setApiConnected(statusRes.mode === "ONLINE");
      setErrorMessage(null);

      if (alertsRes.data && alertsRes.data.length > 0) {
        setAlerts(alertsRes.data);
      }
      if (metricsRes.data) {
        setMetrics(metricsRes.data);
      }

      setLastUpdated(
        new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        })
      );
    } catch (err) {
      setApiConnected(false);
      setConnectionMode("DEMO");
      setErrorMessage("API UNAVAILABLE — Dashboard running in DEMO/REPLAY mode.");
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Immediately prepend simulation alerts to the feed without waiting for the 5s polling cycle
  const handleSimulationAlerts = useCallback((newAlerts: ThreatAlert[]) => {
    setAlerts((prev) => [...newAlerts, ...prev].slice(0, 50));
  }, []);

  useEffect(() => {
    loadData();
    // 5-second polling interval (Step 9.11)
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleSelectSection = (section: NavSection) => {
    setActiveSection(section);
    setSidebarOpen(false);

    const el = document.getElementById(section);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  return (
    <div className="min-h-screen bg-[#060913] text-slate-100 flex flex-col">
      {/* Top Header with Replay Mode & Connectivity Badge */}
      <Header
        connectionMode={connectionMode}
        apiConnected={apiConnected}
        isLoading={isLoading}
        lastUpdated={lastUpdated}
        onRefresh={loadData}
      />

      {/* API Connectivity Banner if Error or Offline */}
      {errorMessage && (
        <div className="bg-amber-950/40 border-b border-amber-500/30 px-6 py-2 text-xs font-mono text-amber-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
            <span>{errorMessage}</span>
          </div>
          <span className="text-[10px] text-amber-400/80 uppercase">
            Source: demo_flows.csv fixture
          </span>
        </div>
      )}

      {/* Body Area with Sidebar + Content */}
      <div className="flex flex-1 w-full">
        {/* Left Sidebar */}
        <Sidebar
          activeSection={activeSection}
          onSelectSection={handleSelectSection}
          isOpen={sidebarOpen}
          onToggle={() => setSidebarOpen(!sidebarOpen)}
        />

        {/* Main Content Area */}
        <main className="flex-1 px-4 py-6 md:px-8 max-w-7xl mx-auto w-full space-y-6">
          {/* Dashboard Title & Overview Banner */}
          <section id="overview" className="flex flex-col justify-between gap-2 sm:flex-row sm:items-center">
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold tracking-tight text-white">
                  Security Operations Center
                </h1>
                <span className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-xs font-semibold text-cyan-400 border border-cyan-500/20">
                  Command Center
                </span>
              </div>
              <p className="mt-1 text-xs text-slate-400">
                Passive network threat intelligence, dual AI/ML evaluation, and correlated kill-chain evidence.
              </p>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span className="rounded-lg border border-slate-800 bg-[#070D1C] px-3 py-1.5 font-mono text-[11px] text-slate-300">
                Sensor: <strong className="text-cyan-400">{systemStatus.active_sensor || "TAP-01-CORE-NORTH"}</strong>
              </span>
            </div>
          </section>

          {/* Hero Data-Flow Visual (Unidirectional Invariant) */}
          <HeroDataFlow />

          {/* AI Quality Gate (Model & Dataset Verification) */}
          <section id="quality-gate">
            <AIQualityGate />
          </section>

          {/* Attack Simulation Lab */}
          <section id="simulation">
            <AttackSimulationLab onAlertsGenerated={handleSimulationAlerts} />
          </section>

          {/* KPI Summary Cards */}
          <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard
              title="Network Flows"
              value={(metrics.flows_analyzed || 18420).toLocaleString()}
              subtitle={`${(metrics.flow_rate / 1000).toFixed(1)}K flows/s ingress`}
              trend={`+${metrics.flow_rate_trend}% vs baseline`}
              trendPositive={true}
              isLive={metrics.is_live}
              badge="Passive Ingress"
              icon={
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
                </svg>
              }
            />

            <MetricCard
              title="Threats Detected"
              value={metrics.threats_detected || metrics.active_threats}
              subtitle="Correlated anomaly clusters"
              trend={`${metrics.high_severity_count || metrics.high_severity || 0} high severity`}
              trendPositive={false}
              isLive={metrics.is_live}
              badge="7 vectors"
              icon={
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
              }
            />

            <MetricCard
              title="High / Critical"
              value={
                ((metrics.high_severity || metrics.high_severity_count || 0) +
                  (metrics.critical_severity || metrics.critical_alerts || 0)) ||
                35
              }
              subtitle={`${metrics.critical_severity || metrics.critical_alerts || 0} critical escalated`}
              trend="Escalated to SOC"
              trendPositive={false}
              isLive={metrics.is_live}
              icon={
                <svg className="h-4 w-4 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
                </svg>
              }
            />

            <MetricCard
              title="Active Chains"
              value={metrics.active_chains || 8}
              subtitle="Multi-stage host attacks"
              trend={`${metrics.avg_confidence}% avg confidence`}
              trendPositive={true}
              isLive={metrics.is_live}
              icon={
                <svg className="h-4 w-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              }
            />
          </section>

          {/* Traffic Panel & Threat Distribution Panel */}
          <section id="traffic" className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <TrafficChart />
            </div>
            <div id="threats">
              <ThreatDistribution alerts={alerts} />
            </div>
          </section>

          {/* Attack Chain Visualization (Hero Component) */}
          <section id="chains">
            <AttackChain />
          </section>

          {/* Live Alerts Intelligence Feed & Severity Matrix */}
          <section id="alerts" className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <LiveIntelligence alerts={alerts} />
            </div>
            <div className="space-y-6">
              <SeveritySummary alerts={alerts} />
              {/* Adaptive Baseline UI (Step 9.8) */}
              <AdaptiveBaseline status="LEARNING" deviationPercent={78} />
            </div>
          </section>

          {/* Security Boundary & Dual ML Intelligence / Health */}
          <section id="health" className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <SecurityBoundary />
            <div className="space-y-6">
              <MLIntelligence />
              <SensorStatus status={systemStatus} mode={connectionMode} />
            </div>
          </section>

          {/* Footer Note */}
          <footer className="border-t border-slate-800/80 pt-6 pb-8 text-center text-xs text-slate-400">
            <p className="font-mono">
              SentinelFlow • Passive AI/ML Network Threat Intelligence Platform • SOC v1.0
            </p>
            <p className="mt-1 text-[11px] text-slate-400">
              Strictly read-only monitoring architecture. Zero packet injection, no active scanning, zero return path.
            </p>
          </footer>
        </main>
      </div>
    </div>
  );
}
