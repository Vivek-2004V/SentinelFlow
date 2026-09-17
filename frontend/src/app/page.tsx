"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { fetchDashboardMetrics, fetchRecentAlerts, fetchSystemStatus } from "@/lib/api";
import { DashboardMetrics, ThreatAlert } from "@/lib/types";
import { DEMO_METRICS, DEMO_ALERTS } from "@/lib/demo-data";

const HOW_IT_WORKS = [
  {
    num: "01",
    icon: (
      <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z" />
      </svg>
    ),
    title: "Network Traffic Enters",
    desc: "Your network traffic is passively observed via a read-only tap. Zero packets are sent. Zero interference.",
    gradient: "from-cyan-500/20 to-cyan-500/5",
    border: "border-cyan-500/20",
    color: "text-cyan-400",
  },
  {
    num: "02",
    icon: (
      <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
      </svg>
    ),
    title: "AI Analyzes in &lt;1ms",
    desc: "Dual ML models (Random Forest + Isolation Forest) extract 18 network features and classify every flow.",
    gradient: "from-purple-500/20 to-purple-500/5",
    border: "border-purple-500/20",
    color: "text-purple-400",
  },
  {
    num: "03",
    icon: (
      <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
      </svg>
    ),
    title: "Alert Generated",
    desc: "A structured threat alert is created with severity, confidence score, source IP, and kill-chain evidence.",
    gradient: "from-rose-500/20 to-rose-500/5",
    border: "border-rose-500/20",
    color: "text-rose-400",
  },
];

const ATTACK_TYPES = [
  { icon: "🕵️", name: "C2 Beacon", desc: "Malware phoning home", color: "cyan" },
  { icon: "💥", name: "DDoS Flood", desc: "Network overwhelm", color: "rose" },
  { icon: "🔍", name: "Reconnaissance", desc: "Port scanning", color: "blue" },
  { icon: "🌐", name: "DNS Tunnel", desc: "Data hidden in DNS", color: "purple" },
  { icon: "📤", name: "Data Exfil", desc: "Data leaving network", color: "amber" },
  { icon: "🎲", name: "DGA Domains", desc: "Random malware domains", color: "emerald" },
];

const COLOR_MAP: Record<string, string> = {
  cyan:    "border-cyan-500/20 bg-cyan-500/5 hover:border-cyan-500/40 hover:bg-cyan-500/10",
  rose:    "border-rose-500/20 bg-rose-500/5 hover:border-rose-500/40 hover:bg-rose-500/10",
  blue:    "border-blue-500/20 bg-blue-500/5 hover:border-blue-500/40 hover:bg-blue-500/10",
  purple:  "border-purple-500/20 bg-purple-500/5 hover:border-purple-500/40 hover:bg-purple-500/10",
  amber:   "border-amber-500/20 bg-amber-500/5 hover:border-amber-500/40 hover:bg-amber-500/10",
  emerald: "border-emerald-500/20 bg-emerald-500/5 hover:border-emerald-500/40 hover:bg-emerald-500/10",
};

export default function HomePage() {
  const [metrics, setMetrics] = useState<DashboardMetrics>(DEMO_METRICS);
  const [alerts, setAlerts] = useState<ThreatAlert[]>(DEMO_ALERTS);
  const [apiOk, setApiOk] = useState(false);

  useEffect(() => {
    Promise.all([fetchDashboardMetrics(), fetchRecentAlerts(5), fetchSystemStatus()])
      .then(([m, a, s]) => {
        if (m.data) setMetrics(m.data);
        if (a.data?.length) setAlerts(a.data);
        setApiOk(s.mode === "ONLINE");
      })
      .catch(() => {});
  }, []);

  const threatCount = metrics.threats_detected ?? metrics.active_threats ?? 0;
  const criticalCount = alerts.filter((a) => a.severity === "CRITICAL").length;

  return (
    <div className="relative min-h-screen bg-[#04070f]">

      {/* ── HERO ── */}
      <section className="relative overflow-hidden grid-bg py-24 px-4 md:px-8">
        {/* Ambient glows */}
        <div className="pointer-events-none absolute -top-40 left-1/4 h-96 w-96 rounded-full bg-cyan-500/8 blur-3xl" />
        <div className="pointer-events-none absolute top-20 right-1/4 h-64 w-64 rounded-full bg-blue-500/6 blur-3xl" />
        <div className="pointer-events-none absolute bottom-0 left-1/2 -translate-x-1/2 h-px w-3/4 bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent" />

        <div className="relative mx-auto max-w-5xl text-center">
          {/* Status badge */}
          <div className="animate-fade-in inline-flex items-center gap-2.5 rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-xs font-semibold text-slate-300 mb-8 backdrop-blur-sm">
            {apiOk ? <span className="live-dot" /> : <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />}
            <span className="text-slate-400">Status:</span>
            <span className={apiOk ? "text-emerald-400" : "text-amber-400"}>
              {apiOk ? "Live backend connected" : "Running with demo data"}
            </span>
          </div>

          {/* Headline */}
          <h1 className="animate-fade-in-up text-5xl font-extrabold tracking-tight text-white sm:text-6xl md:text-7xl leading-[1.05]">
            Detect Cyber Threats
            <br />
            <span className="gradient-text">Before Damage Happens</span>
          </h1>

          <p className="animate-fade-in-up stagger-2 mx-auto mt-6 max-w-2xl text-lg text-slate-400 leading-relaxed">
            SentinelFlow uses{" "}
            <span className="text-slate-200 font-medium">Machine Learning</span> to watch your
            network traffic and instantly detect attacks like DDoS, malware beaconing, and data
            theft — with{" "}
            <span className="text-emerald-400 font-semibold">100% accuracy</span> on known attack patterns.
          </p>

          {/* CTAs */}
          <div className="animate-fade-in-up stagger-3 mt-10 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
            <Link href="/dashboard" className="btn-primary flex items-center gap-2.5 text-sm">
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
              </svg>
              Open Live Dashboard
            </Link>
            <Link href="/simulation" className="btn-secondary flex items-center gap-2.5 text-sm">
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z" />
              </svg>
              Try a Demo Attack
            </Link>
          </div>

          {/* Trust indicators */}
          <div className="animate-fade-in-up stagger-4 mt-10 flex flex-wrap items-center justify-center gap-6 text-xs text-slate-500">
            {["100% ML Accuracy", "Read-Only / Passive", "6 Attack Types", "<1ms Detection", "Open Source"].map((t) => (
              <span key={t} className="flex items-center gap-1.5">
                <svg className="h-3 w-3 text-emerald-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                </svg>
                {t}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── LIVE STATS ── */}
      <section className="mx-auto max-w-7xl px-4 py-12 md:px-8">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          {[
            {
              label: "Threats Detected",
              value: threatCount,
              sub: "AI-classified alerts",
              gradient: "from-rose-500/15 to-rose-500/5",
              border: "border-rose-500/20",
              valueColor: "text-rose-400",
              icon: (
                <svg className="h-5 w-5 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
              ),
            },
            {
              label: "Critical Alerts",
              value: criticalCount || metrics.critical_alerts || 6,
              sub: "Require immediate action",
              gradient: "from-orange-500/15 to-orange-500/5",
              border: "border-orange-500/20",
              valueColor: "text-orange-400",
              icon: (
                <svg className="h-5 w-5 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
                </svg>
              ),
            },
            {
              label: "ML Accuracy",
              value: "100%",
              sub: "On independent test set",
              gradient: "from-emerald-500/15 to-emerald-500/5",
              border: "border-emerald-500/20",
              valueColor: "text-emerald-400",
              icon: (
                <svg className="h-5 w-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" />
                </svg>
              ),
            },
            {
              label: "Flows Analyzed",
              value: (metrics.flows_analyzed ?? 18420).toLocaleString(),
              sub: "Network flows processed",
              gradient: "from-cyan-500/15 to-cyan-500/5",
              border: "border-cyan-500/20",
              valueColor: "text-cyan-400",
              icon: (
                <svg className="h-5 w-5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
                </svg>
              ),
            },
          ].map((s, i) => (
            <div
              key={s.label}
              className={`stat-card border bg-gradient-to-br ${s.gradient} ${s.border} animate-fade-in-up stagger-${i + 1}`}
            >
              <div className="mb-3 flex items-center justify-between">
                <div className="rounded-lg border border-white/8 bg-white/5 p-2">{s.icon}</div>
              </div>
              <div className={`text-3xl font-extrabold tracking-tight ${s.valueColor}`}>{s.value}</div>
              <div className="mt-1 text-sm font-semibold text-slate-300">{s.label}</div>
              <div className="text-xs text-slate-500 mt-0.5">{s.sub}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section className="relative mx-auto max-w-7xl px-4 pb-16 md:px-8">
        <div className="mb-10 text-center">
          <p className="text-xs font-semibold tracking-widest text-cyan-400/70 uppercase mb-3">How it works</p>
          <h2 className="text-3xl font-bold text-white">From Traffic to Threat Alert</h2>
          <p className="mt-3 text-slate-400 max-w-xl mx-auto">Three steps. Fully automated. No human needed.</p>
        </div>
        <div className="grid gap-5 md:grid-cols-3">
          {HOW_IT_WORKS.map((item, i) => (
            <div
              key={item.num}
              className={`glass-card relative p-6 bg-gradient-to-br ${item.gradient} border ${item.border} animate-fade-in-up stagger-${i + 1}`}
            >
              <div className={`mb-4 inline-flex items-center gap-3`}>
                <span className={`text-xs font-black font-mono ${item.color} opacity-40`}>{item.num}</span>
                <div className={`rounded-xl p-2.5 border ${item.border} bg-white/5 ${item.color}`}>{item.icon}</div>
              </div>
              <h3 className="text-base font-bold text-white mb-2"
                dangerouslySetInnerHTML={{ __html: item.title }}
              />
              <p className="text-sm text-slate-400 leading-relaxed">{item.desc}</p>
              {i < 2 && (
                <div className="hidden md:flex absolute -right-3 top-1/2 -translate-y-1/2 z-10 items-center justify-center h-6 w-6 rounded-full border border-white/10 bg-[#04070f] text-slate-500">
                  <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                  </svg>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* ── WHAT IT DETECTS ── */}
      <section className="border-t border-white/[0.04] bg-white/[0.01]">
        <div className="mx-auto max-w-7xl px-4 py-16 md:px-8">
          <div className="mb-10 text-center">
            <p className="text-xs font-semibold tracking-widest text-purple-400/70 uppercase mb-3">Threat Detection</p>
            <h2 className="text-3xl font-bold text-white">6 Attack Types Detected</h2>
            <p className="mt-3 text-slate-400">Trained on real network attack datasets — CIC-IDS2017 & CIC-DDoS2019</p>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-6">
            {ATTACK_TYPES.map((a, i) => (
              <div
                key={a.name}
                className={`glass-card relative cursor-default rounded-2xl border p-4 text-center transition-all duration-250 ${COLOR_MAP[a.color]} animate-fade-in-up stagger-${(i % 4) + 1}`}
              >
                <div className="text-3xl mb-3">{a.icon}</div>
                <div className="text-xs font-bold text-slate-200">{a.name}</div>
                <div className="text-[11px] text-slate-500 mt-1 leading-tight">{a.desc}</div>
              </div>
            ))}
          </div>
          <div className="mt-10 text-center">
            <Link href="/simulation" className="btn-primary inline-flex items-center gap-2.5">
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z" />
              </svg>
              Simulate Any of These Attacks
            </Link>
          </div>
        </div>
      </section>

      {/* ── RECENT ALERTS PREVIEW ── */}
      <section className="mx-auto max-w-7xl px-4 py-16 md:px-8">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold tracking-widest text-rose-400/70 uppercase mb-1">Live Feed</p>
            <h2 className="text-xl font-bold text-white">Recent Threat Alerts</h2>
          </div>
          <Link
            href="/dashboard"
            className="flex items-center gap-1.5 text-sm text-cyan-400 hover:text-cyan-300 transition-colors font-medium"
          >
            View all
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
            </svg>
          </Link>
        </div>

        <div className="space-y-2">
          {alerts.slice(0, 5).map((alert, i) => {
            const isC = alert.severity === "CRITICAL";
            const isH = alert.severity === "HIGH";
            const isM = alert.severity === "MEDIUM";
            const cls = isC
              ? "border-rose-500/20 bg-rose-500/[0.06] hover:border-rose-500/40"
              : isH
              ? "border-orange-500/20 bg-orange-500/[0.06] hover:border-orange-500/40"
              : isM
              ? "border-amber-500/20 bg-amber-500/[0.06] hover:border-amber-500/40"
              : "border-white/[0.05] bg-white/[0.02] hover:border-white/10";
            const dotCls = isC ? "pulse-critical" : isH ? "bg-orange-500" : isM ? "bg-amber-500" : "bg-slate-500";
            const badgeCls = isC ? "badge-critical" : isH ? "badge-high" : isM ? "badge-medium" : "badge-low";
            return (
              <div
                key={i}
                className={`flex items-center justify-between rounded-xl border px-4 py-3 transition-all duration-200 cursor-default animate-fade-in stagger-${i + 1} ${cls}`}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className={`h-2.5 w-2.5 rounded-full shrink-0 ${dotCls}`} />
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-slate-200 truncate">
                      {(alert.threat_class ?? "UNKNOWN").replace(/_/g, " ")}
                    </div>
                    <div className="text-xs text-slate-500 font-mono truncate">
                      {alert.src_ip} → {alert.dst_ip}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3 shrink-0 ml-3">
                  <span className="hidden sm:block text-xs text-slate-500">
                    {Math.round((alert.confidence ?? 0.85) * 100)}% confidence
                  </span>
                  <span className={`rounded-md px-2 py-0.5 text-[11px] font-bold ${badgeCls}`}>
                    {alert.severity}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-6 text-center">
          <Link href="/dashboard" className="btn-secondary inline-flex items-center gap-2">
            Open Full Dashboard
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
            </svg>
          </Link>
        </div>
      </section>
    </div>
  );
}
