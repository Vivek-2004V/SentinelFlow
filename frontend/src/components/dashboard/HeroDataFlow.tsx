"use client";

import React from "react";
import {
  Globe,
  ArrowRightLeft,
  ShieldCheck,
  GitMerge,
  BellRing,
} from "lucide-react";

export function HeroDataFlow() {
  const stages = [
    {
      label: "Production Network",
      sub: "Live NetFlow / Zeek Telemetry",
      icon: <Globe className="h-3.5 w-3.5 text-slate-300" />,
    },
    {
      label: "One-Way Passive TAP",
      sub: "Physical Diode / SPAN (Rx Only)",
      icon: <ArrowRightLeft className="h-3.5 w-3.5 text-cyan-400" />,
    },
    {
      label: "SentinelFlow Core",
      sub: "Feature Extraction & Dual AI Models",
      icon: <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />,
    },
    {
      label: "Explainable Attribution",
      sub: "Multi-Stage Attack Chain Fusion",
      icon: <GitMerge className="h-3.5 w-3.5 text-purple-400" />,
    },
    {
      label: "SOC Actionable Alert",
      sub: "Strict ALERT_ONLY Output",
      icon: <BellRing className="h-3.5 w-3.5 text-amber-400" />,
    },
  ];

  return (
    <div className="rounded-xl border border-slate-800/80 bg-gradient-to-r from-[#0B1222] via-[#0E172C] to-[#0B1222] p-4 shadow-lg">
      <div className="flex flex-col items-center justify-between gap-3 lg:flex-row">
        {/* Left Concept Headline */}
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md border border-cyan-500/30 bg-cyan-950/40 text-cyan-400">
            <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-bold tracking-wider text-cyan-400 uppercase">
                Passive Unidirectional Invariant
              </span>
              <span className="rounded bg-emerald-500/10 px-1.5 py-0.2 font-mono text-[9px] font-semibold text-emerald-400 border border-emerald-500/20">
                RETURN_PATH = FALSE
              </span>
            </div>
            <p className="text-xs text-slate-300">
              Observe <span className="text-cyan-400 font-semibold">→</span> Correlate{" "}
              <span className="text-cyan-400 font-semibold">→</span> Explain{" "}
              <span className="text-cyan-400 font-semibold">→</span> Alert.{" "}
              <span className="text-amber-300 font-semibold">Never Respond.</span>
            </p>
          </div>
        </div>

        {/* Linear Unidirectional Stage Flow */}
        <div className="flex flex-wrap items-center justify-center gap-1 sm:gap-2">
          {stages.map((st, idx) => (
            <React.Fragment key={st.label}>
              <div className="group relative flex items-center gap-2 rounded-lg border border-slate-800 bg-[#070D1A] px-2.5 py-1.5 transition-colors hover:border-cyan-500/30">
                <div className="flex h-5 w-5 shrink-0 items-center justify-center">
                  {st.icon}
                </div>
                <div>
                  <p className="font-mono text-[11px] font-medium text-slate-200">{st.label}</p>
                  <p className="text-[9px] text-slate-400">{st.sub}</p>
                </div>
              </div>

              {idx < stages.length - 1 && (
                <div className="flex items-center text-cyan-500/60">
                  <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                  </svg>
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>
    </div>
  );
}
