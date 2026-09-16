"use client";

import React from "react";

interface BaselineMetric {
  name: string;
  status: "Normal" | "Elevated" | "Anomalous";
  zScore: string;
  detail: string;
}

interface AdaptiveBaselineProps {
  status?: string;
  deviationPercent?: number;
  metrics?: BaselineMetric[];
}

export function AdaptiveBaseline({
  status = "LEARNING",
  deviationPercent = 78,
  metrics,
}: AdaptiveBaselineProps) {
  const defaultMetrics: BaselineMetric[] = [
    {
      name: "DNS queries",
      status: "Normal",
      zScore: "+0.42 σ",
      detail: "Within 95% EWMA confidence bounds",
    },
    {
      name: "Outbound traffic",
      status: "Elevated",
      zScore: "+2.84 σ",
      detail: "Exceeds standard deviation envelope",
    },
    {
      name: "Connection rate",
      status: "Normal",
      zScore: "+0.18 σ",
      detail: "Stable flow creation frequency",
    },
    {
      name: "Internal fan-out",
      status: "Normal",
      zScore: "+0.05 σ",
      detail: "Zero lateral movement spread",
    },
  ];

  const displayMetrics = metrics || defaultMetrics;

  const getStatusBadge = (metricStatus: "Normal" | "Elevated" | "Anomalous") => {
    switch (metricStatus) {
      case "Normal":
        return (
          <span className="rounded bg-emerald-950/60 px-2 py-0.5 font-mono text-[10px] font-semibold text-emerald-400 border border-emerald-500/30">
            Normal
          </span>
        );
      case "Elevated":
        return (
          <span className="rounded bg-amber-950/60 px-2 py-0.5 font-mono text-[10px] font-semibold text-amber-400 border border-amber-500/30 animate-pulse">
            Elevated
          </span>
        );
      case "Anomalous":
        return (
          <span className="rounded bg-rose-950/60 px-2 py-0.5 font-mono text-[10px] font-semibold text-rose-400 border border-rose-500/30 animate-pulse">
            Anomalous
          </span>
        );
    }
  };

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold tracking-tight text-white flex items-center gap-2">
            <span className="inline-block h-2 w-2 rounded-full bg-cyan-400"></span>
            Adaptive Baseline
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Dynamic per-host behavioral profiling & online statistical deviation tracking
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 rounded-full border border-cyan-500/30 bg-cyan-950/40 px-2.5 py-0.5 text-[11px] font-mono font-medium text-cyan-300">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
            <span>{status}</span>
          </div>
        </div>
      </div>

      {/* Normal Behavior Telemetry Table */}
      <div className="mt-4">
        <div className="flex items-center justify-between pb-1.5 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
          <span>Observed Behavior Vector</span>
          <span>Baseline State</span>
        </div>

        <div className="divide-y divide-slate-800/60 text-xs">
          {displayMetrics.map((m) => (
            <div
              key={m.name}
              className="flex items-center justify-between py-2.5 hover:bg-slate-800/20 px-1 rounded transition-colors"
            >
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-medium text-slate-200">{m.name}</span>
                  <span className="font-mono text-[10px] text-slate-500">{m.zScore}</span>
                </div>
                <p className="text-[10px] text-slate-400">{m.detail}</p>
              </div>
              <div>{getStatusBadge(m.status)}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Baseline Status & Deviation Meter */}
      <div className="mt-4 rounded-xl border border-slate-800 bg-[#070D1C] p-3.5">
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs font-semibold text-slate-300">
            BASELINE DEVIATION
          </span>
          <span className="font-mono text-xs font-bold text-amber-400">
            {deviationPercent}%
          </span>
        </div>

        {/* ASCII & Graphical Progress Bar */}
        <div className="mt-2 space-y-1.5">
          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyan-500 via-amber-500 to-rose-500 transition-all duration-500"
              style={{ width: `${deviationPercent}%` }}
            />
          </div>

          <div className="flex justify-between font-mono text-[10px] text-slate-500">
            <span>0% (Nominal)</span>
            <span className="text-amber-400/90 font-medium">Anomaly Threshold: 65%</span>
            <span>100% (Critical)</span>
          </div>
        </div>

        {/* Analyst Insight */}
        <p className="mt-3 text-[11px] text-slate-300 leading-relaxed border-t border-slate-800/80 pt-2.5">
          <strong className="text-amber-300">Analyst Telemetry Note:</strong> System observed a{" "}
          <span className="font-mono font-semibold text-white">{deviationPercent}%</span> statistical
          divergence relative to calibrated rolling EWMA baseline window.
        </p>
      </div>
    </div>
  );
}
