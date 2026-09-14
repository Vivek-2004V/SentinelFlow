"use client";

import React from "react";

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle: string;
  trend?: string;
  trendPositive?: boolean;
  icon: React.ReactNode;
  accentColor?: string;
  badge?: string;
  isLive?: boolean;
}

export function MetricCard({
  title,
  value,
  subtitle,
  trend,
  trendPositive = true,
  icon,
  badge,
  isLive = false,
}: MetricCardProps) {
  return (
    <div className="glass-panel glass-panel-hover group relative overflow-hidden rounded-xl p-5 shadow-sm">
      {/* Top Title & Icon */}
      <div className="flex items-center justify-between">
        <span className="font-mono text-[11px] font-semibold tracking-wider text-slate-400 uppercase">
          {title}
        </span>
        <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-800 bg-[#070D1C] text-slate-300 group-hover:border-cyan-500/30 group-hover:text-cyan-400 transition-colors">
          {icon}
        </div>
      </div>

      {/* Main Metric Value */}
      <div className="mt-3 flex items-baseline gap-2">
        <span className="font-mono text-3xl font-bold tracking-tight text-white">
          {value}
        </span>
        {badge && (
          <span className="rounded bg-slate-800/80 px-2 py-0.5 font-mono text-[10px] font-medium text-slate-300">
            {badge}
          </span>
        )}
      </div>

      {/* Bottom Subtitle / Trend */}
      <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
        <span className="truncate">{subtitle}</span>
        {trend && (
          <span
            className={`font-mono text-[11px] font-medium ${
              trendPositive ? "text-emerald-400" : "text-rose-400"
            }`}
          >
            {trend}
          </span>
        )}
      </div>

      {/* Data Provenance Pill */}
      <div className="mt-3 border-t border-slate-800/60 pt-2 flex items-center justify-between text-[10px] font-mono text-slate-400">
        <span>Provenance:</span>
        <span className={isLive ? "text-emerald-400" : "text-amber-400"}>
          {isLive ? "● Live Telemetry" : "○ Replay Sample"}
        </span>
      </div>
    </div>
  );
}
