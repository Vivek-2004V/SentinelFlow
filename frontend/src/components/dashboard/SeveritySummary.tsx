"use client";

import React from "react";
import { DEMO_SEVERITY_SUMMARY } from "@/lib/demo-data";
import { SeverityCount, ThreatAlert } from "@/lib/types";

interface SeveritySummaryProps {
  alerts?: ThreatAlert[];
}

const SEVERITY_CONFIG: Record<string, { color: string; order: number }> = {
  CRITICAL: { color: "#F43F5E", order: 1 },
  HIGH: { color: "#FB923C", order: 2 },
  MEDIUM: { color: "#FBBF24", order: 3 },
  LOW: { color: "#38BDF8", order: 4 },
  INFO: { color: "#94A3B8", order: 5 },
};

export function SeveritySummary({ alerts }: SeveritySummaryProps) {
  let severities: SeverityCount[] = DEMO_SEVERITY_SUMMARY;

  if (alerts && alerts.length > 0) {
    const total = alerts.length;
    const counts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    alerts.forEach((a) => {
      const sev = (a.severity || "INFO").toUpperCase();
      if (counts[sev] !== undefined) {
        counts[sev]++;
      } else {
        counts.INFO++;
      }
    });

    severities = Object.entries(counts).map(([sev, count]) => ({
      severity: sev as any,
      count,
      percentage: total > 0 ? Math.round((count / total) * 100) : 0,
      color: SEVERITY_CONFIG[sev]?.color || "#94A3B8",
    }));
  }

  const actionableCount = severities
    .filter((s) => s.severity === "CRITICAL" || s.severity === "HIGH")
    .reduce((acc, s) => acc + s.count, 0);

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold tracking-tight text-white">
            Severity Triage Matrix
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Active alert severity distribution
          </p>
        </div>
        <span className="rounded bg-rose-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-rose-400 border border-rose-500/20">
          {actionableCount} Actionable
        </span>
      </div>

      {/* Severity Progress Bars */}
      <div className="mt-4 space-y-3">
        {severities.map((item) => (
          <div key={item.severity} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-1.5">
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ backgroundColor: item.color }}
                />
                <span className="font-mono text-[11px] font-semibold text-slate-300">
                  {item.severity}
                </span>
              </div>
              <div className="flex items-center gap-2 font-mono text-[11px]">
                <span className="font-bold text-white">{item.count}</span>
                <span className="text-slate-400">({item.percentage}%)</span>
              </div>
            </div>
            {/* Progress Track */}
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${item.percentage}%`,
                  backgroundColor: item.color,
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
