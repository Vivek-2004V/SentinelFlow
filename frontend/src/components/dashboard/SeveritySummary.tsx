"use client";

import React from "react";
import { DEMO_SEVERITY_SUMMARY } from "@/lib/demo-data";
import { SeverityCount } from "@/lib/types";

export function SeveritySummary() {
  const severities: SeverityCount[] = DEMO_SEVERITY_SUMMARY;

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
          6 Actionable
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
