"use client";

import React from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { DEMO_THREAT_DISTRIBUTION } from "@/lib/demo-data";
import { ThreatAlert, ThreatDistributionItem } from "@/lib/types";

interface ThreatDistributionProps {
  alerts?: ThreatAlert[];
}

const THREAT_COLORS: Record<string, string> = {
  DDOS: "#38BDF8",
  RECON: "#F59E0B",
  C2_BEACON: "#EF4444",
  DGA: "#8B5CF6",
  DNS_TUNNEL: "#EC4899",
  EXFIL: "#10B981",
  TLS_ANOMALY: "#6366F1",
  LIKELY_COMPROMISED_HOST: "#DC2626",
  ANOMALY: "#64748B",
};

export function ThreatDistribution({ alerts }: ThreatDistributionProps) {
  let data: ThreatDistributionItem[] = DEMO_THREAT_DISTRIBUTION;

  if (alerts && alerts.length > 0) {
    const counts: Record<string, number> = {};
    alerts.forEach((a) => {
      const cls = a.threat_class || "ANOMALY";
      counts[cls] = (counts[cls] || 0) + 1;
    });

    const totalAlerts = alerts.length;
    data = Object.entries(counts).map(([cls, count]) => ({
      name: cls.replace(/_/g, " "),
      threat_class: cls,
      count,
      percentage: Math.round((count / totalAlerts) * 100),
      color: THREAT_COLORS[cls] || "#38BDF8",
    }));
  }

  const total = data.reduce((acc, item) => acc + item.count, 0);

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold tracking-tight text-white">
            Threat Distribution
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Breakdown across 7 canonical threat vectors
          </p>
        </div>
        <span className="rounded bg-slate-800/80 px-2 py-0.5 font-mono text-[10px] font-medium text-slate-300">
          Total: {total} Events
        </span>
      </div>

      {/* Donut Chart & Legend Side-by-Side */}
      <div className="mt-4 flex flex-col items-center gap-4 sm:flex-row">
        {/* Donut Chart with Center Total */}
        <div className="relative h-44 w-44 shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                innerRadius={52}
                outerRadius={72}
                paddingAngle={3}
                dataKey="count"
                stroke="none"
              >
                {data.map((entry) => (
                  <Cell key={`cell-${entry.threat_class}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const item = payload[0].payload as ThreatDistributionItem;
                    return (
                      <div className="rounded-lg border border-slate-700 bg-[#0B1222] p-2.5 text-xs shadow-xl backdrop-blur-md">
                        <p className="font-semibold text-white">{item.name}</p>
                        <p className="font-mono text-cyan-400">
                          {item.count} alerts ({item.percentage}%)
                        </p>
                      </div>
                    );
                  }
                  return null;
                }}
              />
            </PieChart>
          </ResponsiveContainer>

          {/* Center Callout */}
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">
            <span className="font-mono text-2xl font-bold text-white">{total}</span>
            <span className="text-[10px] uppercase tracking-wider text-slate-400">Threats</span>
          </div>
        </div>

        {/* Compact Legend Grid */}
        <div className="grid w-full grid-cols-1 gap-1.5 xs:grid-cols-2">
          {data.map((item) => (
            <div
              key={item.threat_class}
              className="flex items-center justify-between rounded-lg border border-slate-800/60 bg-[#070D1C] px-2.5 py-1.5 text-xs hover:border-slate-700 transition-colors"
            >
              <div className="flex items-center gap-2 truncate">
                <span
                  className="h-2 w-2 shrink-0 rounded-full"
                  style={{ backgroundColor: item.color }}
                />
                <span className="truncate text-slate-300 text-[11px] font-medium">
                  {item.name}
                </span>
              </div>
              <div className="flex items-center gap-1.5 font-mono text-[11px]">
                <span className="text-slate-400 font-semibold">{item.count}</span>
                <span className="text-slate-400">({item.percentage}%)</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
