"use client";

import React, { useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { generateTrafficHistory } from "@/lib/demo-data";
import { TrafficDataPoint } from "@/lib/types";

export function TrafficChart() {
  const [timeRange, setTimeRange] = useState<"1m" | "5m" | "15m" | "1h">("5m");
  const data: TrafficDataPoint[] = generateTrafficHistory(timeRange);

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Chart Header */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold tracking-tight text-white">
              Live Traffic Activity
            </h2>
            <span className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] font-medium text-cyan-400 border border-cyan-500/20">
              Unidirectional Ingest
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-400">
            Real-time passive flow rate and packet throughput per second
          </p>
        </div>

        {/* Time Range Selector */}
        <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-[#070D1C] p-1 text-xs">
          {(["1m", "5m", "15m", "1h"] as const).map((range) => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`rounded px-2.5 py-1 font-mono text-[11px] font-medium transition-colors ${
                timeRange === range
                  ? "bg-cyan-500/20 text-cyan-300 shadow-sm"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      {/* Chart Area */}
      <div className="mt-5 h-72 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="flowGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#0EA5E9" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#0EA5E9" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="anomalyGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#EF4444" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
              </linearGradient>
            </defs>

            <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />

            <XAxis
              dataKey="time"
              stroke="#64748B"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: "#1E293B" }}
              fontFamily="monospace"
            />

            <YAxis
              stroke="#64748B"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: "#1E293B" }}
              tickFormatter={(v) => `${(v / 1000).toFixed(0)}k`}
              fontFamily="monospace"
            />

            <Tooltip
              content={({ active, payload, label }) => {
                if (active && payload && payload.length) {
                  const pt = payload[0].payload as TrafficDataPoint;
                  return (
                    <div className="rounded-lg border border-slate-700 bg-[#0B1222] p-3 shadow-xl backdrop-blur-md">
                      <p className="font-mono text-[11px] font-semibold text-slate-400 border-b border-slate-800 pb-1.5">
                        TIMESTAMP: {label}
                      </p>
                      <div className="mt-2 space-y-1 text-xs">
                        <div className="flex items-center justify-between gap-4">
                          <span className="text-slate-400">Flow Rate:</span>
                          <span className="font-mono font-bold text-cyan-400">
                            {pt.flows_sec.toLocaleString()} flows/s
                          </span>
                        </div>
                        <div className="flex items-center justify-between gap-4">
                          <span className="text-slate-400">Packets/s:</span>
                          <span className="font-mono text-slate-200">
                            {pt.pkts_sec.toLocaleString()} pps
                          </span>
                        </div>
                        <div className="flex items-center justify-between gap-4">
                          <span className="text-slate-400">Throughput:</span>
                          <span className="font-mono text-slate-200">
                            {(pt.bytes_sec / (1024 * 1024)).toFixed(2)} MB/s
                          </span>
                        </div>
                        <div className="flex items-center justify-between gap-4 pt-1 border-t border-slate-800">
                          <span className="text-slate-400">Anomaly Index:</span>
                          <span
                            className={`font-mono font-semibold ${
                              pt.anomaly_score > 0.4 ? "text-rose-400" : "text-emerald-400"
                            }`}
                          >
                            {(pt.anomaly_score * 100).toFixed(0)}%
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                }
                return null;
              }}
            />

            <Area
              type="monotone"
              dataKey="flows_sec"
              stroke="#38BDF8"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#flowGradient)"
              name="Flows/sec"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Footer Metrics */}
      <div className="mt-3 grid grid-cols-2 gap-4 border-t border-slate-800/80 pt-3 text-xs sm:grid-cols-4">
        <div>
          <span className="text-[11px] text-slate-400">Median Rate</span>
          <p className="font-mono font-semibold text-slate-200">24,450 flows/s</p>
        </div>
        <div>
          <span className="text-[11px] text-slate-400">Peak Surge</span>
          <p className="font-mono font-semibold text-cyan-400">36,890 flows/s</p>
        </div>
        <div>
          <span className="text-[11px] text-slate-400">Dropped Inactive</span>
          <p className="font-mono font-semibold text-slate-200">0 (Lossless Tap)</p>
        </div>
        <div>
          <span className="text-[11px] text-slate-400">P99 Inference Latency</span>
          <p className="font-mono font-semibold text-emerald-400">4.30 ms</p>
        </div>
      </div>
    </div>
  );
}
