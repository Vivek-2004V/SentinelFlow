"use client";

import React, { useState } from "react";
import { SeverityLevel, ThreatAlert } from "@/lib/types";
import { AlertDetail } from "../alerts/AlertDetail";

interface LiveIntelligenceProps {
  alerts: ThreatAlert[];
}

function formatAlertTime(timestamp: string): string {
  if (!timestamp) return "--:--";
  if (timestamp.includes("T")) {
    const timePart = timestamp.split("T")[1];
    if (timePart) {
      const parts = timePart.split(":");
      if (parts.length >= 2) {
        return `${parts[0]}:${parts[1]}`;
      }
    }
  }
  return timestamp.slice(0, 5);
}

export function LiveIntelligence({ alerts }: LiveIntelligenceProps) {
  const [filterSeverity, setFilterSeverity] = useState<SeverityLevel | "ALL">("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);

  const filteredAlerts = alerts.filter((a) => {
    if (filterSeverity !== "ALL" && a.severity !== filterSeverity) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        a.threat_class.toLowerCase().includes(q) ||
        a.src_ip.toLowerCase().includes(q) ||
        a.dst_ip.toLowerCase().includes(q) ||
        a.flow_id.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Header & Filter Controls */}
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold tracking-tight text-white">
              Live Threat Intelligence
            </h2>
            <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] font-medium text-slate-300">
              {filteredAlerts.length} Events
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-400">
            Explainable telemetry events processed across passive sensor interfaces
          </p>
        </div>

        {/* Severity Filter Tabs & Search */}
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            placeholder="Filter IP or threat..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="rounded-lg border border-slate-800 bg-[#070D1C] px-3 py-1 font-mono text-xs text-slate-200 placeholder-slate-400 focus:border-cyan-500/50 focus:outline-none"
          />

          <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-[#070D1C] p-1 text-xs">
            {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`rounded px-2 py-1 font-mono text-[10px] font-semibold transition-colors ${
                  filterSeverity === sev
                    ? "bg-slate-700 text-white"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Alert Cards List */}
      <div className="mt-4 space-y-2.5">
        {filteredAlerts.length > 0 ? (
          filteredAlerts.map((alert) => {
            const isCrit = alert.severity === "CRITICAL";
            const isHigh = alert.severity === "HIGH";
            const isMed = alert.severity === "MEDIUM";

            const badgeStyle = isCrit
              ? "bg-rose-500/15 text-rose-400 border-rose-500/30"
              : isHigh
              ? "bg-orange-500/15 text-orange-400 border-orange-500/30"
              : isMed
              ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
              : "bg-cyan-500/15 text-cyan-400 border-cyan-500/30";

            return (
              <div
                key={alert.flow_id}
                onClick={() => setSelectedAlert(alert)}
                className="group flex cursor-pointer flex-col justify-between gap-3 rounded-xl border border-slate-800/80 bg-[#070D1C] p-3.5 transition-all hover:border-slate-700 hover:bg-[#0B1326] sm:flex-row sm:items-center"
              >
                {/* Left Threat Identifier & Source/Dest */}
                <div className="flex items-start gap-3">
                  <div className="mt-0.5">
                    <span className={`inline-block rounded border px-2 py-0.5 font-mono text-[10px] font-bold ${badgeStyle}`}>
                      {alert.severity}
                    </span>
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-white group-hover:text-cyan-400 transition-colors">
                        {alert.threat_class}
                      </span>
                      <span className="font-mono text-[10px] text-slate-400">
                        {alert.flow_id}
                      </span>
                    </div>

                    <div className="mt-1 flex items-center gap-2 text-xs text-slate-300 font-mono">
                      <span className="text-cyan-300">{alert.src_ip}</span>
                      <span className="text-slate-400">→</span>
                      <span className="text-slate-300">{alert.dst_ip}</span>
                      <span className="text-[10px] text-slate-400">({alert.protocol})</span>
                    </div>

                    {/* First Evidence Reason Preview */}
                    {alert.evidence && alert.evidence[0] && (
                      <p className="mt-1 text-[11px] text-slate-400 line-clamp-1">
                        <span className="font-mono text-slate-400">Evidence: </span>
                        {alert.evidence[0].description}
                      </p>
                    )}
                  </div>
                </div>

                {/* Right Metadata & Action */}
                <div className="flex shrink-0 items-center justify-between gap-4 sm:flex-col sm:items-end sm:gap-1">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-cyan-400 border border-cyan-500/20">
                      {(alert.confidence * 100).toFixed(0)}% Conf
                    </span>
                    <span
                      className="font-mono text-[11px] text-slate-400"
                      suppressHydrationWarning={true}
                    >
                      {formatAlertTime(alert.timestamp)}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400 group-hover:text-cyan-400 transition-colors">
                    <span>View Evidence</span>
                    <span>→</span>
                  </div>
                </div>
              </div>
            );
          })
        ) : (
          /* Empty State */
          <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 p-10 text-center">
            <svg className="h-8 w-8 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="mt-2 font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
              No Active Threats Found
            </p>
            <p className="mt-1 max-w-sm text-xs text-slate-400">
              Passive monitoring is active. SentinelFlow is continuously analyzing observed telemetry with 0 alerts matching the current filter.
            </p>
          </div>
        )}
      </div>

      {/* Alert Detail Modal */}
      <AlertDetail
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />
    </div>
  );
}
