"use client";

import React from "react";
import { ThreatAlert } from "@/lib/types";
import { ForensicExport } from "@/components/dashboard/ForensicExport";

interface AlertDetailProps {
  alert: ThreatAlert | null;
  onClose: () => void;
}

export function AlertDetail({ alert, onClose }: AlertDetailProps) {
  if (!alert) return null;

  const severityColor =
    alert.severity === "CRITICAL"
      ? "bg-rose-500/10 text-rose-400 border-rose-500/30"
      : alert.severity === "HIGH"
      ? "bg-orange-500/10 text-orange-400 border-orange-500/30"
      : alert.severity === "MEDIUM"
      ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
      : "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-2xl rounded-2xl border border-slate-700/80 bg-[#0A1020] p-6 shadow-2xl max-h-[90vh] overflow-y-auto">
        {/* Header with Close */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className={`rounded border px-2 py-0.5 font-mono text-xs font-bold ${severityColor}`}>
                {alert.severity}
              </span>
              <h2 className="font-mono text-lg font-bold text-white tracking-tight">
                {alert.threat_class}
              </h2>
            </div>
            <p className="mt-1 font-mono text-xs text-slate-400">
              Flow ID: <span className="text-slate-200">{alert.flow_id}</span> • Observed: {new Date(alert.timestamp).toUTCString()}
            </p>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg border border-slate-800 p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Core Metadata Grid */}
        <div className="mt-4 grid grid-cols-2 gap-3 rounded-xl border border-slate-800/80 bg-[#060A14] p-4 text-xs sm:grid-cols-4 font-mono">
          <div>
            <span className="text-[10px] text-slate-400 uppercase">Source IP</span>
            <p className="mt-0.5 font-bold text-cyan-300 truncate">{alert.src_ip}</p>
          </div>
          <div>
            <span className="text-[10px] text-slate-400 uppercase">Destination IP</span>
            <p className="mt-0.5 font-bold text-slate-200 truncate">{alert.dst_ip}</p>
          </div>
          <div>
            <span className="text-[10px] text-slate-400 uppercase">Protocol</span>
            <p className="mt-0.5 font-bold text-slate-200">{alert.protocol} {alert.dst_port ? `:${alert.dst_port}` : ""}</p>
          </div>
          <div>
            <span className="text-[10px] text-slate-400 uppercase">Confidence</span>
            <p className="mt-0.5 font-bold text-emerald-400">{(alert.confidence * 100).toFixed(0)}%</p>
          </div>
        </div>

        {/* Explainability Section: Why Was This Detected? */}
        <div className="mt-5">
          <div className="flex items-center gap-2">
            <svg className="h-4 w-4 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
            </svg>
            <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-slate-200">
              Why was this detected? (Explainable Evidence)
            </h3>
          </div>

          <div className="mt-2.5 space-y-2">
            {alert.evidence && alert.evidence.length > 0 ? (
              alert.evidence.map((ev, i) => (
                <div
                  key={i}
                  className="rounded-lg border border-slate-800 bg-[#070D1C] p-3 text-xs"
                >
                  <div className="flex items-center justify-between font-mono">
                    <span className="font-semibold text-cyan-400">{ev.feature}</span>
                    <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[10px] text-slate-300">
                      Value: {String(ev.value)}
                    </span>
                  </div>
                  <p className="mt-1 text-slate-300">{ev.description}</p>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-400 italic">No low-level feature evidence captured.</p>
            )}
          </div>
        </div>

        {/* Attack Chain Progression */}
        {alert.attack_chain && alert.attack_chain.length > 0 && (
          <div className="mt-5">
            <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-slate-200">
              Correlated Attack Chain
            </h3>
            <div className="mt-2 flex flex-wrap items-center gap-2 font-mono text-xs">
              {alert.attack_chain.map((stage, idx) => (
                <React.Fragment key={stage}>
                  <span className="rounded border border-purple-500/30 bg-purple-950/30 px-2.5 py-1 font-semibold text-purple-300">
                    {stage}
                  </span>
                  {idx < alert.attack_chain.length - 1 && (
                    <span className="text-slate-400">→</span>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>
        )}

        {/* Immutable Security Boundary Note */}
        <div className="mt-6 rounded-xl border border-cyan-500/20 bg-cyan-950/20 p-4 text-xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-mono font-bold text-cyan-300 uppercase">
              <svg className="h-4 w-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
              </svg>
              <span>Security Action: {alert.action}</span>
            </div>
            <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-400">
              Detector: {alert.detector}
            </span>
          </div>
          <p className="mt-1.5 text-slate-300">
            SentinelFlow strictly emits passive telemetry alerts. No firewall rules modified, no packets dropped, and zero command execution on target hosts.
          </p>
        </div>

        {/* Close Button + Forensic Export */}
        <div className="mt-6 flex items-center justify-between gap-3">
          <ForensicExport
            report={alert as unknown as Record<string, unknown>}
            filename={`alert_${alert.flow_id}`}
            label="Forensic Export"
          />
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition-colors"
          >
            Dismiss View
          </button>
        </div>
      </div>
    </div>
  );
}
