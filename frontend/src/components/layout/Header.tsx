"use client";

import React from "react";
import { ConnectionMode } from "@/lib/types";

interface HeaderProps {
  connectionMode: ConnectionMode;
  lastUpdated: string;
  onRefresh?: () => void;
}

export function Header({ connectionMode, lastUpdated, onRefresh }: HeaderProps) {
  const isLive = connectionMode === "ONLINE";

  return (
    <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-slate-800/80 bg-[#060913]/90 px-6 backdrop-blur-md">
      {/* Brand & Wordmark */}
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400 shadow-[0_0_15px_-3px_rgba(56,189,248,0.25)]">
          <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-lg font-bold tracking-tight text-white">
              Sentinel<span className="text-cyan-400">Flow</span>
            </span>
            <span className="rounded bg-slate-800/80 px-1.5 py-0.5 text-[10px] font-mono font-medium text-slate-400">
              v1.0
            </span>
          </div>
          <p className="text-[11px] font-medium tracking-wide text-slate-400">
            Passive Threat Intelligence
          </p>
        </div>
      </div>

      {/* Center / Right Telemetry Status */}
      <div className="flex items-center gap-3 md:gap-4">
        {/* Sensor Live/Demo Indicator */}
        <div className="flex items-center gap-2 rounded-full border border-slate-800 bg-[#0B1120] px-3 py-1 text-xs">
          <span
            className={`h-2 w-2 rounded-full ${
              isLive ? "bg-emerald-400 pulse-glow-green" : "bg-amber-400 pulse-glow-amber"
            }`}
          />
          <span className="font-mono text-[11px] font-medium tracking-wider text-slate-300 uppercase">
            {isLive ? "SENSOR ONLINE" : "DEMO / REPLAY MODE"}
          </span>
        </div>

        {/* Security Invariant Pills */}
        <div className="hidden items-center gap-1.5 sm:flex">
          <span className="rounded border border-cyan-500/30 bg-cyan-950/30 px-2 py-0.5 font-mono text-[11px] font-medium text-cyan-300">
            READ-ONLY
          </span>
          <span className="rounded border border-slate-700 bg-slate-800/50 px-2 py-0.5 font-mono text-[11px] font-medium text-slate-300">
            ALERT-ONLY
          </span>
        </div>

        {/* Last Updated Timestamp & Refresh Button */}
        <div className="hidden items-center gap-2 text-slate-500 lg:flex">
          <span className="text-xs">Last updated: {lastUpdated}</span>
          {onRefresh && (
            <button
              onClick={onRefresh}
              className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors"
              title="Refresh telemetry"
            >
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
