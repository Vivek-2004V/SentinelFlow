"use client";

import React from "react";
import { ConnectionMode } from "@/lib/types";

interface HeaderProps {
  connectionMode: ConnectionMode;
  lastUpdated: string;
  apiConnected?: boolean;
  isLoading?: boolean;
  onRefresh?: () => void;
}

export function Header({
  connectionMode,
  lastUpdated,
  apiConnected = true,
  isLoading = false,
  onRefresh,
}: HeaderProps) {
  const isOnline = connectionMode === "ONLINE";

  return (
    <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-slate-800/80 bg-[#060913]/90 px-4 md:px-6 backdrop-blur-md">
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
              SOC v1.0
            </span>
          </div>
          <p className="text-[11px] font-medium tracking-wide text-slate-400">
            Passive Threat Intelligence
          </p>
        </div>
      </div>

      {/* Center / Right Telemetry Status */}
      <div className="flex items-center gap-2.5 md:gap-4">
        {/* Replay / Ingest Mode Badge */}
        <div className="flex items-center gap-2 rounded-full border border-slate-800 bg-[#0B1120] px-3 py-1 text-xs">
          <span
            className={`h-2 w-2 rounded-full ${
              isOnline
                ? "bg-emerald-400 animate-pulse"
                : "bg-amber-400 animate-pulse"
            }`}
          />
          <div className="flex items-center gap-1.5 font-mono text-[11px] font-medium tracking-wider">
            <span className={isOnline ? "text-emerald-300" : "text-amber-300"}>
              {isOnline ? "● LIVE TAP INGRESS" : "● REPLAY MODE"}
            </span>
            {!isOnline && (
              <span className="hidden sm:inline text-slate-500 font-mono text-[10px]">
                (Source: demo_flows.csv)
              </span>
            )}
          </div>
        </div>

        {/* API Connectivity Status */}
        <div className="hidden lg:flex items-center gap-1.5 rounded-md border border-slate-800/80 bg-[#070D1C] px-2.5 py-1 text-[11px] font-mono">
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              apiConnected ? "bg-emerald-400" : "bg-rose-500 animate-ping"
            }`}
          />
          <span className={apiConnected ? "text-slate-300" : "text-rose-400"}>
            {apiConnected ? "API CONNECTED" : "API OFFLINE"}
          </span>
        </div>

        {/* Security Invariant Badges */}
        <div className="hidden md:flex items-center gap-1.5">
          <span className="rounded border border-cyan-500/30 bg-cyan-950/30 px-2 py-0.5 font-mono text-[11px] font-medium text-cyan-300">
            READ-ONLY
          </span>
          <span className="rounded border border-slate-700 bg-slate-800/50 px-2 py-0.5 font-mono text-[11px] font-medium text-slate-300">
            ALERT-ONLY
          </span>
        </div>

        {/* Last Updated Timestamp & Refresh Button */}
        <div className="flex items-center gap-2 text-slate-500">
          <span className="hidden xl:inline text-xs font-mono" suppressHydrationWarning={true}>
            {isLoading ? "Syncing..." : `Updated: ${lastUpdated}`}
          </span>
          {onRefresh && (
            <button
              onClick={onRefresh}
              disabled={isLoading}
              className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200 transition-colors disabled:opacity-50"
              title="Poll backend telemetry"
            >
              <svg
                className={`h-3.5 w-3.5 ${isLoading ? "animate-spin text-cyan-400" : ""}`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
