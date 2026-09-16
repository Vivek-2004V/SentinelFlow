"use client";

import React from "react";
import { ConnectionMode, SystemStatusData } from "@/lib/types";

interface SensorStatusProps {
  status: SystemStatusData;
  mode: ConnectionMode;
}

export function SensorStatus({ status, mode }: SensorStatusProps) {
  const isOnline = mode === "ONLINE";

  const rows = [
    { label: "Sensor Ingest", value: status.ingest_mode.toUpperCase(), ok: true },
    { label: "Execution Mode", value: status.response_mode.toUpperCase(), ok: true },
    { label: "Payload Decryption", value: status.payload_decryption ? "ENABLED" : "DISABLED", ok: !status.payload_decryption },
    { label: "Network Return Path", value: status.return_path ? "ENABLED" : "DISABLED", ok: !status.return_path },
    { label: "Backend API Bridge", value: isOnline ? "CONNECTED (8000)" : "REPLAY BRIDGE", ok: isOnline },
    { label: "Active TAP Interface", value: status.active_sensor || "TAP-01-CORE-NORTH", ok: true },
  ];

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold tracking-tight text-white">
            Sensor & System Health
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Hardware interface and boundary validation
          </p>
        </div>
        <span
          className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
            isOnline
              ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
              : "bg-amber-500/15 text-amber-400 border border-amber-500/30"
          }`}
        >
          {isOnline ? (
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              SENSOR ONLINE
            </span>
          ) : (
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
              DEMO REPLAY
            </span>
          )}
        </span>
      </div>

      {/* Grid of System Attributes */}
      <div className="mt-4 grid grid-cols-2 gap-2.5 sm:grid-cols-3">
        {rows.map((row) => (
          <div
            key={row.label}
            className="rounded-lg border border-slate-800 bg-[#070D1C] p-2.5 text-xs"
          >
            <span className="text-[10px] text-slate-400 uppercase font-mono">{row.label}</span>
            <p className="mt-1 font-mono font-bold text-slate-200 truncate">
              {row.value}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}
