"use client";

import React, { useState, useCallback } from "react";
import { ThreatAlert } from "@/lib/types";
import { PcapUploader } from "@/components/dashboard/PcapUploader";
import { LiveNicSniffer } from "@/components/dashboard/LiveNicSniffer";
import { LiveIntelligence } from "@/components/dashboard/LiveIntelligence";

export default function ToolsPage() {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);

  const handleAlerts = useCallback((newAlerts: ThreatAlert[]) => {
    setAlerts((prev) => [...newAlerts, ...prev].slice(0, 30));
  }, []);

  return (
    <div className="mx-auto max-w-7xl px-4 py-6 md:px-8 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">🛠️ Analysis Tools</h1>
        <p className="mt-1 text-sm text-slate-400">
          Analyze captured network traffic files or monitor your live network interface
        </p>
      </div>

      {/* Tool cards info */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/10 p-4">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-2xl">📁</span>
            <div>
              <h2 className="text-sm font-bold text-white">PCAP File Analysis</h2>
              <p className="text-xs text-slate-400">Upload a saved network capture file</p>
            </div>
          </div>
          <ul className="text-xs text-slate-500 space-y-1">
            <li className="flex items-center gap-2"><span className="text-cyan-400">✓</span> Accepts .pcap and .pcapng files</li>
            <li className="flex items-center gap-2"><span className="text-cyan-400">✓</span> AI analyzes every network flow</li>
            <li className="flex items-center gap-2"><span className="text-cyan-400">✓</span> Results appear instantly below</li>
          </ul>
        </div>
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/10 p-4">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-2xl">📡</span>
            <div>
              <h2 className="text-sm font-bold text-white">Live Network Monitor</h2>
              <p className="text-xs text-slate-400">Watch your real network traffic in real time</p>
            </div>
          </div>
          <ul className="text-xs text-slate-500 space-y-1">
            <li className="flex items-center gap-2"><span className="text-emerald-400">✓</span> Select a network interface (NIC)</li>
            <li className="flex items-center gap-2"><span className="text-emerald-400">✓</span> Passive capture — no packets sent</li>
            <li className="flex items-center gap-2"><span className="text-emerald-400">⚠️</span> Requires root/admin permissions</li>
          </ul>
        </div>
      </div>

      {/* Tools side by side */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <PcapUploader onAlertsGenerated={handleAlerts} />
        <LiveNicSniffer onAlertsGenerated={handleAlerts} />
      </div>

      {/* Results feed */}
      {alerts.length > 0 && (
        <div>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-base font-bold text-white">
              🚨 Detected Threats ({alerts.length})
            </h2>
            <button
              onClick={() => setAlerts([])}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
            >
              Clear
            </button>
          </div>
          <LiveIntelligence alerts={alerts} />
        </div>
      )}

      {alerts.length === 0 && (
        <div className="rounded-xl border border-dashed border-slate-700/60 py-12 text-center text-slate-500">
          <div className="text-4xl mb-3">🔍</div>
          <p className="text-sm">Upload a PCAP file or start the live monitor to see results here</p>
        </div>
      )}
    </div>
  );
}
