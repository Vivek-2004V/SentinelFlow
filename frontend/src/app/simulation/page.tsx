"use client";

import React, { useState, useCallback } from "react";
import { AttackSimulationLab } from "@/components/dashboard/AttackSimulationLab";
import { ThreatAlert } from "@/lib/types";
import { AIQualityGate } from "@/components/dashboard/AIQualityGate";

const ATTACK_EXPLAINERS = [
  {
    id: "c2_beacon",
    icon: "🕵️",
    name: "C2 Beacon",
    color: "border-orange-500/30 bg-orange-950/15",
    badge: "text-orange-300 bg-orange-950/40 border-orange-500/30",
    what: "What is it?",
    desc: "A Command & Control beacon is malware regularly 'phoning home' to its controller. The AI detects the regular timing pattern (beaconing interval) that humans would miss.",
    detects: ["Regular time intervals", "Unusual destination IPs", "Low data volume pattern"],
  },
  {
    id: "ddos",
    icon: "💥",
    name: "DDoS Flood",
    color: "border-rose-500/30 bg-rose-950/15",
    badge: "text-rose-300 bg-rose-950/40 border-rose-500/30",
    what: "What is it?",
    desc: "A Distributed Denial of Service attack floods a server with traffic to make it unavailable. The AI detects sudden spikes in packet volume from many sources.",
    detects: ["High packets per second", "Many source IPs", "Same destination port"],
  },
  {
    id: "recon",
    icon: "🔍",
    name: "Reconnaissance",
    color: "border-cyan-500/30 bg-cyan-950/15",
    badge: "text-cyan-300 bg-cyan-950/40 border-cyan-500/30",
    what: "What is it?",
    desc: "Reconnaissance is an attacker scanning your network to find open ports and services before launching a real attack. The AI spots sequential port access patterns.",
    detects: ["Sequential port numbers", "Short connection durations", "SYN packets without ACK"],
  },
  {
    id: "dns_tunnel",
    icon: "🌐",
    name: "DNS Tunnel",
    color: "border-purple-500/30 bg-purple-950/15",
    badge: "text-purple-300 bg-purple-950/40 border-purple-500/30",
    what: "What is it?",
    desc: "DNS Tunneling hides data inside DNS queries to bypass firewalls. The AI detects abnormally long or high-entropy DNS query names that no real website uses.",
    detects: ["High entropy domain names", "Unusually long subdomains", "High DNS query frequency"],
  },
  {
    id: "exfil",
    icon: "📤",
    name: "Data Exfiltration",
    color: "border-amber-500/30 bg-amber-950/15",
    badge: "text-amber-300 bg-amber-950/40 border-amber-500/30",
    what: "What is it?",
    desc: "Data exfiltration is when stolen data is sent outside your network. The AI detects unusually large outbound data transfers to unknown external IPs.",
    detects: ["Large outbound bytes", "Unknown destination IPs", "Off-hours transfers"],
  },
  {
    id: "dga",
    icon: "🎲",
    name: "DGA Domains",
    color: "border-emerald-500/30 bg-emerald-950/15",
    badge: "text-emerald-300 bg-emerald-950/40 border-emerald-500/30",
    what: "What is it?",
    desc: "Domain Generation Algorithms create random-looking domain names for malware to connect to. The AI uses an n-gram ML model to detect these nonsense domain names.",
    detects: ["Random-looking domains", "High character entropy", "No real dictionary words"],
  },
];

export default function SimulationPage() {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [selectedAttack, setSelectedAttack] = useState<string | null>(null);

  const handleAlerts = useCallback((newAlerts: ThreatAlert[]) => {
    setAlerts((prev) => [...newAlerts, ...prev].slice(0, 20));
  }, []);

  const latestAlert = alerts[0];

  return (
    <div className="mx-auto max-w-7xl px-4 py-6 md:px-8 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">🧪 Attack Demo Lab</h1>
        <p className="mt-1 text-sm text-slate-400">
          Simulate real cyberattacks and watch the AI detect them in real time. No real traffic is sent — this is 100% simulated.
        </p>
      </div>

      {/* How to use banner */}
      <div className="rounded-xl border border-slate-700/60 bg-slate-800/30 px-5 py-4">
        <p className="text-sm font-semibold text-slate-300 mb-3">📋 How to use this page:</p>
        <div className="flex flex-wrap gap-4 text-sm text-slate-400">
          <span className="flex items-center gap-2">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-700 text-xs font-bold text-slate-200">1</span>
            Read about an attack type below
          </span>
          <span className="text-slate-600">→</span>
          <span className="flex items-center gap-2">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-700 text-xs font-bold text-slate-200">2</span>
            Use the simulation panel to run it
          </span>
          <span className="text-slate-600">→</span>
          <span className="flex items-center gap-2">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-700 text-xs font-bold text-slate-200">3</span>
            See the AI detection result appear
          </span>
        </div>
      </div>

      {/* Main: Attack types explainer + Simulation panel */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Attack type explainers */}
        <div>
          <h2 className="mb-4 text-base font-bold text-white">Understanding Each Attack</h2>
          <div className="space-y-3">
            {ATTACK_EXPLAINERS.map((a) => (
              <button
                key={a.id}
                onClick={() => setSelectedAttack(selectedAttack === a.id ? null : a.id)}
                className={`w-full rounded-xl border p-4 text-left transition-all ${a.color} ${
                  selectedAttack === a.id ? "ring-2 ring-cyan-500/40" : "hover:brightness-110"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{a.icon}</span>
                    <div>
                      <span className="text-sm font-bold text-white">{a.name}</span>
                    </div>
                  </div>
                  <svg
                    className={`h-4 w-4 text-slate-400 transition-transform ${selectedAttack === a.id ? "rotate-180" : ""}`}
                    fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
                {selectedAttack === a.id && (
                  <div className="mt-3 border-t border-slate-700/40 pt-3 space-y-2">
                    <p className="text-xs text-slate-300 leading-relaxed">{a.desc}</p>
                    <div>
                      <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide mb-1">AI detects:</p>
                      <ul className="space-y-1">
                        {a.detects.map((d) => (
                          <li key={d} className="flex items-center gap-2 text-xs text-slate-400">
                            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 shrink-0" />
                            {d}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Simulation panel + result */}
        <div className="space-y-4">
          <AttackSimulationLab onAlertsGenerated={handleAlerts} />

          {/* Detection Result */}
          {latestAlert && (
            <div className={`rounded-xl border p-4 ${
              latestAlert.severity === "CRITICAL" ? "border-rose-500/40 bg-rose-950/20" :
              latestAlert.severity === "HIGH" ? "border-orange-500/40 bg-orange-950/20" :
              "border-amber-500/40 bg-amber-950/20"
            }`}>
              <div className="flex items-center gap-2 mb-3">
                <span className="text-lg">
                  {latestAlert.severity === "CRITICAL" ? "🔴" : latestAlert.severity === "HIGH" ? "🟠" : "🟡"}
                </span>
                <span className="font-bold text-white">AI Detection Result</span>
                <span className={`ml-auto rounded px-2 py-0.5 text-xs font-bold border ${
                  latestAlert.severity === "CRITICAL" ? "text-rose-300 border-rose-500/30 bg-rose-950/40" :
                  latestAlert.severity === "HIGH" ? "text-orange-300 border-orange-500/30 bg-orange-950/40" :
                  "text-amber-300 border-amber-500/30 bg-amber-950/40"
                }`}>{latestAlert.severity}</span>
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-400">Attack Type</span>
                  <span className="font-semibold text-white">{latestAlert.threat_class?.replace("_", " ")}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Confidence</span>
                  <span className="font-semibold text-emerald-400">{Math.round((latestAlert.confidence ?? 0.85) * 100)}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Source IP</span>
                  <span className="font-mono text-xs text-slate-300">{latestAlert.src_ip}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Destination</span>
                  <span className="font-mono text-xs text-slate-300">{latestAlert.dst_ip}:{latestAlert.dst_port}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* AI Quality Gate */}
      <AIQualityGate />
    </div>
  );
}
