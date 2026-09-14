"use client";

import React from "react";

export function MLIntelligence() {
  const models = [
    {
      name: "Random Forest Classifier",
      type: "Supervised Ensemble (200 Trees)",
      purpose: "Multi-class classification across 7 known threat vectors",
      badge: "Supervised ML",
    },
    {
      name: "Isolation Forest Detector",
      type: "Unsupervised Tree Isolation (200 Trees)",
      purpose: "Zero-day & novel anomalous behavioral outlier detection",
      badge: "Unsupervised ML",
    },
  ];

  const statisticalSignals = [
    { name: "Shannon DNS Entropy", desc: "Pseudorandom DGA detection" },
    { name: "Periodicity Autocorrelation", desc: "C2 beacon regular interval tracking" },
    { name: "Traffic Rate Bounds", desc: "Volumetric PPS / BPS surges" },
    { name: "Fan-Out Dispersion", desc: "Recon horizontal & vertical scanning" },
    { name: "Byte Ratio Asymmetry", desc: "Exfiltration upload/download deviation" },
    { name: "Adaptive Baseline Z-Score", desc: "Dynamic rolling per-host behavior model" },
  ];

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold tracking-tight text-white">
            Dual AI/ML & Statistical Intelligence
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Hybrid Triad: Deterministic Signatures + 2 Machine Learning Models + Online Baselines
          </p>
        </div>
        <span className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-400 border border-cyan-500/20">
          2 AI Models Active
        </span>
      </div>

      {/* Two Active AI/ML Models */}
      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        {models.map((m) => (
          <div
            key={m.name}
            className="rounded-xl border border-slate-800 bg-[#070D1C] p-3.5 text-xs"
          >
            <div className="flex items-center justify-between">
              <span className="rounded bg-slate-800 px-1.5 py-0.2 font-mono text-[10px] font-semibold text-slate-300">
                {m.badge}
              </span>
              <span className="font-mono text-[10px] text-emerald-400">● Loaded in Memory</span>
            </div>
            <h3 className="mt-2 font-mono text-sm font-bold text-white">{m.name}</h3>
            <p className="mt-0.5 text-[11px] text-cyan-400 font-mono">{m.type}</p>
            <p className="mt-1.5 text-slate-400">{m.purpose}</p>
          </div>
        ))}
      </div>

      {/* Deterministic Statistical Signals Grid */}
      <div className="mt-4 border-t border-slate-800/80 pt-3">
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Deterministic Statistical Signals (Non-AI Mathematical Heuristics)
          </span>
        </div>
        <div className="mt-2.5 grid grid-cols-2 gap-2 sm:grid-cols-3">
          {statisticalSignals.map((sig) => (
            <div
              key={sig.name}
              className="rounded-lg border border-slate-800/60 bg-[#060A14] p-2 text-xs"
            >
              <p className="font-mono text-[11px] font-semibold text-slate-200">{sig.name}</p>
              <p className="text-[10px] text-slate-400">{sig.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Architectural Guarantee Note */}
      <div className="mt-4 rounded-lg border border-slate-800 bg-[#050914] p-3 text-xs text-slate-400 flex items-start gap-2.5">
        <svg className="h-4 w-4 shrink-0 text-cyan-400 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
        </svg>
        <p className="leading-relaxed">
          <strong className="text-slate-200">Architectural Note:</strong> Primary threat detection, telemetry scoring, and attack-chain assessment are purely statistical and deterministic; security decisioning is never delegated to an LLM.
        </p>
      </div>
    </div>
  );
}
