"use client";

import React from "react";

export function MLIntelligence() {
  const models = [
    {
      name: "RANDOM FOREST",
      type: "Supervised Classification",
      purpose: "Known Threat Detection",
      badge: "Supervised Model",
      description: "Trained on multi-class network attack vectors from normalized telemetry.",
      metrics: "F1 Score: 0.997 | Validation Set: 1,048 flows | Unseen Test: 524 flows",
      decisionRole: "Primary signature-guided multi-vector classifier",
    },
    {
      name: "ISOLATION FOREST",
      type: "Unsupervised Detection",
      purpose: "Unseen Anomaly Detection",
      badge: "Unsupervised Model",
      description: "Zero-day outlier isolation in high-dimensional feature subspace.",
      metrics: "Outlier Precision: 88.98% | FPR: 13.73% | Contamination: 5%",
      decisionRole: "Zero-day / unknown pattern anomaly detector",
    },
  ];

  const fusionLayers = [
    { name: "Detector Signals", type: "Entropy, Rate Bounds, Periodicity" },
    { name: "Random Forest", type: "Supervised Threat Classification" },
    { name: "Isolation Forest", type: "Unsupervised Anomaly Isolation" },
    { name: "Adaptive Baseline", type: "Rolling EWMA Host Profiles" },
  ];

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold tracking-tight text-white flex items-center gap-2">
            <span className="inline-block h-2 w-2 rounded-full bg-cyan-400"></span>
            AI / ML Intelligence
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Exactly 2 Active Machine Learning Models + Deterministic Threat Fusion
          </p>
        </div>
        <span className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-400 border border-cyan-500/20">
          2 Models Active
        </span>
      </div>

      {/* The 2 ML Models (Step 9.9) */}
      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        {models.map((m) => (
          <div
            key={m.name}
            className="rounded-xl border border-slate-800 bg-[#070D1C] p-4 text-xs flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between">
                <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] font-semibold text-slate-300">
                  {m.badge}
                </span>
                <span className="font-mono text-[10px] text-emerald-400">● Active</span>
              </div>
              <h3 className="mt-2.5 font-mono text-sm font-bold text-white tracking-wide">
                {m.name}
              </h3>
              <p className="text-[11px] font-mono font-medium text-cyan-400">{m.type}</p>
              <div className="mt-2 rounded bg-[#0A1329] p-2 border border-slate-800/80">
                <span className="text-[10px] font-mono uppercase text-slate-400 block mb-0.5">
                  Core Purpose
                </span>
                <p className="text-xs font-medium text-slate-200">{m.purpose}</p>
              </div>
              <p className="mt-2 text-[11px] text-slate-400 leading-relaxed">{m.description}</p>
            </div>
            <div className="mt-3 rounded border border-cyan-500/20 bg-cyan-950/30 px-2.5 py-1.5 font-mono text-[10px] text-cyan-300">
              {m.metrics}
            </div>
          </div>
        ))}
      </div>

      {/* FINAL INTELLIGENCE Threat Fusion Diagram */}
      <div className="mt-4 rounded-xl border border-slate-800 bg-[#070D1C] p-4">
        <div className="flex items-center justify-between mb-3">
          <span className="font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Final Intelligence Fusion Architecture
          </span>
          <span className="font-mono text-[10px] text-slate-400">Multi-Signal Triad</span>
        </div>

        {/* Fusion Nodes Flow */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
          {fusionLayers.map((layer, idx) => (
            <div
              key={layer.name}
              className="rounded-lg border border-slate-800/80 bg-[#0A1329] p-2.5 flex flex-col justify-center items-center"
            >
              <span className="text-[9px] font-mono text-slate-500 mb-1">Signal {idx + 1}</span>
              <p className="font-mono text-xs font-bold text-white">{layer.name}</p>
              <p className="text-[9px] text-slate-400 mt-0.5">{layer.type}</p>
            </div>
          ))}
        </div>

        {/* Threat Fusion Aggregator */}
        <div className="mt-3 flex flex-col items-center">
          <div className="text-cyan-400 font-mono text-xs mb-1">↓</div>
          <div className="w-full rounded-lg border border-cyan-500/40 bg-gradient-to-r from-cyan-950/50 via-[#0A1329] to-cyan-950/50 p-2.5 text-center shadow-inner">
            <span className="font-mono text-xs font-bold text-cyan-300 tracking-wider">
              THREAT FUSION ENGINE
            </span>
            <p className="text-[10px] text-slate-400 mt-0.5">
              Weighted cross-validation • Correlated Kill-Chain Scoring • Explainable Evidence
            </p>
          </div>
        </div>
      </div>

      {/* LLM Boundary Constraint Notice */}
      <div className="mt-4 rounded-lg border border-slate-800 bg-[#050914] p-3 text-xs text-slate-400 flex items-start gap-2.5">
        <svg
          className="h-4 w-4 shrink-0 text-cyan-400 mt-0.5"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth="2"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"
          />
        </svg>
        <p className="leading-relaxed">
          <strong className="text-slate-200">Security Decision-Making Invariant:</strong> LLMs are{" "}
          <strong className="text-amber-300">never</strong> used for primary threat detection or
          verdicts. Any present or future LLM integration serves strictly as a read-only natural
          language explanation layer.
        </p>
      </div>
    </div>
  );
}
