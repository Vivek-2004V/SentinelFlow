"use client";

import React from "react";
import { TreePine, Waypoints, TrendingUp, Layers, Info } from "lucide-react";

export function MLIntelligence() {
  const models = [
    {
      icon: <TreePine className="h-4 w-4" />,
      iconColor: "text-emerald-400 bg-emerald-950/40 border-emerald-500/30",
      name: "RANDOM FOREST",
      type: "Supervised Classification",
      purpose: "Known Threat Detection",
      badge: "Supervised Model",
      description: "Trained on multi-class network attack vectors from normalized telemetry.",
      metrics: "F1 Score: 0.997 | Validation: 1,048 flows | Unseen Test: 524 flows",
      decisionRole: "Primary signature-guided multi-vector classifier",
    },
    {
      icon: <Waypoints className="h-4 w-4" />,
      iconColor: "text-purple-400 bg-purple-950/40 border-purple-500/30",
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
    { icon: <TrendingUp className="h-3.5 w-3.5" />, name: "Detector Signals",  type: "Entropy, Rate Bounds, Periodicity",    color: "text-slate-300" },
    { icon: <TreePine    className="h-3.5 w-3.5" />, name: "Random Forest",     type: "Supervised Threat Classification",       color: "text-emerald-400" },
    { icon: <Waypoints   className="h-3.5 w-3.5" />, name: "Isolation Forest",  type: "Unsupervised Anomaly Isolation",         color: "text-purple-400" },
    { icon: <TrendingUp  className="h-3.5 w-3.5" />, name: "Adaptive Baseline", type: "Rolling EWMA Host Profiles",             color: "text-cyan-400" },
  ];

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold tracking-tight text-white flex items-center gap-2">
            <Layers className="h-4 w-4 text-cyan-400" />
            AI / ML Intelligence
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            2 Active Machine Learning Models + Deterministic Threat Fusion
          </p>
        </div>
        <span className="rounded border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-400">
          2 Models Active
        </span>
      </div>

      {/* The 2 ML Models */}
      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        {models.map((m) => (
          <div
            key={m.name}
            className="rounded-xl border border-slate-800 bg-[#070D1C] p-4 text-xs flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className={`flex h-7 w-7 items-center justify-center rounded-lg border ${m.iconColor}`}>
                    {m.icon}
                  </div>
                  <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] font-semibold text-slate-300">
                    {m.badge}
                  </span>
                </div>
                <span className="flex items-center gap-1 font-mono text-[10px] text-emerald-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                  Active
                </span>
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

      {/* Fusion Architecture Diagram */}
      <div className="mt-4 rounded-xl border border-slate-800 bg-[#070D1C] p-4">
        <div className="flex items-center justify-between mb-3">
          <span className="font-mono text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Final Intelligence Fusion Architecture
          </span>
          <span className="font-mono text-[10px] text-slate-400">Multi-Signal Triad</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
          {fusionLayers.map((layer, idx) => (
            <div
              key={layer.name}
              className="rounded-lg border border-slate-800/80 bg-[#0A1329] p-2.5 flex flex-col items-center gap-1.5"
            >
              <span className={`text-[9px] font-mono text-slate-500`}>Signal {idx + 1}</span>
              <div className={layer.color}>{layer.icon}</div>
              <p className="font-mono text-xs font-bold text-white leading-tight">{layer.name}</p>
              <p className="text-[9px] text-slate-400 leading-tight">{layer.type}</p>
            </div>
          ))}
        </div>

        {/* Threat Fusion Aggregator */}
        <div className="mt-3 flex flex-col items-center">
          <div className="text-cyan-400 text-xs mb-1">↓</div>
          <div className="w-full rounded-lg border border-cyan-500/40 bg-gradient-to-r from-cyan-950/50 via-[#0A1329] to-cyan-950/50 p-2.5 text-center shadow-inner">
            <div className="flex items-center justify-center gap-2">
              <Layers className="h-3.5 w-3.5 text-cyan-400" />
              <span className="font-mono text-xs font-bold text-cyan-300 tracking-wider">
                THREAT FUSION ENGINE
              </span>
            </div>
            <p className="text-[10px] text-slate-400 mt-0.5">
              Weighted cross-validation · Correlated Kill-Chain Scoring · Explainable Evidence
            </p>
          </div>
        </div>
      </div>

      {/* Security Decision-Making Note */}
      <div className="mt-4 rounded-lg border border-slate-800 bg-[#050914] p-3 text-xs text-slate-400 flex items-start gap-2.5">
        <Info className="h-4 w-4 shrink-0 text-cyan-400 mt-0.5" />
        <p className="leading-relaxed">
          <strong className="text-slate-200">Security Decision-Making Invariant:</strong>{" "}
          LLMs are <strong className="text-amber-300">never</strong> used for primary threat
          detection or verdicts. Any present or future LLM integration serves strictly as a
          read-only natural language explanation layer.
        </p>
      </div>
    </div>
  );
}
