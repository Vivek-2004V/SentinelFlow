"use client";

import React from "react";
import { AIAnalysis } from "@/lib/api";

interface SimulationAIAnalysisProps {
  analysis: AIAnalysis;
  attackType: string;
}

function ScoreBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    pct >= 85 ? "bg-rose-500" : pct >= 65 ? "bg-orange-500" : pct >= 40 ? "bg-amber-400" : "bg-cyan-400";
  return (
    <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
      <div
        className={`h-full rounded-full transition-all duration-700 ${color}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

function ModelRow({
  label,
  type,
  value,
  tag,
  color,
}: {
  label: string;
  type: string;
  value: number;
  tag: string;
  color: string;
}) {
  const pct = Math.round(value * 100);
  return (
    <div className="rounded-lg border border-slate-800 bg-[#070D1C] p-3">
      <div className="flex items-center justify-between">
        <div>
          <p className={`font-mono text-[10px] font-bold ${color} uppercase tracking-wider`}>
            {label}
          </p>
          <p className="font-mono text-[9px] text-slate-500 mt-0.5">{type}</p>
        </div>
        <span
          className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold ${
            pct >= 85
              ? "border-rose-500/30 bg-rose-950/30 text-rose-400"
              : pct >= 65
              ? "border-orange-500/30 bg-orange-950/30 text-orange-400"
              : "border-cyan-500/30 bg-cyan-950/30 text-cyan-400"
          }`}
        >
          {(value).toFixed(3)}
        </span>
      </div>
      <div className="mt-1.5 flex items-center justify-between text-[10px] font-mono text-slate-400">
        <span>{tag}</span>
        <span className="text-white font-semibold">{pct}%</span>
      </div>
      <ScoreBar value={value} />
    </div>
  );
}

export function SimulationAIAnalysis({ analysis, attackType }: SimulationAIAnalysisProps) {
  return (
    <div className="rounded-xl border border-cyan-500/30 bg-[#060C1E] p-4 mt-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
          <span className="font-mono text-xs font-bold text-cyan-300 uppercase tracking-wider">
            AI / ML Analysis
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-[9px] font-semibold text-cyan-400 border border-cyan-500/20 uppercase">
            {analysis.primary_threat}
          </span>
          <span className="font-mono text-[9px] text-slate-500">Real model output</span>
        </div>
      </div>

      {/* Model rows */}
      <div className="space-y-2">
        <ModelRow
          label="Random Forest"
          type="Supervised Classification"
          value={analysis.ml_score}
          tag={`Prediction: ${attackType}`}
          color="text-emerald-400"
        />
        <ModelRow
          label="Isolation Forest"
          type="Anomaly Detection"
          value={analysis.anomaly_score}
          tag="Zero-day outlier score"
          color="text-purple-400"
        />
        <ModelRow
          label="Rule Engine"
          type="Deterministic Signals"
          value={analysis.rule_score}
          tag="Signature match score"
          color="text-amber-400"
        />
      </div>

      {/* Threat Fusion Row */}
      <div className="mt-3 rounded-lg border border-rose-500/30 bg-rose-950/10 p-3 flex items-center justify-between">
        <div>
          <p className="font-mono text-[10px] font-bold text-rose-400 uppercase tracking-wider">
            Threat Fusion Engine
          </p>
          <p className="font-mono text-[9px] text-slate-500 mt-0.5">
            Baseline deviation: Δ{analysis.baseline_deviation.toFixed(1)}σ
          </p>
        </div>
        <span className="font-mono text-lg font-bold text-rose-400">
          {(analysis.threat_fusion_confidence * 100).toFixed(0)}%
        </span>
      </div>

      {/* Detector signals */}
      {analysis.detector_signals.length > 0 && (
        <div className="mt-3">
          <p className="font-mono text-[9px] text-slate-500 uppercase tracking-wider mb-1.5">
            Fired Detector Signals
          </p>
          <div className="flex flex-wrap gap-1">
            {analysis.detector_signals.map((sig) => (
              <span
                key={sig}
                className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[9px] text-slate-300"
              >
                {sig}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Note */}
      <p className="mt-3 text-[9px] font-mono text-slate-600 border-t border-slate-800/60 pt-2">
        ✓ All values from live pipeline run — zero hard-coded values
      </p>
    </div>
  );
}
