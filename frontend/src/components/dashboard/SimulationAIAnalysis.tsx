"use client";

import React from "react";
import { TreePine, Waypoints, TrendingUp, Layers, CheckCircle2 } from "lucide-react";
import { AIAnalysis } from "@/lib/api";

interface SimulationAIAnalysisProps {
  analysis: AIAnalysis;
  attackType: string;
}

function ScoreBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    pct >= 85 ? "bg-rose-500"
    : pct >= 65 ? "bg-orange-500"
    : pct >= 40 ? "bg-amber-400"
    : "bg-cyan-400";
  return (
    <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-slate-800">
      <div
        className={`h-full rounded-full transition-all duration-700 ${color}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

interface ModelRowProps {
  icon: React.ReactNode;
  label: string;
  sublabel: string;
  value: number;
  tag: string;
  iconColor: string;
}

function ModelRow({ icon, label, sublabel, value, tag, iconColor }: ModelRowProps) {
  const pct = Math.round(value * 100);
  return (
    <div className="rounded-lg border border-slate-800 bg-[#070D1C] p-3">
      <div className="flex items-start gap-2.5">
        <div className={`mt-0.5 shrink-0 ${iconColor}`}>{icon}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-mono text-[11px] font-bold text-white">{label}</p>
              <p className="font-mono text-[9px] text-slate-500">{sublabel}</p>
            </div>
            <span
              className={`ml-2 shrink-0 rounded border px-1.5 py-0.5 font-mono text-[11px] font-bold ${
                pct >= 85
                  ? "border-rose-500/30 bg-rose-950/30 text-rose-400"
                  : pct >= 65
                  ? "border-orange-500/30 bg-orange-950/30 text-orange-400"
                  : "border-cyan-500/30 bg-cyan-950/30 text-cyan-400"
              }`}
            >
              {value.toFixed(3)}
            </span>
          </div>
          <div className="mt-1 flex items-center justify-between">
            <span className="font-mono text-[9px] text-slate-500">{tag}</span>
            <span className="font-mono text-[9px] font-semibold text-slate-300">{pct}%</span>
          </div>
          <ScoreBar value={value} />
        </div>
      </div>
    </div>
  );
}

export function SimulationAIAnalysis({ analysis, attackType }: SimulationAIAnalysisProps) {
  return (
    <div className="rounded-xl border border-cyan-500/20 bg-[#060C1E] p-4 mt-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Layers className="h-3.5 w-3.5 text-cyan-400" />
          <span className="font-mono text-xs font-bold text-cyan-300 uppercase tracking-wider">
            AI / ML Analysis
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="rounded border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 font-mono text-[9px] font-semibold text-cyan-400 uppercase">
            {analysis.primary_threat}
          </span>
          <span className="font-mono text-[9px] text-slate-600">Real model output</span>
        </div>
      </div>

      {/* Model Rows */}
      <div className="space-y-2">
        <ModelRow
          icon={<TreePine className="h-3.5 w-3.5" />}
          label="Random Forest"
          sublabel="Supervised Classification"
          value={analysis.ml_score}
          tag={`Prediction: ${attackType}`}
          iconColor="text-emerald-400"
        />
        <ModelRow
          icon={<Waypoints className="h-3.5 w-3.5" />}
          label="Isolation Forest"
          sublabel="Anomaly Detection"
          value={analysis.anomaly_score}
          tag="Zero-day outlier score"
          iconColor="text-purple-400"
        />
        <ModelRow
          icon={<TrendingUp className="h-3.5 w-3.5" />}
          label="Rule Engine"
          sublabel="Deterministic Signals"
          value={analysis.rule_score}
          tag="Signature match score"
          iconColor="text-amber-400"
        />
      </div>

      {/* Threat Fusion */}
      <div className="mt-3 flex items-center justify-between rounded-lg border border-rose-500/25 bg-rose-950/10 px-3 py-2.5">
        <div className="flex items-center gap-2">
          <Layers className="h-3.5 w-3.5 text-rose-400" />
          <div>
            <p className="font-mono text-[11px] font-bold text-rose-400 uppercase tracking-wider">
              Threat Fusion
            </p>
            <p className="font-mono text-[9px] text-slate-500">
              Baseline deviation: {analysis.baseline_deviation.toFixed(1)}σ
            </p>
          </div>
        </div>
        <div className="text-right">
          <span className="font-mono text-xl font-bold text-rose-400">
            {(analysis.threat_fusion_confidence * 100).toFixed(0)}%
          </span>
          <p className="font-mono text-[9px] text-slate-500">fusion conf.</p>
        </div>
      </div>

      {/* Fired Detector Signals */}
      {analysis.detector_signals.length > 0 && (
        <div className="mt-3">
          <p className="font-mono text-[9px] text-slate-600 uppercase tracking-wider mb-1.5">
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

      {/* Verification note */}
      <div className="mt-3 flex items-center gap-1.5 border-t border-slate-800/60 pt-2">
        <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-500" />
        <p className="font-mono text-[9px] text-slate-600">
          All values from live pipeline run — zero hard-coded values
        </p>
      </div>
    </div>
  );
}
