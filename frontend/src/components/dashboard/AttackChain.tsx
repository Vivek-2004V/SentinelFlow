"use client";

import React, { useState } from "react";
import { DEMO_ATTACK_CHAIN } from "@/lib/demo-data";
import { AttackChainStory } from "@/types";

interface AttackChainProps {
  chainStory?: AttackChainStory;
}

export function AttackChain({ chainStory }: AttackChainProps) {
  const chain: AttackChainStory = chainStory || DEMO_ATTACK_CHAIN;
  const [selectedNodeIndex, setSelectedNodeIndex] = useState<number>(1); // Default to C2 BEACON

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Header */}
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold tracking-tight text-white">
              Multi-Stage Attack Chain Correlation
            </h2>
            <span className="rounded bg-purple-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-purple-400 border border-purple-500/20">
              Temporal Sliding Window
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-400">
            Automated correlation across same source IP within a bounded 5-minute sliding window
          </p>
        </div>

        {/* Assessment Status Pill */}
        <div className="flex items-center gap-2.5 rounded-lg border border-rose-500/30 bg-rose-950/20 px-3 py-1.5">
          <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
          <div>
            <p className="font-mono text-[11px] font-bold text-rose-400 uppercase">
              {chain.assessment || "LIKELY_COMPROMISED_HOST"}
            </p>
            <p className="text-[10px] text-slate-400">
              Severity: <strong className="text-rose-300">{chain.severity}</strong> • Action: <strong className="text-cyan-400">ALERT_ONLY</strong>
            </p>
          </div>
        </div>
      </div>

      {/* Main Content Layout: Flow Nodes Sequence + Sidebar Intelligence */}
      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-4">
        {/* Left 3 Columns: Connected Stage Sequence */}
        <div className="space-y-3 lg:col-span-3">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {chain.nodes.slice(0, 3).map((node, index) => {
              const isSelected = selectedNodeIndex === index;
              const isLast = index === 2 || index === chain.nodes.length - 1;

              return (
                <div key={node.stage} className="relative flex flex-col justify-between">
                  <div
                    onClick={() => setSelectedNodeIndex(index)}
                    className={`h-full cursor-pointer rounded-xl border p-4 transition-all ${
                      isSelected
                        ? "border-cyan-500/60 bg-[#0E1A33] shadow-[0_0_20px_-3px_rgba(56,189,248,0.25)]"
                        : "border-slate-800 bg-[#070D1C] hover:border-slate-700 hover:bg-[#0A1224]"
                    }`}
                  >
                    {/* Stage Header */}
                    <div className="flex items-center justify-between">
                      <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[9px] font-bold text-slate-300 uppercase">
                        Stage {index + 1}: {node.stage}
                      </span>
                      <span className="font-mono text-[10px] text-slate-400">
                        {node.timestamp}
                      </span>
                    </div>

                    {/* Threat Class Title */}
                    <div className="mt-2.5 flex items-center justify-between">
                      <h3 className="font-mono text-sm font-bold text-white tracking-tight">
                        {node.threat_class}
                      </h3>
                      <span className="rounded bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[10px] font-bold text-cyan-400 border border-cyan-500/20">
                        {(node.confidence * 100).toFixed(0)}% Conf
                      </span>
                    </div>

                    {/* Summary Description */}
                    <p className="mt-1.5 text-xs text-slate-300 line-clamp-2 leading-relaxed">
                      {node.summary}
                    </p>

                    {/* Telemetry Evidence Pill */}
                    <div className="mt-3 rounded border border-slate-800/80 bg-[#050914] p-2 font-mono text-[10px] text-slate-400">
                      <span className="text-cyan-400 font-semibold">Evidence: </span>
                      <span className="text-slate-300">{node.indicator}</span>
                    </div>
                  </div>

                  {/* Flow Arrow Between Nodes (Desktop Horizontal / Mobile Vertical) */}
                  {!isLast && (
                    <div className="hidden sm:flex absolute -right-2.5 top-1/2 -translate-y-1/2 z-10 items-center justify-center h-5 w-5 rounded-full bg-slate-800 border border-slate-700 text-[10px] font-bold text-cyan-400">
                      →
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Selected Stage Detail Drawer */}
          {selectedNodeIndex !== null && chain.nodes[selectedNodeIndex] && (
            <div className="rounded-xl border border-slate-800 bg-[#070D1C] p-4 text-xs">
              <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-center border-b border-slate-800/80 pb-2.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-cyan-400">
                    {chain.nodes[selectedNodeIndex].stage} → {chain.nodes[selectedNodeIndex].threat_class}
                  </span>
                  <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">
                    Host: {chain.source_ip}
                  </span>
                </div>
                <span className="font-mono text-slate-400 text-[11px]">
                  Observed at {chain.nodes[selectedNodeIndex].timestamp}
                </span>
              </div>

              <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-mono">Tactic Progression</span>
                  <p className="mt-0.5 text-slate-200 font-medium">{chain.nodes[selectedNodeIndex].summary}</p>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-mono">Statistical Proof</span>
                  <p className="mt-0.5 font-mono text-cyan-300">{chain.nodes[selectedNodeIndex].indicator}</p>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase font-mono">Temporal Bound</span>
                  <p className="mt-0.5 font-mono text-emerald-400">Correlated within {chain.time_window}</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right 1 Column: Correlation Summary Sidebar */}
        <div className="flex flex-col justify-between rounded-xl border border-slate-800 bg-[#070D1C] p-4 font-mono text-xs">
          <div className="space-y-4">
            <div>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">
                Chain Confidence
              </span>
              <p className="mt-1 text-2xl font-bold text-cyan-400">
                {(chain.overall_confidence * 100).toFixed(0)}%
              </p>
              <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-cyan-400 transition-all duration-500"
                  style={{ width: `${chain.overall_confidence * 100}%` }}
                />
              </div>
            </div>

            <div className="border-t border-slate-800/80 pt-3">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">
                Correlated Source IP
              </span>
              <p className="mt-1 text-sm font-bold text-white truncate">
                {chain.source_ip}
              </p>
              <p className="text-[10px] text-slate-400">Internal Enclave Node</p>
            </div>

            <div className="border-t border-slate-800/80 pt-3">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">
                Time Window
              </span>
              <p className="mt-1 text-sm font-bold text-amber-300">
                {chain.time_window || "4m 32s"}
              </p>
              <p className="text-[10px] text-slate-400">Bounded Sliding Window</p>
            </div>

            <div className="border-t border-slate-800/80 pt-3">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">
                Target Objective
              </span>
              <p className="mt-1 text-xs font-bold text-slate-200">
                {chain.target_ip}
              </p>
            </div>
          </div>

          {/* Security Action Guardrail */}
          <div className="mt-4 rounded-lg border border-cyan-500/20 bg-cyan-950/20 p-2.5 text-[10px] text-slate-300">
            <span className="font-bold text-cyan-300 uppercase">Action: ALERT_ONLY</span>
            <p className="mt-0.5 text-slate-400">Passive SOC intelligence without active mitigation.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
