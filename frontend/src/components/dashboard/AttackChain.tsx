"use client";

import React, { useState } from "react";
import { DEMO_ATTACK_CHAIN } from "@/lib/demo-data";
import { AttackChainStory } from "@/lib/types";

export function AttackChain() {
  const chain: AttackChainStory = DEMO_ATTACK_CHAIN;
  const [selectedNodeIndex, setSelectedNodeIndex] = useState<number>(2); // Default to C2 Beacon

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Header */}
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold tracking-tight text-white">
              Attack Chain Intelligence
            </h2>
            <span className="rounded bg-purple-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-purple-400 border border-purple-500/20">
              Temporal Correlation
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-400">
            Automated multi-stage kill-chain reconstruction within 5-minute sliding window
          </p>
        </div>

        {/* Assessment Badge */}
        <div className="flex items-center gap-3 rounded-lg border border-rose-500/30 bg-rose-950/20 px-3 py-1.5">
          <span className="h-2 w-2 rounded-full bg-rose-500 pulse-glow-amber" />
          <div>
            <p className="font-mono text-[11px] font-bold text-rose-400 uppercase">
              {chain.assessment}
            </p>
            <p className="text-[10px] text-slate-400">
              Host: <span className="font-mono text-slate-200">{chain.source_ip}</span> • Conf: <span className="font-mono text-cyan-400">{(chain.overall_confidence * 100).toFixed(0)}%</span>
            </p>
          </div>
        </div>
      </div>

      {/* Reconstructed Multi-Stage Flow Diagram */}
      <div className="mt-6">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {chain.nodes.map((node, index) => {
            const isSelected = selectedNodeIndex === index;
            return (
              <div
                key={node.stage}
                onClick={() => setSelectedNodeIndex(index)}
                className={`cursor-pointer rounded-xl border p-4 transition-all ${
                  isSelected
                    ? "border-cyan-500/60 bg-[#0E1A33] shadow-[0_0_20px_-3px_rgba(56,189,248,0.2)]"
                    : "border-slate-800 bg-[#070D1C] hover:border-slate-700 hover:bg-[#0A1224]"
                }`}
              >
                {/* Stage Header */}
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] font-semibold text-slate-400 uppercase">
                    {node.stage}
                  </span>
                  <span className="font-mono text-[11px] text-slate-400">
                    {node.timestamp}
                  </span>
                </div>

                {/* Threat Class & Badge */}
                <div className="mt-2 flex items-center justify-between">
                  <h3 className="font-mono text-sm font-bold text-white">
                    {node.threat_class}
                  </h3>
                  <span className="rounded bg-cyan-500/10 px-1.5 py-0.2 font-mono text-[11px] font-semibold text-cyan-400 border border-cyan-500/20">
                    {(node.confidence * 100).toFixed(0)}%
                  </span>
                </div>

                {/* Summary */}
                <p className="mt-1.5 text-xs text-slate-300">
                  {node.summary}
                </p>

                {/* Telemetry Feature Indicator */}
                <div className="mt-3 rounded border border-slate-800/80 bg-[#050914] p-2 font-mono text-[10px] text-slate-400">
                  <span className="text-cyan-400">Evidence: </span>
                  {node.indicator}
                </div>

                {/* Arrow indicator for next stage on desktop */}
                {index < chain.nodes.length - 1 && (
                  <div className="mt-2 hidden justify-center text-slate-400 lg:flex">
                    <span>↓</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Deep-Dive Investigation Box for Selected Node */}
      {selectedNodeIndex !== null && (
        <div className="mt-4 rounded-xl border border-slate-800 bg-[#070D1C] p-4 text-xs">
          <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-center border-b border-slate-800/80 pb-2.5">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-semibold text-cyan-400">
                {chain.nodes[selectedNodeIndex].stage}: {chain.nodes[selectedNodeIndex].threat_class} Detailed Attribution
              </span>
              <span className="rounded bg-slate-800 px-1.5 py-0.2 font-mono text-[10px] text-slate-300">
                Host: {chain.source_ip}
              </span>
            </div>
            <span className="font-mono text-slate-400 text-[11px]">
              Observed at {chain.nodes[selectedNodeIndex].timestamp} UTC
            </span>
          </div>

          <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
            <div>
              <span className="text-[11px] text-slate-400">Kill-Chain Role:</span>
              <p className="mt-0.5 text-slate-200 font-medium">{chain.nodes[selectedNodeIndex].summary}</p>
            </div>
            <div>
              <span className="text-[11px] text-slate-400">Telemetry Proof:</span>
              <p className="mt-0.5 font-mono text-cyan-300">{chain.nodes[selectedNodeIndex].indicator}</p>
            </div>
            <div>
              <span className="text-[11px] text-slate-400">Temporal Correlation:</span>
              <p className="mt-0.5 text-emerald-400">Correlated within {chain.time_window}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
