"use client";

import React from "react";
import { Check, X, Lock } from "lucide-react";

export function SecurityBoundary() {
  const capabilities = [
    "Passive flow observation",
    "Non-invasive metadata extraction",
    "Multi-class threat detection",
    "Explainable evidence attribution",
    "Standardized security alerts",
  ];

  const restrictions = [
    "No active host probing",
    "No port scanning or ping injection",
    "No TLS payload decryption",
    "No automated blocking or drops",
    "No mitigation / firewall modification",
    "Strictly zero return path to network",
  ];

  return (
    <div className="glass-panel relative overflow-hidden rounded-xl p-5 shadow-sm">
      {/* Background Decorative Gradient */}
      <div className="pointer-events-none absolute -right-12 -top-12 h-40 w-40 rounded-full bg-cyan-500/5 blur-3xl" />

      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400 shadow-[0_0_15px_-3px_rgba(56,189,248,0.3)]">
          <Lock className="h-4 w-4" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold tracking-tight text-white">
              Passive Security Boundary
            </h2>
            <span className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-cyan-400 border border-cyan-500/20">
              One-Way Optical TAP
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-400">
            Guaranteed physical &amp; logical isolation with read-only monitoring architecture
          </p>
        </div>
      </div>

      {/* Two-Column Comparison Grid */}
      <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* Positive Capabilities */}
        <div className="rounded-xl border border-emerald-500/20 bg-[#061215]/80 p-4">
          <div className="flex items-center gap-2 border-b border-emerald-500/20 pb-2">
            <span className="flex h-4 w-4 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-400">
              <Check className="h-2.5 w-2.5 stroke-[3]" />
            </span>
            <span className="font-mono text-xs font-bold text-emerald-300 uppercase tracking-wider">
              Enforced Capabilities
            </span>
          </div>
          <ul className="mt-2.5 space-y-1.5 text-xs text-slate-300">
            {capabilities.map((cap) => (
              <li key={cap} className="flex items-center gap-2">
                <Check className="h-3 w-3 shrink-0 text-emerald-400 stroke-[2.5]" />
                <span>{cap}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Explicit Architectural Restrictions */}
        <div className="rounded-xl border border-rose-500/20 bg-[#160A10]/80 p-4">
          <div className="flex items-center gap-2 border-b border-rose-500/20 pb-2">
            <span className="flex h-4 w-4 items-center justify-center rounded-full bg-rose-500/20 text-rose-400">
              <X className="h-2.5 w-2.5 stroke-[3]" />
            </span>
            <span className="font-mono text-xs font-bold text-rose-300 uppercase tracking-wider">
              Strict Non-Interference Restrictions
            </span>
          </div>
          <ul className="mt-2.5 space-y-1.5 text-xs text-slate-300">
            {restrictions.map((res) => (
              <li key={res} className="flex items-center gap-2">
                <X className="h-3 w-3 shrink-0 text-rose-400 stroke-[2.5]" />
                <span>{res}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
