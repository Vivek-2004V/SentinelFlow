"use client";

import React, { useState, useCallback } from "react";
import {
  AttackType,
  SimulateResult,
  runSimulation,
  runAttackChain,
} from "@/lib/api";
import { ThreatAlert } from "@/types";
import { SimulationAIAnalysis } from "./SimulationAIAnalysis";

// ─── Types ────────────────────────────────────────────────────────────────────

interface AttackOption {
  id: AttackType;
  label: string;
  shortLabel: string;
  icon: string;
  desc: string;
  color: string;
  bgColor: string;
  borderColor: string;
}

type SimStatus = "idle" | "running" | "success" | "error";

interface LogEntry {
  time: string;
  msg: string;
  type: "info" | "success" | "warn" | "data";
}

interface AttackSimulationLabProps {
  onAlertsGenerated?: (alerts: ThreatAlert[]) => void;
}

// ─── Attack Definitions ───────────────────────────────────────────────────────

const ATTACK_OPTIONS: AttackOption[] = [
  {
    id: "DDOS",
    label: "DDoS Flood",
    shortLabel: "DDoS",
    icon: "⚡",
    desc: "52K pps · 5.2 MB/s · UDP flood",
    color: "text-rose-400",
    bgColor: "bg-rose-950/30",
    borderColor: "border-rose-500/40",
  },
  {
    id: "C2_BEACON",
    label: "C2 Beacon",
    shortLabel: "C2",
    icon: "📡",
    desc: "300s interval · low IAT variance",
    color: "text-orange-400",
    bgColor: "bg-orange-950/30",
    borderColor: "border-orange-500/40",
  },
  {
    id: "DGA",
    label: "DGA Domain",
    shortLabel: "DGA",
    icon: "🔀",
    desc: "High entropy DNS · digit ratio elevated",
    color: "text-purple-400",
    bgColor: "bg-purple-950/30",
    borderColor: "border-purple-500/40",
  },
  {
    id: "DNS_TUNNEL",
    label: "DNS Tunnel",
    shortLabel: "DNS-T",
    icon: "🌀",
    desc: "Encoded subdomain chain · 64-char label",
    color: "text-indigo-400",
    bgColor: "bg-indigo-950/30",
    borderColor: "border-indigo-500/40",
  },
  {
    id: "RECON",
    label: "Recon Sweep",
    shortLabel: "Recon",
    icon: "🔍",
    desc: "Port sweep 1–1024 · 1200 packets",
    color: "text-amber-400",
    bgColor: "bg-amber-950/30",
    borderColor: "border-amber-500/40",
  },
  {
    id: "EXFIL",
    label: "Data Exfil",
    shortLabel: "Exfil",
    icon: "💾",
    desc: "85 MB outbound · upload ratio 0.99",
    color: "text-cyan-400",
    bgColor: "bg-cyan-950/30",
    borderColor: "border-cyan-500/40",
  },
];

// Full attack chain sequence for display
const CHAIN_STAGES = [
  { id: "RECON", label: "RECON", color: "text-amber-400", dotColor: "bg-amber-400" },
  { id: "DGA", label: "DGA", color: "text-purple-400", dotColor: "bg-purple-400" },
  { id: "C2_BEACON", label: "C2 BEACON", color: "text-orange-400", dotColor: "bg-orange-400" },
  { id: "EXFIL", label: "EXFIL", color: "text-rose-400", dotColor: "bg-rose-400" },
];

// ─── Severity colors ──────────────────────────────────────────────────────────

function severityStyle(sev: string) {
  switch (sev) {
    case "CRITICAL":
      return "bg-rose-500/15 text-rose-400 border-rose-500/30";
    case "HIGH":
      return "bg-orange-500/15 text-orange-400 border-orange-500/30";
    case "MEDIUM":
      return "bg-amber-500/15 text-amber-400 border-amber-500/30";
    default:
      return "bg-cyan-500/15 text-cyan-400 border-cyan-500/30";
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function nowStr() {
  const d = new Date();
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function AttackSimulationLab({ onAlertsGenerated }: AttackSimulationLabProps) {
  const [selectedAttack, setSelectedAttack] = useState<AttackType>("DDOS");
  const [status, setStatus] = useState<SimStatus>("idle");
  const [isChainMode, setIsChainMode] = useState(false);
  const [log, setLog] = useState<LogEntry[]>([]);
  const [result, setResult] = useState<SimulateResult | null>(null);
  const [activeChainStage, setActiveChainStage] = useState<number>(-1);
  const [errorMsg, setErrorMsg] = useState<string>("");

  const pushLog = useCallback((msg: string, type: LogEntry["type"] = "info") => {
    setLog((prev) => [...prev, { time: nowStr(), msg, type }]);
  }, []);

  const runSingleAttack = useCallback(async () => {
    setStatus("running");
    setResult(null);
    setIsChainMode(false);
    setErrorMsg("");
    setLog([]);

    const opt = ATTACK_OPTIONS.find((a) => a.id === selectedAttack)!;
    pushLog(`Initializing ${opt.label} simulation...`, "info");
    pushLog(`Crafting synthetic ${selectedAttack} telemetry → src: 10.0.0.77`, "info");

    await new Promise((r) => setTimeout(r, 350));
    pushLog("Routing through Feature Engine...", "info");

    await new Promise((r) => setTimeout(r, 300));
    pushLog("Running 7 Hybrid Detectors (Rules + RF + IF)...", "info");

    await new Promise((r) => setTimeout(r, 250));

    try {
      const res = await runSimulation(selectedAttack);
      pushLog(`Random Forest → score: ${res.ai_analysis?.ml_score?.toFixed(3) ?? "N/A"}`, "data");
      pushLog(`Isolation Forest → anomaly: ${res.ai_analysis?.anomaly_score?.toFixed(3) ?? "N/A"}`, "data");
      pushLog("Threat Fusion Engine → correlating signals...", "info");

      await new Promise((r) => setTimeout(r, 200));

      if (res.alerts_generated > 0) {
        pushLog(`⚠ THREAT DETECTED: ${res.alerts[0].threat_class} [${res.alerts[0].severity}]`, "success");
        pushLog(`Confidence: ${(res.alerts[0].confidence * 100).toFixed(0)}% • Action: ALERT_ONLY`, "success");
      } else {
        pushLog("No alert threshold reached for this flow.", "warn");
      }

      setResult(res);
      setStatus("success");
      if (onAlertsGenerated && res.alerts.length > 0) {
        onAlertsGenerated(res.alerts);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      pushLog(`ERROR: ${msg}`, "warn");
      setErrorMsg(msg);
      setStatus("error");
    }
  }, [selectedAttack, pushLog, onAlertsGenerated]);

  const runChain = useCallback(async () => {
    setStatus("running");
    setResult(null);
    setIsChainMode(true);
    setActiveChainStage(-1);
    setErrorMsg("");
    setLog([]);

    pushLog("Initializing Full Attack Chain simulation...", "info");
    pushLog("Source: 10.0.0.77 → Target: 203.0.113.9", "info");

    // Animate each chain stage
    for (let i = 0; i < CHAIN_STAGES.length; i++) {
      const stage = CHAIN_STAGES[i];
      await new Promise((r) => setTimeout(r, 500));
      setActiveChainStage(i);
      pushLog(`[T+${String(i * 3).padStart(2, "0")}s] Injecting ${stage.label} flow...`, "info");
    }

    await new Promise((r) => setTimeout(r, 400));
    pushLog("Routing all flows through Threat Fusion Engine...", "info");

    try {
      const res = await runAttackChain();

      await new Promise((r) => setTimeout(r, 300));
      pushLog(`Alerts generated: ${res.alerts_generated}`, "data");

      res.alerts.forEach((a) => {
        pushLog(
          `  ⚠ ${a.threat_class} [${a.severity}] · conf: ${(a.confidence * 100).toFixed(0)}%`,
          "success"
        );
      });

      if (res.alerts_generated >= 2) {
        pushLog("⛓ MULTI-STAGE ATTACK CHAIN CONFIRMED", "success");
      }

      setResult(res);
      setStatus("success");
      if (onAlertsGenerated && res.alerts.length > 0) {
        onAlertsGenerated(res.alerts);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      pushLog(`ERROR: ${msg}`, "warn");
      setErrorMsg(msg);
      setStatus("error");
    }
  }, [pushLog, onAlertsGenerated]);

  const handleReset = () => {
    setStatus("idle");
    setResult(null);
    setLog([]);
    setActiveChainStage(-1);
    setIsChainMode(false);
    setErrorMsg("");
  };

  const isRunning = status === "running";

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* ── Header ── */}
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-lg">🧪</span>
            <h2 className="text-base font-semibold tracking-tight text-white">
              Attack Simulation Lab
            </h2>
            <span className="rounded bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-amber-400 border border-amber-500/20">
              DEMO AUTHORIZED
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-400">
            Generates synthetic telemetry → routes through real detection pipeline → live dashboard update
          </p>
        </div>

        <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          <span>Backend Connected · No real traffic injected</span>
        </div>
      </div>

      {/* ── Main Grid ── */}
      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-5">

        {/* ── Left: Attack selector + controls ── */}
        <div className="lg:col-span-2 space-y-4">
          {/* Attack Type Buttons */}
          <div>
            <p className="font-mono text-[10px] text-slate-500 uppercase tracking-wider mb-2">
              Select Attack Type
            </p>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-2">
              {ATTACK_OPTIONS.map((opt) => {
                const isSelected = selectedAttack === opt.id;
                return (
                  <button
                    key={opt.id}
                    id={`sim-attack-${opt.id.toLowerCase()}`}
                    onClick={() => { setSelectedAttack(opt.id); handleReset(); }}
                    disabled={isRunning}
                    className={`relative rounded-xl border p-3 text-left transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed
                      ${isSelected
                        ? `${opt.bgColor} ${opt.borderColor} shadow-lg`
                        : "border-slate-800 bg-[#070D1C] hover:border-slate-700 hover:bg-[#0A1224]"
                      }`}
                  >
                    <span className="text-base">{opt.icon}</span>
                    <p className={`mt-1 font-mono text-xs font-bold ${isSelected ? opt.color : "text-slate-300"}`}>
                      {opt.shortLabel}
                    </p>
                    <p className="text-[9px] text-slate-500 mt-0.5 leading-tight">{opt.desc}</p>
                    {isSelected && (
                      <span className="absolute top-2 right-2 h-1.5 w-1.5 rounded-full bg-emerald-400" />
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Run Controls */}
          <div className="space-y-2">
            <button
              id="sim-run-single"
              onClick={runSingleAttack}
              disabled={isRunning}
              className={`w-full rounded-xl border py-3 font-mono text-sm font-bold tracking-wide transition-all duration-200 flex items-center justify-center gap-2
                ${isRunning
                  ? "border-slate-700 bg-slate-800/50 text-slate-500 cursor-not-allowed"
                  : "border-cyan-500/50 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-950/60 hover:border-cyan-400 hover:shadow-[0_0_20px_-5px_rgba(34,211,238,0.4)]"
                }`}
            >
              {isRunning && !isChainMode ? (
                <>
                  <span className="h-3 w-3 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
                  RUNNING...
                </>
              ) : (
                <>▶ RUN {ATTACK_OPTIONS.find((a) => a.id === selectedAttack)?.shortLabel ?? ""} ATTACK</>
              )}
            </button>

            <button
              id="sim-run-chain"
              onClick={runChain}
              disabled={isRunning}
              className={`w-full rounded-xl border py-3 font-mono text-sm font-bold tracking-wide transition-all duration-200 flex items-center justify-center gap-2
                ${isRunning
                  ? "border-slate-700 bg-slate-800/50 text-slate-500 cursor-not-allowed"
                  : "border-rose-500/50 bg-rose-950/20 text-rose-300 hover:bg-rose-950/40 hover:border-rose-400 hover:shadow-[0_0_20px_-5px_rgba(244,63,94,0.3)]"
                }`}
            >
              {isRunning && isChainMode ? (
                <>
                  <span className="h-3 w-3 rounded-full border-2 border-rose-400 border-t-transparent animate-spin" />
                  CHAINING...
                </>
              ) : (
                <>⛓ RUN FULL ATTACK CHAIN</>
              )}
            </button>

            {status !== "idle" && (
              <button
                id="sim-reset"
                onClick={handleReset}
                disabled={isRunning}
                className="w-full rounded-xl border border-slate-800 py-2 font-mono text-xs text-slate-500 hover:text-slate-300 hover:border-slate-700 transition-colors disabled:opacity-30"
              >
                ↺ RESET
              </button>
            )}
          </div>

          {/* Full Chain Visualizer */}
          {isChainMode && (
            <div className="rounded-xl border border-slate-800 bg-[#070D1C] p-3">
              <p className="font-mono text-[9px] text-slate-500 uppercase tracking-wider mb-3">
                Kill Chain Progression
              </p>
              <div className="space-y-2">
                {CHAIN_STAGES.map((stage, i) => {
                  const isDone = activeChainStage >= i && status !== "idle";
                  const isActive = activeChainStage === i && isRunning;
                  return (
                    <div key={stage.id} className="flex items-center gap-2">
                      <div className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border transition-all duration-300
                        ${isDone
                          ? `${stage.dotColor} border-transparent`
                          : isActive
                          ? "border-slate-500 bg-slate-800 animate-pulse"
                          : "border-slate-700 bg-[#060913]"
                        }`}
                      >
                        {isDone && !isActive && (
                          <span className="text-[8px] font-bold text-black">✓</span>
                        )}
                        {isActive && (
                          <span className={`text-[6px] font-bold ${stage.color}`}>●</span>
                        )}
                      </div>
                      <span className={`font-mono text-[10px] font-bold transition-colors ${isDone ? stage.color : "text-slate-600"}`}>
                        {stage.label}
                      </span>
                      {i < CHAIN_STAGES.length - 1 && (
                        <div className="flex-1 border-t border-dashed border-slate-800" />
                      )}
                    </div>
                  );
                })}

                {status === "success" && isChainMode && (
                  <div className="mt-2 rounded-lg border border-rose-500/30 bg-rose-950/20 p-2 text-center">
                    <span className="font-mono text-[10px] font-bold text-rose-400">
                      ⚠ LIKELY MULTI-STAGE ATTACK
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* ── Right: Live log + results ── */}
        <div className="lg:col-span-3 space-y-4">

          {/* Live Pipeline Log */}
          <div className="rounded-xl border border-slate-800 bg-[#070D1C]">
            <div className="flex items-center justify-between border-b border-slate-800/80 px-3 py-2">
              <span className="font-mono text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Pipeline Execution Log
              </span>
              {isRunning && (
                <span className="flex items-center gap-1.5 font-mono text-[10px] text-emerald-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  LIVE
                </span>
              )}
            </div>

            <div className="h-44 overflow-y-auto p-3 font-mono text-[10px] space-y-1 scroll-smooth">
              {log.length === 0 ? (
                <div className="flex h-full items-center justify-center">
                  <p className="text-slate-600">Select an attack type and click RUN to begin.</p>
                </div>
              ) : (
                log.map((entry, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="shrink-0 text-slate-600">{entry.time}</span>
                    <span
                      className={
                        entry.type === "success"
                          ? "text-emerald-400"
                          : entry.type === "warn"
                          ? "text-amber-400"
                          : entry.type === "data"
                          ? "text-cyan-300"
                          : "text-slate-400"
                      }
                    >
                      {entry.msg}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Results Panel */}
          {status === "success" && result && result.alerts_generated > 0 && (
            <div className="rounded-xl border border-slate-800 bg-[#070D1C] p-4 space-y-3 animate-[fadeIn_0.4s_ease-out]">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-white uppercase">
                  {result.alerts_generated > 1 ? "Attack Chain Alerts" : "Threat Detected"}
                </span>
                <span className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold ${severityStyle(result.alerts[0]?.severity ?? "")}`}>
                  {result.alerts[0]?.severity}
                </span>
              </div>

              {result.alerts.map((alert, i) => (
                <div
                  key={alert.flow_id}
                  className="rounded-lg border border-slate-800/80 bg-[#060913] p-3 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-white">{alert.threat_class}</span>
                    <span className="font-mono text-[10px] text-cyan-400">
                      {(alert.confidence * 100).toFixed(0)}% confidence
                    </span>
                  </div>

                  <div className="mt-1.5 flex items-center gap-2 font-mono text-[10px] text-slate-400">
                    <span className="text-cyan-300">{alert.src_ip}</span>
                    <span>→</span>
                    <span>{alert.dst_ip}</span>
                    <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-[9px]">
                      ALERT_ONLY
                    </span>
                  </div>

                  {alert.evidence && alert.evidence.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {alert.evidence.slice(0, 3).map((ev, ei) => (
                        <div key={ei} className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400">
                          <span className="text-emerald-500">✓</span>
                          <span>{ev.description}</span>
                          <span className="ml-auto text-cyan-300 font-semibold">
                            {typeof ev.value === "number" && ev.value > 100
                              ? ev.value.toLocaleString()
                              : String(ev.value ?? "")}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}

                  {alert.attack_chain && alert.attack_chain.length > 0 && (
                    <div className="mt-2 flex items-center gap-1.5 flex-wrap">
                      <span className="font-mono text-[9px] text-slate-600 uppercase">chain:</span>
                      {alert.attack_chain.map((stage, si) => (
                        <span key={si} className="font-mono text-[9px] text-purple-400">
                          {si > 0 && <span className="text-slate-700 mr-1">→</span>}
                          {stage}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}

              {/* AI Analysis Card */}
              {result.ai_analysis && (
                <SimulationAIAnalysis
                  analysis={result.ai_analysis}
                  attackType={result.attack_type}
                />
              )}
            </div>
          )}

          {/* No alert state */}
          {status === "success" && result && result.alerts_generated === 0 && (
            <div className="rounded-xl border border-slate-800 bg-[#070D1C] p-6 text-center">
              <p className="font-mono text-xs font-semibold text-slate-400">Flow processed — below detection threshold</p>
              <p className="mt-1 text-[10px] text-slate-600">
                Threshold not reached. Try a higher-volume attack type.
              </p>
            </div>
          )}

          {/* Error state */}
          {status === "error" && (
            <div className="rounded-xl border border-amber-500/30 bg-amber-950/10 p-4">
              <p className="font-mono text-xs font-bold text-amber-400">⚠ Simulation Error</p>
              <p className="mt-1 font-mono text-[10px] text-slate-400">{errorMsg}</p>
              <p className="mt-1 text-[10px] text-slate-500">
                Make sure the backend is running at{" "}
                <span className="text-cyan-400">http://localhost:8000</span>
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ── Footer disclaimer ── */}
      <div className="mt-4 flex items-start gap-2 rounded-lg border border-slate-800/60 bg-[#060913] px-3 py-2">
        <span className="font-mono text-[9px] text-slate-600">ℹ</span>
        <p className="font-mono text-[9px] text-slate-600 leading-relaxed">
          Authorized demo telemetry only. Synthetic flows are fabricated in-memory and processed by the live detection
          pipeline. No packets are injected onto any network. Architecture remains strictly passive and read-only.
        </p>
      </div>
    </div>
  );
}
