"use client";

import React, { useState, useCallback } from "react";
import {
  Zap,
  Radio,
  Shuffle,
  Globe,
  ScanSearch,
  Upload,
  FlaskConical,
  Link2,
  Play,
  RotateCcw,
  ChevronRight,
  AlertTriangle,
  Check,
  CheckCircle2,
  Loader2,
  WifiOff,
} from "lucide-react";
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
  icon: React.ReactNode;
  desc: string;
  activeClass: string;
  idleClass: string;
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
    icon: <Zap className="h-4 w-4" />,
    desc: "52K pps · 5.2 MB/s · UDP flood",
    activeClass: "border-rose-500/50 bg-rose-950/30 text-rose-400",
    idleClass: "border-slate-800 bg-[#070D1C] text-slate-400 hover:border-slate-700",
  },
  {
    id: "C2_BEACON",
    label: "C2 Beacon",
    shortLabel: "C2 Beacon",
    icon: <Radio className="h-4 w-4" />,
    desc: "300s interval · low IAT variance",
    activeClass: "border-orange-500/50 bg-orange-950/30 text-orange-400",
    idleClass: "border-slate-800 bg-[#070D1C] text-slate-400 hover:border-slate-700",
  },
  {
    id: "DGA",
    label: "DGA Domain",
    shortLabel: "DGA",
    icon: <Shuffle className="h-4 w-4" />,
    desc: "High entropy DNS · elevated digit ratio",
    activeClass: "border-purple-500/50 bg-purple-950/30 text-purple-400",
    idleClass: "border-slate-800 bg-[#070D1C] text-slate-400 hover:border-slate-700",
  },
  {
    id: "DNS_TUNNEL",
    label: "DNS Tunnel",
    shortLabel: "DNS Tunnel",
    icon: <Globe className="h-4 w-4" />,
    desc: "Encoded subdomain chain · 64-char label",
    activeClass: "border-indigo-500/50 bg-indigo-950/30 text-indigo-400",
    idleClass: "border-slate-800 bg-[#070D1C] text-slate-400 hover:border-slate-700",
  },
  {
    id: "RECON",
    label: "Recon Sweep",
    shortLabel: "Recon",
    icon: <ScanSearch className="h-4 w-4" />,
    desc: "Port sweep 1–1024 · 1200 packets",
    activeClass: "border-amber-500/50 bg-amber-950/30 text-amber-400",
    idleClass: "border-slate-800 bg-[#070D1C] text-slate-400 hover:border-slate-700",
  },
  {
    id: "EXFIL",
    label: "Data Exfil",
    shortLabel: "Exfil",
    icon: <Upload className="h-4 w-4" />,
    desc: "85 MB outbound · upload ratio 0.99",
    activeClass: "border-cyan-500/50 bg-cyan-950/30 text-cyan-400",
    idleClass: "border-slate-800 bg-[#070D1C] text-slate-400 hover:border-slate-700",
  },
];

// Full attack chain sequence for display
const CHAIN_STAGES = [
  { id: "RECON",     label: "RECON",     dotColor: "bg-amber-400",  textColor: "text-amber-400"  },
  { id: "DGA",       label: "DGA",       dotColor: "bg-purple-400", textColor: "text-purple-400" },
  { id: "C2_BEACON", label: "C2 BEACON", dotColor: "bg-orange-400", textColor: "text-orange-400" },
  { id: "EXFIL",     label: "EXFIL",     dotColor: "bg-rose-400",   textColor: "text-rose-400"   },
];

// ─── Severity badge helper ────────────────────────────────────────────────────

function severityStyle(sev: string) {
  switch (sev) {
    case "CRITICAL": return "bg-rose-500/15 text-rose-400 border-rose-500/30";
    case "HIGH":     return "bg-orange-500/15 text-orange-400 border-orange-500/30";
    case "MEDIUM":   return "bg-amber-500/15 text-amber-400 border-amber-500/30";
    default:         return "bg-cyan-500/15 text-cyan-400 border-cyan-500/30";
  }
}

// ─── Time helper ──────────────────────────────────────────────────────────────

function nowStr() {
  const d = new Date();
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((v) => String(v).padStart(2, "0"))
    .join(":");
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
    pushLog(`Initializing ${opt.label} simulation...`);
    pushLog(`Crafting synthetic ${selectedAttack} telemetry — src: 10.0.0.77`);
    await new Promise((r) => setTimeout(r, 350));

    pushLog("Routing through Feature Engine...");
    await new Promise((r) => setTimeout(r, 300));

    pushLog("Running Hybrid Detectors — Rules + Random Forest + Isolation Forest...");
    await new Promise((r) => setTimeout(r, 250));

    try {
      const res = await runSimulation(selectedAttack);
      pushLog(`Random Forest    score: ${res.ai_analysis?.ml_score?.toFixed(3) ?? "N/A"}`, "data");
      pushLog(`Isolation Forest score: ${res.ai_analysis?.anomaly_score?.toFixed(3) ?? "N/A"}`, "data");
      pushLog("Threat Fusion Engine — correlating detector signals...");
      await new Promise((r) => setTimeout(r, 200));

      if (res.alerts_generated > 0) {
        pushLog(
          `THREAT DETECTED: ${res.alerts[0].threat_class}  [${res.alerts[0].severity}]`,
          "success"
        );
        pushLog(
          `Confidence: ${(res.alerts[0].confidence * 100).toFixed(0)}%  — Action: ALERT_ONLY`,
          "success"
        );
      } else {
        pushLog("Flow processed — below detection threshold.", "warn");
      }

      setResult(res);
      setStatus("success");
      if (onAlertsGenerated && res.alerts.length > 0) onAlertsGenerated(res.alerts);
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

    pushLog("Initializing full kill-chain simulation...");
    pushLog("Source host: 10.0.0.77  —  Target: 203.0.113.9");

    for (let i = 0; i < CHAIN_STAGES.length; i++) {
      await new Promise((r) => setTimeout(r, 500));
      setActiveChainStage(i);
      pushLog(`[T+${String(i * 3).padStart(2, "0")}s] Injecting ${CHAIN_STAGES[i].label} flow...`);
    }

    await new Promise((r) => setTimeout(r, 400));
    pushLog("Routing all flows through Threat Fusion Engine...");

    try {
      const res = await runAttackChain();
      await new Promise((r) => setTimeout(r, 300));
      pushLog(`Alerts generated: ${res.alerts_generated}`, "data");

      res.alerts.forEach((a) => {
        pushLog(
          `  ${a.threat_class}  [${a.severity}]  conf: ${(a.confidence * 100).toFixed(0)}%`,
          "success"
        );
      });

      if (res.alerts_generated >= 2) {
        pushLog("MULTI-STAGE ATTACK CHAIN CONFIRMED", "success");
      }

      setResult(res);
      setStatus("success");
      if (onAlertsGenerated && res.alerts.length > 0) onAlertsGenerated(res.alerts);
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
  const selectedOpt = ATTACK_OPTIONS.find((a) => a.id === selectedAttack)!;

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* ── Header ── */}
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-amber-500/30 bg-amber-950/30 text-amber-400">
              <FlaskConical className="h-4 w-4" />
            </div>
            <h2 className="text-base font-semibold tracking-tight text-white">
              Attack Simulation Lab
            </h2>
            <span className="rounded border border-amber-500/25 bg-amber-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-amber-400">
              DEMO · SYNTHETIC
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Generates authorized synthetic telemetry routed through the live detection pipeline
          </p>
        </div>

        <div className="flex items-center gap-1.5 font-mono text-[10px] text-slate-500">
          <div className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          Backend connected · No real traffic injected
        </div>
      </div>

      {/* ── Main Grid ── */}
      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-5">

        {/* ── Left: Attack selector + controls ── */}
        <div className="lg:col-span-2 space-y-4">

          {/* Attack Type Grid */}
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
                    className={`relative flex items-center gap-2.5 rounded-xl border p-3 text-left transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed
                      ${isSelected ? opt.activeClass : opt.idleClass}`}
                  >
                    <span className={`shrink-0 ${isSelected ? "" : "opacity-60"}`}>
                      {opt.icon}
                    </span>
                    <div className="min-w-0">
                      <p className="font-mono text-xs font-semibold truncate">{opt.shortLabel}</p>
                      <p className="text-[9px] text-slate-500 mt-0.5 leading-tight truncate">{opt.desc}</p>
                    </div>
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
            {/* Single attack */}
            <button
              id="sim-run-single"
              onClick={runSingleAttack}
              disabled={isRunning}
              className={`w-full flex items-center justify-center gap-2 rounded-xl border py-3 font-mono text-sm font-bold tracking-wide transition-all duration-200
                ${isRunning && !isChainMode
                  ? "cursor-not-allowed border-slate-700 bg-slate-800/50 text-slate-500"
                  : "border-cyan-500/50 bg-cyan-950/30 text-cyan-300 hover:bg-cyan-950/60 hover:border-cyan-400 hover:shadow-[0_0_20px_-5px_rgba(34,211,238,0.35)]"
                }`}
            >
              {isRunning && !isChainMode ? (
                <><Loader2 className="h-4 w-4 animate-spin" /> RUNNING...</>
              ) : (
                <><Play className="h-4 w-4" /> RUN {selectedOpt.shortLabel.toUpperCase()}</>
              )}
            </button>

            {/* Full chain */}
            <button
              id="sim-run-chain"
              onClick={runChain}
              disabled={isRunning}
              className={`w-full flex items-center justify-center gap-2 rounded-xl border py-3 font-mono text-sm font-bold tracking-wide transition-all duration-200
                ${isRunning && isChainMode
                  ? "cursor-not-allowed border-slate-700 bg-slate-800/50 text-slate-500"
                  : "border-rose-500/50 bg-rose-950/20 text-rose-300 hover:bg-rose-950/40 hover:border-rose-400 hover:shadow-[0_0_20px_-5px_rgba(244,63,94,0.25)]"
                }`}
            >
              {isRunning && isChainMode ? (
                <><Loader2 className="h-4 w-4 animate-spin" /> CHAINING...</>
              ) : (
                <><Link2 className="h-4 w-4" /> RUN FULL ATTACK CHAIN</>
              )}
            </button>

            {status !== "idle" && (
              <button
                id="sim-reset"
                onClick={handleReset}
                disabled={isRunning}
                className="w-full flex items-center justify-center gap-1.5 rounded-xl border border-slate-800 py-2 font-mono text-xs text-slate-500 hover:text-slate-300 hover:border-slate-700 transition-colors disabled:opacity-30"
              >
                <RotateCcw className="h-3 w-3" /> RESET
              </button>
            )}
          </div>

          {/* Kill Chain Stage Visualizer */}
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
                        ${isDone && !isActive
                          ? `${stage.dotColor} border-transparent`
                          : isActive
                          ? "border-slate-500 bg-slate-800 animate-pulse"
                          : "border-slate-700 bg-[#060913]"
                        }`}
                      >
                        {isDone && !isActive && (
                          <Check className="h-2.5 w-2.5 text-black stroke-[3]" />
                        )}
                        {isActive && (
                          <Loader2 className={`h-2.5 w-2.5 animate-spin ${stage.textColor}`} />
                        )}
                      </div>
                      <span className={`font-mono text-[10px] font-bold transition-colors ${isDone ? stage.textColor : "text-slate-600"}`}>
                        {stage.label}
                      </span>
                      {i < CHAIN_STAGES.length - 1 && (
                        <div className="flex-1 border-t border-dashed border-slate-800" />
                      )}
                    </div>
                  );
                })}

                {status === "success" && isChainMode && (
                  <div className="mt-2 flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-950/20 px-3 py-2">
                    <AlertTriangle className="h-3 w-3 shrink-0 text-rose-400" />
                    <span className="font-mono text-[10px] font-bold text-rose-400">
                      LIKELY MULTI-STAGE ATTACK
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* ── Right: Live log + results ── */}
        <div className="lg:col-span-3 space-y-4">

          {/* Pipeline Execution Log */}
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

            <div className="h-44 overflow-y-auto p-3 font-mono text-[10px] space-y-1">
              {log.length === 0 ? (
                <div className="flex h-full items-center justify-center">
                  <p className="text-slate-600">Select an attack type and click Run to begin.</p>
                </div>
              ) : (
                log.map((entry, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="shrink-0 text-slate-600">{entry.time}</span>
                    <span className={
                      entry.type === "success" ? "text-emerald-400"
                      : entry.type === "warn"    ? "text-amber-400"
                      : entry.type === "data"    ? "text-cyan-300"
                      : "text-slate-400"
                    }>
                      {entry.msg}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Result Panel */}
          {status === "success" && result && result.alerts_generated > 0 && (
            <div className="rounded-xl border border-slate-800 bg-[#070D1C] p-4 space-y-3">
              {/* Result Header */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  <span className="font-mono text-xs font-bold text-white uppercase">
                    {result.alerts_generated > 1 ? "Attack Chain Alerts" : "Threat Detected"}
                  </span>
                </div>
                <span className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold ${severityStyle(result.alerts[0]?.severity ?? "")}`}>
                  {result.alerts[0]?.severity}
                </span>
              </div>

              {/* Individual Alerts */}
              {result.alerts.map((alert) => (
                <div key={alert.flow_id} className="rounded-lg border border-slate-800/80 bg-[#060913] p-3 text-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-white">{alert.threat_class}</span>
                    <span className="font-mono text-[10px] text-cyan-400">
                      {(alert.confidence * 100).toFixed(0)}% confidence
                    </span>
                  </div>

                  {/* Confidence bar */}
                  <div className="h-1 w-full overflow-hidden rounded-full bg-slate-800">
                    <div
                      className="h-full rounded-full bg-cyan-500 transition-all duration-700"
                      style={{ width: `${(alert.confidence * 100).toFixed(0)}%` }}
                    />
                  </div>

                  <div className="flex items-center gap-2 font-mono text-[10px] text-slate-400">
                    <span className="text-cyan-300">{alert.src_ip}</span>
                    <ChevronRight className="h-3 w-3" />
                    <span>{alert.dst_ip}</span>
                    <span className="ml-auto rounded bg-slate-800 px-1.5 py-0.5 text-[9px]">ALERT_ONLY</span>
                  </div>

                  {/* Evidence items */}
                  {alert.evidence && alert.evidence.length > 0 && (
                    <div className="space-y-1 border-t border-slate-800/80 pt-2">
                      {alert.evidence.slice(0, 3).map((ev, ei) => (
                        <div key={ei} className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400">
                          <Check className="h-3 w-3 shrink-0 text-emerald-500 stroke-[2.5]" />
                          <span className="flex-1">{ev.description}</span>
                          <span className="text-cyan-300 font-semibold">
                            {typeof ev.value === "number" && ev.value > 100
                              ? ev.value.toLocaleString()
                              : String(ev.value ?? "")}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Attack chain progression */}
                  {alert.attack_chain && alert.attack_chain.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap border-t border-slate-800/80 pt-2">
                      <span className="font-mono text-[9px] text-slate-600 uppercase">Chain:</span>
                      {alert.attack_chain.map((stage, si) => (
                        <React.Fragment key={stage}>
                          {si > 0 && <ChevronRight className="h-2.5 w-2.5 text-slate-700" />}
                          <span className="font-mono text-[9px] font-semibold text-purple-400">{stage}</span>
                        </React.Fragment>
                      ))}
                    </div>
                  )}
                </div>
              ))}

              {/* AI/ML Analysis & LLM Incident Explanation */}
              {result.ai_analysis && (
                <SimulationAIAnalysis
                  analysis={result.ai_analysis}
                  attackType={result.attack_type}
                  llm={result.llm}
                />
              )}
            </div>
          )}

          {/* Below-threshold state */}
          {status === "success" && result && result.alerts_generated === 0 && (
            <div className="rounded-xl border border-slate-800 bg-[#070D1C] p-6 text-center">
              <p className="font-mono text-xs font-semibold text-slate-400">
                Flow processed — below detection threshold
              </p>
              <p className="mt-1 text-[10px] text-slate-600">
                Confidence threshold not reached. Try a higher-volume attack type.
              </p>
            </div>
          )}

          {/* Error state */}
          {status === "error" && (
            <div className="rounded-xl border border-amber-500/30 bg-amber-950/10 p-4 flex items-start gap-3">
              <WifiOff className="h-4 w-4 shrink-0 text-amber-400 mt-0.5" />
              <div>
                <p className="font-mono text-xs font-bold text-amber-400">Simulation Error</p>
                <p className="mt-1 font-mono text-[10px] text-slate-400">{errorMsg}</p>
                <p className="mt-1 text-[10px] text-slate-500">
                  Backend must be running at{" "}
                  <span className="text-cyan-400 font-mono">http://localhost:8000</span>
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Disclaimer footer ── */}
      <div className="mt-4 flex items-start gap-2 rounded-lg border border-slate-800/60 bg-[#060913] px-3 py-2">
        <AlertTriangle className="h-3 w-3 shrink-0 text-slate-600 mt-0.5" />
        <p className="font-mono text-[9px] text-slate-600 leading-relaxed">
          Authorized demo telemetry only. Synthetic flows are fabricated in-memory and processed by
          the live detection pipeline. No packets are injected onto any network. Architecture remains
          strictly passive and read-only.
        </p>
      </div>
    </div>
  );
}


