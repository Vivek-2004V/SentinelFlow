"use client";

import React, { useState, useRef, useCallback } from "react";
import {
  UploadCloud,
  FileCode,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Cpu,
  Zap,
  RotateCcw,
  Sparkles,
  Info,
  Clock,
  Layers,
  ArrowRight,
  Database,
  ExternalLink,
} from "lucide-react";
import { analyzePcap, PcapAnalysisResult } from "@/lib/api";
import { ThreatAlert } from "@/types";

interface PcapUploaderProps {
  onAlertsGenerated?: (alerts: ThreatAlert[]) => void;
}

type UploadState = "idle" | "uploading" | "analyzing" | "complete" | "error";

const PIPELINE_STEPS = [
  { id: 1, label: "Packet Parsing", desc: "Streaming PcapReader (IPv4, TCP/UDP/DNS/TLS)" },
  { id: 2, label: "Flow Reconstruction", desc: "5-tuple stateful bidirectional aggregation" },
  { id: 3, label: "24-Feature Engine", desc: "Standard feature contract (no duplication)" },
  { id: 4, label: "Threat Detectors", desc: "DDoS, C2 beacon, recon & exfil heuristic engines" },
  { id: 5, label: "Dual AI Inference", desc: "Random Forest Classifier + Isolation Forest" },
  { id: 6, label: "Threat Fusion", desc: "Multi-signal confidence scoring & kill-chain evidence" },
  { id: 7, label: "Advisory LLM & Boundary", desc: "Incident narration under strict ALERT_ONLY invariant" },
];

export function PcapUploader({ onAlertsGenerated }: PcapUploaderProps) {
  const [state, setState] = useState<UploadState>("idle");
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeStep, setActiveStep] = useState(0);
  const [result, setResult] = useState<PcapAnalysisResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const startAnalysis = async (file: File) => {
    setSelectedFile(file);
    setErrorMsg(null);
    setState("uploading");
    setActiveStep(1);

    // Step progress simulation while server processes
    const stepInterval = setInterval(() => {
      setActiveStep((prev) => {
        if (prev < 6) return prev + 1;
        return prev;
      });
    }, 450);

    try {
      setState("analyzing");
      const res = await analyzePcap(file);
      clearInterval(stepInterval);
      setActiveStep(7);
      setResult(res);
      setState("complete");

      if (res.alerts && res.alerts.length > 0 && onAlertsGenerated) {
        onAlertsGenerated(res.alerts);
      }
    } catch (err: unknown) {
      clearInterval(stepInterval);
      setState("error");
      const msg = err instanceof Error ? err.message : "Failed to analyze capture file";
      setErrorMsg(msg);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    validateAndUpload(file);
  };

  const validateAndUpload = (file: File) => {
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (ext !== "pcap" && ext !== "pcapng") {
      setErrorMsg(`Invalid file type .${ext}. Only .pcap and .pcapng are supported.`);
      setState("error");
      return;
    }
    if (file.size > 50 * 1024 * 1024) {
      setErrorMsg(`File size ${(file.size / (1024 * 1024)).toFixed(1)}MB exceeds 50MB limit.`);
      setState("error");
      return;
    }
    startAnalysis(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) validateAndUpload(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = () => {
    setDragOver(false);
  };

  const handleReset = () => {
    setState("idle");
    setSelectedFile(null);
    setResult(null);
    setErrorMsg(null);
    setActiveStep(0);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  // Generate a valid synthetic .pcap in memory for 1-click test
  const handleQuickDemoPcap = () => {
    // Construct standard PCAP Global Header (24 bytes)
    // Magic: 0xa1b2c3d4 (little endian), Major: 2, Minor: 4, Snaplen: 65535, Network: 1 (Ethernet)
    const header = new Uint8Array([
      0xd4, 0xc3, 0xb2, 0xa1, // magic number
      0x02, 0x00, 0x04, 0x00, // v2.4
      0x00, 0x00, 0x00, 0x00, // thiszone
      0x00, 0x00, 0x00, 0x00, // sigfigs
      0xff, 0xff, 0x00, 0x00, // snaplen 65535
      0x01, 0x00, 0x00, 0x00, // network linktype Ethernet
    ]);

    // Build 15 synthetic packets (Simulating C2 beaconing on port 4444)
    const packets: Uint8Array[] = [header];
    const baseEpoch = Math.floor(Date.now() / 1000) - 60;

    for (let i = 0; i < 15; i++) {
      const tsSec = baseEpoch + i * 4; // periodic 4s intervals
      // Packet record header: ts_sec (4B), ts_usec (4B), incl_len (4B), orig_len (4B)
      const pcapPktHeader = new Uint8Array(16);
      const view = new DataView(pcapPktHeader.buffer);
      view.setUint32(0, tsSec, true);
      view.setUint32(4, 100000, true);
      const frameLen = 54; // 14 eth + 20 ip + 20 tcp
      view.setUint32(8, frameLen, true);
      view.setUint32(12, frameLen, true);

      // Raw frame (Ethernet II + IPv4 + TCP SYN/ACK)
      const frame = new Uint8Array([
        // Eth
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        // IP (10.0.0.99 -> 192.168.1.50)
        0x45, 0x00, 0x00, 0x28, 0x10, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x63, 0xc0, 0xa8, 0x01, 0x32,
        // TCP (sport 49200 -> dport 4444)
        0xc0, 0x30, 0x11, 0x5c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x72, 0x10, 0x00, 0x00, 0x00, 0x00,
      ]);

      packets.push(pcapPktHeader);
      packets.push(frame);
    }

    const blob = new Blob(packets as BlobPart[], { type: "application/vnd.tcpdump.pcap" });
    const file = new File([blob], "c2_sample_capture.pcap", { type: "application/vnd.tcpdump.pcap" });
    startAnalysis(file);
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-[#070D1C]/90 p-6 shadow-2xl backdrop-blur-md">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <UploadCloud className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-semibold text-white tracking-tight">
                  PCAP Network Telemetry Ingest
                </h2>
                <span className="rounded bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-emerald-400 border border-emerald-500/30">
                  PASSIVE · READ-ONLY
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Upload real-world packet captures to reconstruct flows, extract 24 features, and run dual ML inference.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {state !== "idle" && (
            <button
              onClick={handleReset}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-slate-700 transition"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              New Analysis
            </button>
          )}
          <button
            onClick={handleQuickDemoPcap}
            disabled={state === "uploading" || state === "analyzing"}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3.5 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 transition disabled:opacity-50"
            title="Generate and test a sample PCAP file immediately"
          >
            <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
            Run Demo PCAP
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      {state === "idle" && (
        <div className="mt-6">
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng"
            className="hidden"
            onChange={handleFileChange}
          />
          <div
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => fileInputRef.current?.click()}
            className={`group relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-12 text-center transition-all cursor-pointer ${
              dragOver
                ? "border-cyan-400 bg-cyan-500/10 shadow-lg shadow-cyan-500/10"
                : "border-slate-800 bg-[#0A1022]/60 hover:border-slate-700 hover:bg-[#0E172E]/80"
            }`}
          >
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-slate-900/90 border border-slate-700 text-slate-400 group-hover:border-cyan-500/50 group-hover:text-cyan-300 transition">
              <UploadCloud className="h-7 w-7" />
            </div>

            <p className="mt-4 text-sm font-medium text-slate-200">
              <span className="text-cyan-400 underline decoration-cyan-400/50 underline-offset-2">
                Click to browse
              </span>{" "}
              or drag & drop your capture file
            </p>
            <p className="mt-1 text-xs text-slate-400 font-mono">
              Supported formats: .pcap, .pcapng · Maximum file size: 50 MB
            </p>

            <div className="mt-6 flex flex-wrap items-center justify-center gap-3 text-[11px] text-slate-400">
              <span className="inline-flex items-center gap-1 rounded bg-slate-900/80 px-2.5 py-1 border border-slate-800">
                <FileCode className="h-3 w-3 text-cyan-400" /> Scapy Streaming
              </span>
              <span className="inline-flex items-center gap-1 rounded bg-slate-900/80 px-2.5 py-1 border border-slate-800">
                <Layers className="h-3 w-3 text-cyan-400" /> 5-Tuple Reconstruction
              </span>
              <span className="inline-flex items-center gap-1 rounded bg-slate-900/80 px-2.5 py-1 border border-slate-800">
                <Cpu className="h-3 w-3 text-purple-400" /> 24-Feature Contract
              </span>
              <span className="inline-flex items-center gap-1 rounded bg-emerald-950/40 text-emerald-400 px-2.5 py-1 border border-emerald-500/30">
                <ShieldCheck className="h-3 w-3 text-emerald-400" /> Strictly Alert-Only
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Uploading & Analyzing Stepper View */}
      {(state === "uploading" || state === "analyzing") && (
        <div className="mt-6 space-y-6">
          <div className="flex items-center justify-between rounded-lg border border-cyan-500/30 bg-cyan-950/20 px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
              <div>
                <p className="text-xs font-medium text-cyan-200">
                  Ingesting telemetry: <strong className="font-mono text-cyan-400">{selectedFile?.name}</strong>
                </p>
                <p className="text-[11px] text-cyan-400/70">
                  Size: {((selectedFile?.size || 0) / 1024).toFixed(1)} KB · Zero active scan, zero packet injection
                </p>
              </div>
            </div>
            <span className="text-xs font-mono font-semibold text-cyan-300 animate-pulse">
              ANALYZING...
            </span>
          </div>

          <div className="rounded-lg border border-slate-800 bg-[#0A1022] p-4">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">
              Passive Processing Pipeline
            </h4>
            <div className="space-y-2.5">
              {PIPELINE_STEPS.map((step) => {
                const isCompleted = activeStep > step.id;
                const isCurrent = activeStep === step.id;
                return (
                  <div
                    key={step.id}
                    className={`flex items-center justify-between rounded-md px-3 py-2 text-xs transition ${
                      isCurrent
                        ? "bg-cyan-500/10 border border-cyan-500/40 text-cyan-200"
                        : isCompleted
                        ? "bg-slate-900/60 border border-slate-800 text-slate-300"
                        : "bg-slate-950/40 border border-transparent text-slate-400"
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      {isCompleted ? (
                        <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                      ) : isCurrent ? (
                        <div className="h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
                      ) : (
                        <span className="flex h-4 w-4 items-center justify-center rounded-full bg-slate-800 text-[10px] text-slate-400">
                          {step.id}
                        </span>
                      )}
                      <div>
                        <span className={`font-medium ${isCurrent ? "text-cyan-300" : isCompleted ? "text-slate-200" : "text-slate-400"}`}>
                          {step.label}
                        </span>
                        <span className="hidden sm:inline text-slate-400 ml-2">· {step.desc}</span>
                      </div>
                    </div>
                    <span className="font-mono text-[10px] uppercase">
                      {isCompleted ? "DONE" : isCurrent ? "PROCESSING" : "QUEUED"}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Error State */}
      {state === "error" && (
        <div className="mt-6 rounded-lg border border-rose-500/30 bg-rose-950/20 p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <h4 className="text-sm font-semibold text-rose-200">Capture Ingestion Failed</h4>
              <p className="mt-1 text-xs text-rose-300/80">{errorMsg}</p>
              <div className="mt-3 flex gap-2">
                <button
                  onClick={handleReset}
                  className="rounded bg-rose-900/60 hover:bg-rose-900 border border-rose-700/50 px-3 py-1 text-xs font-medium text-rose-100 transition"
                >
                  Try Again
                </button>
                <button
                  onClick={handleQuickDemoPcap}
                  className="rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 px-3 py-1 text-xs font-medium text-slate-200 transition"
                >
                  Run Synthetic Demo Instead
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Complete Result Screen */}
      {state === "complete" && result && (
        <div className="mt-6 space-y-6">
          {/* Top Status & Counters */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="rounded-lg border border-slate-800 bg-[#0A1022] p-3.5">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>Packets Analyzed</span>
                <FileCode className="h-3.5 w-3.5 text-cyan-400" />
              </div>
              <p className="mt-1 font-mono text-xl font-bold text-white">
                {result.packets_analyzed.toLocaleString()}
              </p>
              <span className="text-[10px] text-slate-400 font-mono">
                {result.filename}
              </span>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#0A1022] p-3.5">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>Flows Reconstructed</span>
                <Layers className="h-3.5 w-3.5 text-purple-400" />
              </div>
              <p className="mt-1 font-mono text-xl font-bold text-purple-300">
                {result.flows_reconstructed.toLocaleString()}
              </p>
              <span className="text-[10px] text-slate-400 font-mono">
                5-Tuple Bidirectional
              </span>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#0A1022] p-3.5">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>Threats Detected</span>
                <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
              </div>
              <p className="mt-1 font-mono text-xl font-bold text-rose-400">
                {result.threats_detected}
              </p>
              <span className="text-[10px] text-slate-400 font-mono">
                Correlated Incidents
              </span>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#0A1022] p-3.5">
              <div className="flex items-center justify-between text-slate-400 text-xs">
                <span>Top Threat</span>
                <Radio className="h-3.5 w-3.5 text-amber-400" />
              </div>
              <p className="mt-1 font-mono text-lg font-bold text-amber-300 truncate">
                {result.ai_analysis?.top_threat ?? "BENIGN"}
              </p>
              <span className="text-[10px] text-slate-400 font-mono">
                Kill-Chain Primary
              </span>
            </div>
          </div>

          {/* AI Intelligence & Security Boundary Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* AI Analysis Card */}
            <div className="rounded-lg border border-slate-800 bg-[#0A1022] p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between border-b border-slate-800 pb-2.5 mb-3">
                  <div className="flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-cyan-400" />
                    <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                      Dual AI / ML Evaluation
                    </h4>
                  </div>
                  <span className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] text-cyan-400 border border-cyan-500/20">
                    24-FEATURE CONTRACT
                  </span>
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between rounded bg-slate-900/60 p-2.5 text-xs">
                    <span className="text-slate-300">Random Forest Classifier</span>
                    <span className="font-mono font-bold text-cyan-300">
                      {result.ai_analysis?.random_forest_detected ?? 0} Classified Threat Flows
                    </span>
                  </div>

                  <div className="flex items-center justify-between rounded bg-slate-900/60 p-2.5 text-xs">
                    <span className="text-slate-300">Isolation Forest (Unsupervised)</span>
                    <span className="font-mono font-bold text-purple-300">
                      {result.ai_analysis?.isolation_forest_anomalies ?? 0} Anomaly Signatures
                    </span>
                  </div>

                  {result.threat_breakdown && Object.keys(result.threat_breakdown).length > 0 && (
                    <div>
                      <span className="text-[11px] text-slate-400 font-medium">Detection Breakdown:</span>
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
                        {Object.entries(result.threat_breakdown).map(([threat, count]) => (
                          <span
                            key={threat}
                            className="inline-flex items-center gap-1 rounded bg-slate-900 px-2 py-1 font-mono text-[11px] text-slate-300 border border-slate-800"
                          >
                            <span className="text-rose-400 font-bold">{threat}:</span>
                            <span className="text-slate-400">{count}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Advisory LLM Section */}
              {result.llm_advisory && (
                <div className="mt-4 rounded border border-purple-500/20 bg-purple-950/10 p-3 text-xs">
                  <div className="flex items-center gap-1.5 text-purple-300 font-semibold mb-1">
                    <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                    <span>LLM Incident Explanation (Advisory)</span>
                  </div>
                  <p className="text-slate-300 text-[11px] leading-relaxed">
                    {result.llm_advisory}
                  </p>
                </div>
              )}
            </div>

            {/* Security Boundary Card */}
            <div className="rounded-lg border border-slate-800 bg-[#0A1022] p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between border-b border-slate-800 pb-2.5 mb-3">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                    <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                      Passive Security Boundary
                    </h4>
                  </div>
                  <span className="rounded bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] text-emerald-400 border border-emerald-500/20">
                    AIR-GAPPED TELEMETRY
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="flex items-center justify-between rounded bg-slate-900/60 p-2 border border-slate-800/80">
                    <span className="text-slate-400">Passive Capture</span>
                    <span className="font-mono font-bold text-emerald-400">✓ ENFORCED</span>
                  </div>
                  <div className="flex items-center justify-between rounded bg-slate-900/60 p-2 border border-slate-800/80">
                    <span className="text-slate-400">Payload Decrypted</span>
                    <span className="font-mono font-bold text-emerald-400">✕ NO (Headers)</span>
                  </div>
                  <div className="flex items-center justify-between rounded bg-slate-900/60 p-2 border border-slate-800/80">
                    <span className="text-slate-400">Active Probe</span>
                    <span className="font-mono font-bold text-emerald-400">✕ NO</span>
                  </div>
                  <div className="flex items-center justify-between rounded bg-slate-900/60 p-2 border border-slate-800/80">
                    <span className="text-slate-400">Active Scan</span>
                    <span className="font-mono font-bold text-emerald-400">✕ NO</span>
                  </div>
                  <div className="flex items-center justify-between rounded bg-slate-900/60 p-2 border border-slate-800/80">
                    <span className="text-slate-400">Mitigation Path</span>
                    <span className="font-mono font-bold text-amber-400">✕ BLOCKED</span>
                  </div>
                  <div className="flex items-center justify-between rounded bg-slate-900/60 p-2 border border-slate-800/80">
                    <span className="text-slate-400">System Response</span>
                    <span className="font-mono font-bold text-cyan-400">ALERT_ONLY</span>
                  </div>
                </div>
              </div>

              <div className="mt-4 rounded bg-slate-900/80 p-3 border border-slate-800 text-[11px] text-slate-400">
                <p className="flex items-center gap-1.5 font-medium text-slate-300">
                  <Info className="h-3.5 w-3.5 text-cyan-400" />
                  Read-Only Telemetry Assurance
                </p>
                <p className="mt-0.5 leading-normal">
                  Uploaded PCAP is analyzed in ephemeral memory and discarded. SentinelFlow maintains zero return path and executes no blocking rules or host modifications.
                </p>
              </div>
            </div>
          </div>

          {/* Alert Feed from this Capture */}
          {result.alerts && result.alerts.length > 0 && (
            <div className="rounded-lg border border-slate-800 bg-[#0A1022] p-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-rose-400" />
                  <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                    Extracted Alerts from Capture ({result.alerts.length})
                  </h4>
                </div>
                <span className="text-[11px] text-slate-400">
                  Transferred to SOC live alert feed
                </span>
              </div>

              <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                {result.alerts.slice(0, 5).map((alert, idx) => (
                  <div
                    key={alert.flow_id || idx}
                    className="flex flex-col sm:flex-row sm:items-center justify-between rounded border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs gap-2"
                  >
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                        alert.severity === "CRITICAL"
                          ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                          : alert.severity === "HIGH"
                          ? "bg-orange-500/20 text-orange-300 border border-orange-500/40"
                          : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                      }`}>
                        {alert.severity}
                      </span>
                      <span className="font-semibold text-white">{alert.threat_class}</span>
                      <span className="text-slate-400 font-mono text-[11px]">
                        {alert.src_ip} → {alert.dst_ip}:{alert.dst_port ?? "-"}
                      </span>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="font-mono text-cyan-400 text-[11px]">
                        Conf: {(alert.confidence * 100).toFixed(0)}%
                      </span>
                      <span className="font-mono text-emerald-400 text-[10px] bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-500/20">
                        {alert.action}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
