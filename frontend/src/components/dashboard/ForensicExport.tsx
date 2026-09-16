"use client";

import React, { useCallback, useState } from "react";

interface ForensicExportProps {
  report: Record<string, unknown> | object;
  filename?: string;
  label?: string;
}

export function ForensicExport({
  report,
  filename = "sentinelflow_report",
  label = "Export",
}: ForensicExportProps) {
  const [copied, setCopied] = useState(false);

  const downloadJson = useCallback(() => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${filename}_${Date.now()}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }, [report, filename]);

  const printPdf = useCallback(() => {
    const printWindow = window.open("", "_blank", "width=900,height=700");
    if (!printWindow) return;

    const json = JSON.stringify(report, null, 2);
    const ts = new Date().toUTCString();

    printWindow.document.write(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>SentinelFlow Forensic Report</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Courier New', Courier, monospace; background: #fff; color: #111; padding: 32px; }
    h1 { font-size: 18px; font-weight: bold; margin-bottom: 4px; }
    .subtitle { font-size: 11px; color: #555; margin-bottom: 24px; }
    .badge { display: inline-block; border: 1px solid #ccc; border-radius: 4px; padding: 2px 8px; font-size: 10px; margin-bottom: 16px; background: #f4f4f4; }
    pre { background: #f9f9f9; border: 1px solid #ddd; border-radius: 6px; padding: 16px; font-size: 11px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
    .footer { margin-top: 24px; font-size: 10px; color: #888; border-top: 1px solid #ddd; padding-top: 12px; }
  </style>
</head>
<body>
  <h1>SentinelFlow — Forensic Export Report</h1>
  <p class="subtitle">Generated: ${ts}</p>
  <span class="badge">PASSIVE READ-ONLY TELEMETRY · ALERT_ONLY</span>
  <pre>${json.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</pre>
  <div class="footer">SentinelFlow Passive AI/ML Network Threat Intelligence Platform · Zero packet injection · No active countermeasures</div>
  <script>window.onload = function(){ window.print(); }<\/script>
</body>
</html>`);
    printWindow.document.close();
  }, [report]);

  const copyJson = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // noop
    }
  }, [report]);

  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-[10px] text-slate-500 uppercase tracking-wider">
        {label}
      </span>
      <button
        id="forensic-export-json"
        onClick={downloadJson}
        title="Download full JSON report"
        className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-1.5 font-mono text-[11px] font-semibold text-slate-200 transition-all hover:border-cyan-500/40 hover:bg-cyan-950/30 hover:text-cyan-300"
      >
        <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
        </svg>
        JSON
      </button>
      <button
        id="forensic-export-pdf"
        onClick={printPdf}
        title="Export as printable PDF"
        className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-1.5 font-mono text-[11px] font-semibold text-slate-200 transition-all hover:border-rose-500/40 hover:bg-rose-950/30 hover:text-rose-300"
      >
        <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M6.72 13.829c-.24.03-.48.062-.72.096m.72-.096a42.415 42.415 0 0110.56 0m-10.56 0L6.34 18m10.94-4.171c.24.03.48.062.72.096m-.72-.096L17.66 18m0 0l.229 2.523a1.125 1.125 0 01-1.12 1.227H7.231c-.662 0-1.18-.568-1.12-1.227L6.34 18m11.318 0h1.091A2.25 2.25 0 0021 15.75V9.456c0-1.081-.768-2.015-1.837-2.175a48.055 48.055 0 00-1.913-.247M6.34 18H5.25A2.25 2.25 0 013 15.75V9.456c0-1.081.768-2.015 1.837-2.175a48.056 48.056 0 011.913-.247m10.5 0a48.536 48.536 0 00-10.5 0m10.5 0V3.375c0-.621-.504-1.125-1.125-1.125h-8.25c-.621 0-1.125.504-1.125 1.125v3.659M18 10.5h.008v.008H18V10.5zm-3 0h.008v.008H15V10.5z" />
        </svg>
        PDF
      </button>
      <button
        id="forensic-export-copy"
        onClick={copyJson}
        title="Copy JSON to clipboard"
        className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-1.5 font-mono text-[11px] font-semibold text-slate-200 transition-all hover:border-emerald-500/40 hover:bg-emerald-950/30 hover:text-emerald-300"
      >
        {copied ? (
          <>
            <svg className="h-3.5 w-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
            </svg>
            Copied!
          </>
        ) : (
          <>
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
            </svg>
            Copy
          </>
        )}
      </button>
    </div>
  );
}
