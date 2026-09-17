"use client";

import React, { useMemo, useState, useCallback, useRef, useEffect } from "react";
import { ThreatAlert } from "@/lib/types";

interface NetworkTopologyProps {
  alerts: ThreatAlert[];
}

interface Node {
  id: string;
  ip: string;
  role: "src" | "dst" | "threat";
  threatCount: number;
  maxSeverity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | null;
  x: number;
  y: number;
}

interface Edge {
  id: string;
  source: string;
  target: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  threatClass: string;
  count: number;
}

const SEV_ORDER: Record<string, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function maxSev(a: string | null, b: string): string {
  if (!a) return b;
  return SEV_ORDER[a] >= SEV_ORDER[b] ? a : b;
}

function nodeColor(node: Node) {
  if (node.role === "threat") return "#f43f5e";
  if (node.maxSeverity === "CRITICAL") return "#f43f5e";
  if (node.maxSeverity === "HIGH") return "#f97316";
  if (node.maxSeverity === "MEDIUM") return "#eab308";
  return "#22d3ee";
}

function edgeColor(sev: string) {
  if (sev === "CRITICAL") return "#f43f5e";
  if (sev === "HIGH") return "#f97316";
  if (sev === "MEDIUM") return "#eab308";
  return "#22d3ee";
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "text-rose-400 border-rose-500/30 bg-rose-500/10",
  HIGH: "text-orange-400 border-orange-500/30 bg-orange-500/10",
  MEDIUM: "text-amber-400 border-amber-500/30 bg-amber-500/10",
  LOW: "text-cyan-400 border-cyan-500/30 bg-cyan-500/10",
};

function layoutNodes(nodes: Omit<Node, "x" | "y">[], width: number, height: number): Node[] {
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(cx, cy) - 60;

  if (nodes.length === 0) return [];
  if (nodes.length === 1) return [{ ...nodes[0], x: cx, y: cy }];

  return nodes.map((n, i) => {
    const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
    return {
      ...n,
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    };
  });
}

export function NetworkTopology({ alerts }: NetworkTopologyProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [width, setWidth] = useState<number | null>(null);
  const height = 400;
  const [mounted, setMounted] = useState(false);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null);
  const [subnetGroup, setSubnetGroup] = useState(false);
  const [filterSev, setFilterSev] = useState<string>("ALL");

  // Only render SVG client-side to avoid hydration mismatch
  useEffect(() => { setMounted(true); }, []);

  useEffect(() => {
    if (!svgRef.current) return;
    const obs = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w) setWidth(w);
    });
    obs.observe(svgRef.current.parentElement!);
    return () => obs.disconnect();
  }, []);

  const { nodes, edges } = useMemo(() => {
    const filteredAlerts = filterSev === "ALL"
      ? alerts
      : alerts.filter((a) => a.severity === filterSev);

    const nodeMap = new Map<string, Omit<Node, "x" | "y">>();
    const edgeMap = new Map<string, Edge & { x: number; y: number }>();

    for (const alert of filteredAlerts) {
      const srcKey = subnetGroup
        ? alert.src_ip.split(".").slice(0, 3).join(".") + ".0/24"
        : alert.src_ip;
      const dstKey = subnetGroup
        ? alert.dst_ip.split(".").slice(0, 3).join(".") + ".0/24"
        : alert.dst_ip;

      if (!nodeMap.has(srcKey)) {
        nodeMap.set(srcKey, { id: srcKey, ip: srcKey, role: "src", threatCount: 0, maxSeverity: null });
      }
      if (!nodeMap.has(dstKey)) {
        nodeMap.set(dstKey, { id: dstKey, ip: dstKey, role: "dst", threatCount: 0, maxSeverity: null });
      }

      const srcNode = nodeMap.get(srcKey)!;
      srcNode.threatCount++;
      srcNode.maxSeverity = maxSev(srcNode.maxSeverity, alert.severity) as Node["maxSeverity"];
      if (SEV_ORDER[alert.severity] >= SEV_ORDER["HIGH"]) {
        srcNode.role = "threat";
      }

      const edgeKey = `${srcKey}→${dstKey}`;
      if (!edgeMap.has(edgeKey)) {
        edgeMap.set(edgeKey, {
          id: edgeKey, source: srcKey, target: dstKey,
          severity: alert.severity, threatClass: alert.threat_class, count: 0,
          x: 0, y: 0,
        });
      }
      const edge = edgeMap.get(edgeKey)!;
      edge.count++;
      if (SEV_ORDER[alert.severity] > SEV_ORDER[edge.severity]) {
        edge.severity = alert.severity;
        edge.threatClass = alert.threat_class;
      }
    }

    const rawNodes = Array.from(nodeMap.values());
    const laidOut = layoutNodes(rawNodes, width ?? 600, height);
    const nodeById = new Map(laidOut.map((n) => [n.id, n]));

    return {
      nodes: laidOut,
      edges: Array.from(edgeMap.values()).map((e) => ({
        ...e,
        sx: nodeById.get(e.source)?.x ?? 0,
        sy: nodeById.get(e.source)?.y ?? 0,
        tx: nodeById.get(e.target)?.x ?? 0,
        ty: nodeById.get(e.target)?.y ?? 0,
      })),
    };
  }, [alerts, subnetGroup, width ?? 600, filterSev]);

  const isEmpty = alerts.length === 0;

  return (
    <div className="glass-panel rounded-xl p-5 shadow-sm">
      {/* Header */}
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center mb-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold tracking-tight text-white">
              Network Topology
            </h2>
            <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[10px] font-medium text-slate-300">
              {nodes.length} Nodes · {edges.length} Flows
            </span>
          </div>
          <p className="mt-0.5 text-xs text-slate-400">
            IP-to-IP interaction graph derived from correlated threat alerts
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Subnet toggle */}
          <button
            onClick={() => setSubnetGroup((v) => !v)}
            className={`rounded-lg border px-3 py-1.5 font-mono text-[11px] font-semibold transition-all ${
              subnetGroup
                ? "border-cyan-500/40 bg-cyan-950/30 text-cyan-300"
                : "border-slate-700 bg-slate-800/70 text-slate-300 hover:border-cyan-500/30"
            }`}
          >
            {subnetGroup ? "By Subnet /24" : "By IP"}
          </button>

          {/* Severity filter */}
          <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-[#070D1C] p-1 text-xs">
            {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setFilterSev(s)}
                className={`rounded px-2 py-1 font-mono text-[10px] font-semibold transition-colors ${
                  filterSev === s ? "bg-slate-700 text-white" : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative rounded-xl border border-slate-800/80 bg-[#060A14] overflow-hidden">
        {isEmpty ? (
          <div className="flex flex-col items-center justify-center h-64 text-center">
            <svg className="h-10 w-10 text-slate-600 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1">
              <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
            </svg>
            <p className="font-mono text-xs text-slate-400 uppercase tracking-wider">No alert flows to map</p>
            <p className="text-xs text-slate-500 mt-1">Run a simulation or ingest traffic to populate</p>
          </div>
        ) : !mounted ? (
          <div className="flex h-[400px] items-center justify-center">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-500/30 border-t-cyan-400" />
          </div>
        ) : (
          <svg
            ref={svgRef}
            width="100%"
            height={height}
            viewBox={`0 0 ${width ?? 600} ${height}`}
            className="select-none"
          >
            <defs>
              {/* Arrow markers per severity */}
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                <marker
                  key={sev}
                  id={`arrow-${sev}`}
                  markerWidth="8"
                  markerHeight="8"
                  refX="6"
                  refY="3"
                  orient="auto"
                >
                  <path d="M0,0 L0,6 L8,3 z" fill={edgeColor(sev)} fillOpacity="0.7" />
                </marker>
              ))}

              {/* Glow filter for critical nodes */}
              <filter id="glow-critical">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Edges */}
            {edges.map((edge) => {
              const isHovered = hoveredEdge === edge.id;
              const col = edgeColor(edge.severity);
              const mx = (edge.sx + edge.tx) / 2;
              const my = (edge.sy + edge.ty) / 2;
              return (
                <g key={edge.id}>
                  <line
                    x1={edge.sx}
                    y1={edge.sy}
                    x2={edge.tx}
                    y2={edge.ty}
                    stroke={col}
                    strokeOpacity={isHovered ? 0.9 : 0.35}
                    strokeWidth={isHovered ? 2.5 : edge.count > 1 ? 2 : 1.2}
                    markerEnd={`url(#arrow-${edge.severity})`}
                    onMouseEnter={() => setHoveredEdge(edge.id)}
                    onMouseLeave={() => setHoveredEdge(null)}
                    className="cursor-pointer transition-all duration-150"
                  />
                  {/* Edge label on hover */}
                  {isHovered && (
                    <g>
                      <rect
                        x={mx - 42}
                        y={my - 14}
                        width={84}
                        height={18}
                        rx={4}
                        fill="#0A1020"
                        stroke={col}
                        strokeOpacity={0.5}
                        strokeWidth={1}
                      />
                      <text
                        x={mx}
                        y={my - 2}
                        textAnchor="middle"
                        fill={col}
                        fontSize={9}
                        fontFamily="monospace"
                      >
                        {edge.threatClass} ×{edge.count}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}

            {/* Nodes */}
            {nodes.map((node) => {
              const isHov = hoveredNode === node.id;
              const col = nodeColor(node);
              const isCrit = node.maxSeverity === "CRITICAL" || node.role === "threat";
              const r = isCrit ? 14 : node.threatCount > 2 ? 12 : 9;

              return (
                <g
                  key={node.id}
                  onMouseEnter={() => setHoveredNode(node.id)}
                  onMouseLeave={() => setHoveredNode(null)}
                  className="cursor-pointer"
                >
                  {/* Pulse ring for critical */}
                  {isCrit && (
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={r + 6}
                      fill="none"
                      stroke={col}
                      strokeOpacity={0.2}
                      strokeWidth={6}
                      className="animate-ping"
                      style={{ animationDuration: "2s" }}
                    />
                  )}

                  {/* Node circle */}
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={r}
                    fill={col}
                    fillOpacity={isHov ? 0.55 : 0.25}
                    stroke={col}
                    strokeWidth={isHov ? 2.5 : 1.5}
                    strokeOpacity={isHov ? 1 : 0.7}
                    filter={isCrit ? "url(#glow-critical)" : undefined}
                    className="transition-all duration-150"
                  />

                  {/* Threat count badge */}
                  {node.threatCount > 0 && (
                    <text
                      x={node.x}
                      y={node.y + 1}
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fill={col}
                      fontSize={8}
                      fontFamily="monospace"
                      fontWeight="bold"
                    >
                      {node.threatCount > 99 ? "99+" : node.threatCount}
                    </text>
                  )}

                  {/* IP label on hover */}
                  {isHov && (
                    <g>
                      <rect
                        x={node.x - 54}
                        y={node.y + r + 4}
                        width={108}
                        height={16}
                        rx={4}
                        fill="#0A1020"
                        stroke={col}
                        strokeOpacity={0.5}
                        strokeWidth={1}
                      />
                      <text
                        x={node.x}
                        y={node.y + r + 15}
                        textAnchor="middle"
                        fill={col}
                        fontSize={9}
                        fontFamily="monospace"
                      >
                        {node.ip}
                      </text>
                    </g>
                  )}

                  {/* Small static label (short) */}
                  {!isHov && (
                    <text
                      x={node.x}
                      y={node.y + r + 13}
                      textAnchor="middle"
                      fill="#94a3b8"
                      fontSize={8}
                      fontFamily="monospace"
                    >
                      {node.ip.split(".").slice(-2).join(".")}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        )}

        {/* Legend */}
        {!isEmpty && (
          <div className="absolute bottom-3 left-3 flex flex-wrap gap-2">
            {Object.entries(SEV_COLORS).map(([sev, cls]) => (
              <span key={sev} className={`rounded border px-2 py-0.5 font-mono text-[9px] font-semibold ${cls}`}>
                {sev}
              </span>
            ))}
            <span className="rounded border border-slate-700 bg-slate-800/50 px-2 py-0.5 font-mono text-[9px] text-slate-400">
              Hover nodes/edges for details
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
