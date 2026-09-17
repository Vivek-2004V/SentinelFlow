"use client";

import React from "react";

export type NavSection =
  | "overview"
  | "quality-gate"
  | "pcap"
  | "sniffer"
  | "topology"
  | "traffic"
  | "threats"
  | "chains"
  | "alerts"
  | "health"
  | "simulation";

interface SidebarProps {
  activeSection: NavSection;
  onSelectSection: (section: NavSection) => void;
  isOpen: boolean;
  onToggle: () => void;
}

interface NavItem {
  id: NavSection;
  label: string;
  description: string;
  emoji: string;
  badge?: string | number;
  badgeColor?: string;
}

export function Sidebar({ activeSection, onSelectSection, isOpen, onToggle }: SidebarProps) {

  const demoItems: NavItem[] = [
    {
      id: "simulation",
      label: "Attack Demo",
      description: "Simulate threats",
      emoji: "🧪",
      badge: "TRY ME",
      badgeColor: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    },
  ];

  const monitorItems: NavItem[] = [
    {
      id: "overview",
      label: "Dashboard",
      description: "Live overview",
      emoji: "🏠",
    },
    {
      id: "alerts",
      label: "Threat Alerts",
      description: "Detected threats",
      emoji: "🚨",
      badge: "Live",
      badgeColor: "bg-rose-500/20 text-rose-300 border-rose-500/30",
    },
    {
      id: "traffic",
      label: "Live Traffic",
      description: "Network flows",
      emoji: "📊",
    },
    {
      id: "topology",
      label: "Network Map",
      description: "IP connections",
      emoji: "🗺️",
    },
    {
      id: "chains",
      label: "Attack Timeline",
      description: "Multi-stage attacks",
      emoji: "🔗",
    },
  ];

  const toolItems: NavItem[] = [
    {
      id: "pcap",
      label: "Analyze File",
      description: "Upload .pcap file",
      emoji: "📁",
      badge: "PCAP",
      badgeColor: "bg-cyan-500/20 text-cyan-300 border-cyan-500/30",
    },
    {
      id: "sniffer",
      label: "Live Monitor",
      description: "Watch network live",
      emoji: "📡",
      badge: "Live",
      badgeColor: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
    },
    {
      id: "quality-gate",
      label: "AI Model Status",
      description: "ML health check",
      emoji: "🤖",
    },
    {
      id: "health",
      label: "System Status",
      description: "Server & sensors",
      emoji: "⚙️",
    },
  ];

  const renderNavItem = (item: NavItem) => {
    const active = activeSection === item.id;
    return (
      <button
        key={item.id}
        onClick={() => onSelectSection(item.id)}
        className={`flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left transition-all ${
          active
            ? "border border-cyan-500/20 bg-cyan-950/30 text-white shadow-[inset_0_0_12px_rgba(56,189,248,0.08)]"
            : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200 border border-transparent"
        }`}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="text-base shrink-0">{item.emoji}</span>
          <div className="min-w-0">
            <div className={`text-xs font-semibold truncate ${active ? "text-white" : "text-slate-300"}`}>
              {item.label}
            </div>
            <div className="text-[10px] text-slate-500 truncate">{item.description}</div>
          </div>
        </div>
        {item.badge && (
          <span
            className={`ml-1 shrink-0 rounded border px-1.5 py-0.5 font-mono text-[9px] font-semibold ${
              active
                ? item.badgeColor ?? "bg-cyan-500/20 text-cyan-300 border-cyan-500/30"
                : "bg-slate-800 text-slate-500 border-slate-700"
            }`}
          >
            {item.badge}
          </span>
        )}
      </button>
    );
  };

  return (
    <>
      {/* Mobile Toggle Button */}
      <button
        onClick={onToggle}
        className="fixed bottom-4 left-4 z-40 flex h-10 w-10 items-center justify-center rounded-full border border-slate-700 bg-slate-900 text-slate-300 shadow-lg md:hidden"
        aria-label="Toggle navigation"
      >
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d={isOpen ? "M6 18L18 6M6 6l12 12" : "M4 6h16M4 12h16M4 18h16"} />
        </svg>
      </button>

      {/* Sidebar Container */}
      <aside
        className={`fixed inset-y-0 left-0 z-30 flex w-60 flex-col border-r border-slate-800/80 bg-[#070B14] pt-16 transition-transform duration-200 md:static md:translate-x-0 ${
          isOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex flex-1 flex-col gap-4 overflow-y-auto p-3">

          {/* Quick Start */}
          <div>
            <div className="px-2 pb-1 text-[10px] font-semibold tracking-widest text-amber-400/70 uppercase">
              ⚡ Quick Start
            </div>
            <div className="space-y-0.5">
              {demoItems.map(renderNavItem)}
            </div>
          </div>

          {/* Monitor */}
          <div>
            <div className="px-2 pb-1 text-[10px] font-semibold tracking-widest text-slate-500 uppercase">
              Monitor
            </div>
            <div className="space-y-0.5">
              {monitorItems.map(renderNavItem)}
            </div>
          </div>

          {/* Tools */}
          <div>
            <div className="px-2 pb-1 text-[10px] font-semibold tracking-widest text-slate-500 uppercase">
              Tools
            </div>
            <div className="space-y-0.5">
              {toolItems.map(renderNavItem)}
            </div>
          </div>

          {/* Bottom read-only badge */}
          <div className="mt-auto rounded-lg border border-slate-800 bg-[#0B1120] p-3">
            <div className="flex items-center gap-2">
              <span className="text-sm">🔒</span>
              <span className="font-semibold text-[11px] text-cyan-400">Read-Only Mode</span>
            </div>
            <p className="mt-1 text-[10px] leading-relaxed text-slate-400">
              This tool only watches your network — it never sends packets or blocks traffic.
            </p>
          </div>
        </div>
      </aside>
    </>
  );
}
