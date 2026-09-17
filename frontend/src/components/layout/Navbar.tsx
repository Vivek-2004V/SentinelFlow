"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_LINKS = [
  { href: "/", label: "Home", exact: true },
  { href: "/dashboard", label: "Dashboard", exact: false },
  { href: "/simulation", label: "Attack Demo", exact: false },
  { href: "/analytics", label: "Analytics", exact: false },
  { href: "/tools", label: "Tools", exact: false },
];

export function Navbar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [apiOk, setApiOk] = useState<boolean | null>(null);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 10);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"}/api/v1/status`,
          { cache: "no-store", signal: AbortSignal.timeout(3000) }
        );
        setApiOk(res.ok);
      } catch {
        setApiOk(false);
      }
    };
    check();
    const id = setInterval(check, 30000);
    return () => clearInterval(id);
  }, []);

  const isActive = (href: string, exact: boolean) =>
    exact ? pathname === href : pathname.startsWith(href);

  return (
    <nav
      className={`sticky top-0 z-50 w-full transition-all duration-300 ${
        scrolled
          ? "border-b border-white/5 bg-[#04070f]/95 backdrop-blur-2xl shadow-[0_1px_0_rgba(34,211,238,0.08)]"
          : "border-b border-white/[0.04] bg-[#04070f]/80 backdrop-blur-xl"
      }`}
    >
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 md:px-8">
        {/* Brand */}
        <Link href="/" className="flex items-center gap-3 group">
          <div className="relative flex h-9 w-9 items-center justify-center">
            {/* Animated ring */}
            <div className="absolute inset-0 rounded-xl border border-cyan-400/30 group-hover:border-cyan-400/60 transition-colors duration-300" />
            <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/10" />
            <svg className="relative h-5 w-5 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <div className="hidden sm:block">
            <div className="text-base font-bold tracking-tight">
              <span className="text-white">Sentinel</span>
              <span className="gradient-text">Flow</span>
            </div>
            <div className="text-[10px] text-slate-500 -mt-0.5 font-medium tracking-wide">AI Threat Detection</div>
          </div>
        </Link>

        {/* Desktop Nav */}
        <div className="hidden md:flex items-center gap-1 rounded-xl border border-white/[0.06] bg-white/[0.03] px-2 py-1.5">
          {NAV_LINKS.map(({ href, label, exact }) => {
            const active = isActive(href, exact);
            return (
              <Link
                key={href}
                href={href}
                className={`relative px-4 py-1.5 rounded-lg text-sm font-medium transition-all duration-200 ${
                  active
                    ? "text-white bg-white/10"
                    : "text-slate-400 hover:text-slate-200 hover:bg-white/[0.05]"
                }`}
              >
                {label}
                {active && <span className="nav-underline" />}
              </Link>
            );
          })}
        </div>

        {/* Right Controls */}
        <div className="flex items-center gap-2.5">
          {/* Status pill */}
          <div
            className={`hidden sm:flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold transition-all duration-500 ${
              apiOk === null
                ? "border-slate-700/50 bg-slate-800/30 text-slate-500"
                : apiOk
                ? "border-emerald-500/20 bg-emerald-950/30 text-emerald-400"
                : "border-amber-500/20 bg-amber-950/30 text-amber-400"
            }`}
          >
            {apiOk ? (
              <span className="live-dot" />
            ) : (
              <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
            )}
            {apiOk === null ? "Connecting…" : apiOk ? "Live" : "Demo"}
          </div>

          {/* CTA */}
          <Link
            href="/simulation"
            className="btn-primary hidden lg:flex items-center gap-2 !py-2 !px-4 !text-sm"
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z" />
            </svg>
            Try Demo
          </Link>

          {/* Mobile toggle */}
          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="md:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] transition-colors"
            aria-label="Toggle menu"
          >
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d={mobileOpen ? "M6 18L18 6M6 6l12 12" : "M4 6h16M4 12h16M4 18h16"} />
            </svg>
          </button>
        </div>
      </div>

      {/* Mobile Dropdown */}
      {mobileOpen && (
        <div className="md:hidden border-t border-white/[0.05] bg-[#04070f]/98 px-4 py-3 space-y-1 animate-fade-in">
          {NAV_LINKS.map(({ href, label, exact }) => {
            const active = isActive(href, exact);
            return (
              <Link
                key={href}
                href={href}
                onClick={() => setMobileOpen(false)}
                className={`flex items-center gap-3 rounded-xl px-4 py-2.5 text-sm font-medium transition-colors ${
                  active
                    ? "bg-white/[0.08] text-white"
                    : "text-slate-400 hover:text-white hover:bg-white/[0.04]"
                }`}
              >
                {label}
                {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-400" />}
              </Link>
            );
          })}
        </div>
      )}
    </nav>
  );
}
