import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Navbar } from "@/components/layout/Navbar";
import { FeedbackModal } from "@/components/feedback/FeedbackModal";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
  weight: ["300", "400", "500", "600", "700", "800", "900"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  display: "swap",
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "SentinelFlow — AI Network Threat Detection",
  description:
    "SentinelFlow uses dual AI/ML models to detect network threats like DDoS, C2 beacons, and data exfiltration in real time. Try a live demo.",
  keywords: ["network security", "threat detection", "AI", "machine learning", "DDoS", "SIEM", "SOC"],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-[#04070f] text-slate-100">
        <Navbar />
        <main className="flex-1">{children}</main>
        <footer className="border-t border-white/[0.04] py-5 text-center">
          <p className="text-xs text-slate-600 font-mono tracking-wide">
            SentinelFlow v1.0 · AI-Powered Network Threat Detection · Passive Read-Only Monitor
          </p>
        </footer>
        <FeedbackModal />
      </body>
    </html>
  );
}
