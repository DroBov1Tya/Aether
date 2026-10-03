import type { Metadata } from "next";
import Nav from "@/components/nav";
import CommandPalette from "@/components/command-palette";
import "@/globals.css";

export const metadata: Metadata = {
  title: "Aether — Private Internet Observatory",
  description: "Advanced network reconnaissance and intelligence platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        {/* Black Water ambient: still pools of warm light held deep
            beneath a polished obsidian surface. Sparse, controlled. */}
        <div className="aurora-blob aurora-1" />
        <div className="aurora-blob aurora-2" />
        <div className="grid-overlay" />
        <div className="water-ripple" aria-hidden="true">
          {[0, 1, 2].map((i) => (
            <svg
              key={i}
              viewBox="0 0 1440 300"
              preserveAspectRatio="none"
              className={`ripple-${i + 1}`}
            >
              <defs>
                <linearGradient id={`wave-${i}`} x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor="rgba(233, 184, 114,0)" />
                  <stop offset="45%" stopColor="rgba(233, 184, 114,0.14)" />
                  <stop offset="55%" stopColor="rgba(233, 184, 114,0.14)" />
                  <stop offset="100%" stopColor="rgba(233, 184, 114,0)" />
                </linearGradient>
              </defs>
              <path
                d="M0,150 C180,124 320,168 480,150 C660,130 760,172 920,152 C1100,130 1240,166 1440,146"
                fill="none"
                stroke={`url(#wave-${i})`}
                strokeWidth="1"
              />
              <path
                d="M0,182 C200,160 360,196 540,178 C720,160 860,198 1040,180 C1220,162 1320,196 1440,176"
                fill="none"
                stroke="rgba(194, 136, 74,0.05)"
                strokeWidth="1"
              />
            </svg>
          ))}
        </div>
        <div className="vignette-overlay" />

        <Nav />
        <CommandPalette />
        <main className="content-layer animate-fade-in">{children}</main>
      </body>
    </html>
  );
}
