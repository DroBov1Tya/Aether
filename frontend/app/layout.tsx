import type { Metadata } from "next";
import Nav from "@/components/nav";
import Fireflies from "@/components/Fireflies";
import "@/globals.css";

export const metadata: Metadata = {
  title: "Aether - Private Internet Observatory",
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
        <div className="aurora-blob aurora-1" />
        <div className="aurora-blob aurora-2" />
        <div className="aurora-blob aurora-3" />
        <div className="grid-overlay" />
        {[...Array(10)].map((_, i) => (
          <div
            key={i}
            className="particle"
            style={{
              left: `${8 + i * 9}%`,
              width: `${2 + (i % 3)}px`,
              height: `${2 + (i % 3)}px`,
              background: i < 5 ? "#8c93fb" : i < 8 ? "#5fed83" : "#8dd6ff",
              boxShadow: `0 0 ${8 + i * 2}px ${i < 5 ? "rgba(140,147,251,0.6)" : i < 8 ? "rgba(95,237,131,0.5)" : "rgba(141,214,255,0.5)"}`,
              animationDuration: `${15 + (i % 5) * 3}s`,
              animationDelay: `${-(i * 2.5)}s`,
            }}
          />
        ))}
        <Fireflies />

        <Nav />
        <main className="relative z-10 animate-fade-in">{children}</main>
      </body>
    </html>
  );
}
