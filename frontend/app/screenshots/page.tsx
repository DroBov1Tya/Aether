"use client";

import { useEffect, useState, useCallback } from "react";
import { listScreenshots, countScreenshots, ScreenshotWithMeta } from "@/lib/api";

const PER_PAGE = 20;

function formatDate(d: string) {
  try {
    return new Date(d).toLocaleDateString("ru-RU", {
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", hour12: false,
    });
  } catch {
    return d;
  }
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* ignore */ }
  }, [text]);
  return (
    <button onClick={handleCopy} style={{
      background: "none", border: "1px solid var(--color-border-subtle)",
      borderRadius: 6, cursor: "pointer", padding: "6px 8px",
      display: "inline-flex", alignItems: "center", gap: 6,
      color: copied ? "#5fed83" : "var(--color-text-muted)",
      fontSize: 12, fontFamily: "var(--font-mono)",
      transition: "color 0.2s",
    }}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
        stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
      </svg>
      {copied ? "copied" : "copy"}
    </button>
  );
}

function ScreenshotThumbnail({ target, port }: { target: string; port: number }) {
  const [src, setSrc] = useState<string | null>(null);
  const [hasError, setHasError] = useState(false);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`/api/proxy/api/screenshots/${target}/${port}`);
        if (!res.ok) { setHasError(true); return; }
        const blob = await res.blob();
        if (!cancelled) setSrc(URL.createObjectURL(blob));
      } catch {
        if (!cancelled) setHasError(true);
      }
    })();
    return () => { cancelled = true; if (src) URL.revokeObjectURL(src); };
  }, [target, port]);
  if (hasError) return (
    <div style={{
      aspectRatio: "16/10", background: "rgba(0,0,0,0.4)",
      display: "flex", alignItems: "center", justifyContent: "center",
    }}>
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none"
        stroke="#818b98" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z" />
        <circle cx="12" cy="13" r="4" />
      </svg>
    </div>
  );
  if (!src) return (
    <div style={{
      aspectRatio: "16/10", width: "100%",
      background: "rgba(255,255,255,0.03)",
      animation: "pulse 1.5s ease-in-out infinite",
    }} />
  );
  return (
    <img src={src} alt={`${target}:${port}`} style={{
      width: "100%", height: "100%", objectFit: "cover",
      display: "block",
    }} />
  );
}

function buildMarkdown(s: ScreenshotWithMeta): string {
  const lines: string[] = [];
  lines.push(`# ${s.target}:${s.port}`);
  lines.push("");
  if (s.http_status) lines.push(`- **Status**: ${s.http_status}`);
  if (s.title) lines.push(`- **Title**: ${s.title}`);
  if (s.technologies?.length) lines.push(`- **Technologies**: ${s.technologies.join(", ")}`);
  lines.push(`- **Taken at**: ${formatDate(s.taken_at)}`);
  return lines.join("\n");
}

function DetailModal({ s, onClose }: { s: ScreenshotWithMeta; onClose: () => void }) {
  const md = buildMarkdown(s);
  return (
    <div onClick={onClose} style={{
      position: "fixed", inset: 0, zIndex: 1000,
      background: "rgba(0,0,0,0.75)",
      display: "flex", alignItems: "center", justifyContent: "center",
      padding: 24,
    }}>
      <div onClick={(e) => e.stopPropagation()} className="card-panel" style={{
        maxWidth: 720, width: "100%", maxHeight: "90vh", overflow: "auto",
        position: "relative",
      }}>
        <button onClick={onClose} style={{
          position: "absolute", top: 12, right: 12,
          background: "none", border: "none", cursor: "pointer",
          color: "var(--color-text-muted)", padding: 4,
        }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        </button>

        <div style={{ borderRadius: 8, overflow: "hidden", marginBottom: 20 }}>
          <ScreenshotThumbnail target={s.target} port={s.port} />
        </div>

        <div style={{
          background: "rgba(0,0,0,0.3)", borderRadius: 8, padding: 16,
          fontFamily: "var(--font-mono)", fontSize: 13, lineHeight: 1.7,
          color: "#f0f6fc", whiteSpace: "pre-wrap", position: "relative",
        }}>
          <div style={{ position: "absolute", top: 12, right: 12 }}>
            <CopyButton text={md} />
          </div>
          {md.split("\n").map((line, i) => {
            if (line.startsWith("# ")) return <div key={i} style={{
              fontSize: 18, fontWeight: 700, color: "#fff",
              marginBottom: 12, paddingRight: 70,
            }}>{line.slice(2)}</div>;
            if (line.startsWith("- **")) {
              const match = line.match(/- \*\*(.+?)\*\*: (.+)/);
              if (!match) return <div key={i}>{line}</div>;
              return (
                <div key={i} style={{ marginBottom: 4, display: "flex", gap: 8 }}>
                  <span style={{ color: "#8c93fb", whiteSpace: "nowrap" }}>{match[1]}:</span>
                  <span style={{ color: "#a4aea6" }}>{match[2]}</span>
                </div>
              );
            }
            return <div key={i}>{line}</div>;
          })}
        </div>
      </div>
    </div>
  );
}

export default function ScreenshotsPage() {
  const [screenshots, setScreenshots] = useState<ScreenshotWithMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<ScreenshotWithMeta | null>(null);

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  const loadPage = useCallback(async (p: number) => {
    setLoading(true);
    try {
      const [data, cnt] = await Promise.all([
        listScreenshots(p, PER_PAGE),
        countScreenshots(),
      ]);
      setScreenshots(data);
      setTotal(cnt.total);
    } catch (e) {
      console.error("Failed to load screenshots:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPage(page);
  }, [page, loadPage]);

  const goToPage = (p: number) => {
    if (p < 1 || p > totalPages) return;
    setPage(p);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const pages: number[] = [];
  const maxVisible = 7;
  let startPage = Math.max(1, page - Math.floor(maxVisible / 2));
  let endPage = Math.min(totalPages, startPage + maxVisible - 1);
  if (endPage - startPage + 1 < maxVisible) {
    startPage = Math.max(1, endPage - maxVisible + 1);
  }
  for (let i = startPage; i <= endPage; i++) pages.push(i);

  return (
    <div className="page-container">
      <h1 className="page-title">SCREENSHOTS GALLERY</h1>
      <p style={{ color: "#818b98", marginBottom: 32 }}>
        Visual reconnaissance of discovered web services
        {total > 0 && <span style={{ marginLeft: 8, color: "#a4aea6" }}>
          — {total} total
        </span>}
      </p>

      {screenshots.length === 0 && !loading && (
        <div style={{ textAlign: "center", padding: 80 }}>
          <div style={{ marginBottom: 16, opacity: 0.6 }}>
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ margin: "0 auto" }}>
              <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z" />
              <circle cx="12" cy="13" r="4" />
            </svg>
          </div>
          <p style={{ color: "#f0f6fc", marginBottom: 8 }}>No screenshots yet</p>
          <p style={{ color: "#818b98" }}>Screenshots will appear here after scans with HXN enabled</p>
        </div>
      )}

      <div className="screenshots-grid">
        {screenshots.map((s, i) => (
          <div
            key={`${s.target}-${s.port}-${i}`}
            className="screenshot-card-gallery"
            onClick={() => setSelected(s)}
          >
            <div style={{ aspectRatio: "16/10", overflow: "hidden", position: "relative" }}>
              <ScreenshotThumbnail target={s.target} port={s.port} />
              <div style={{
                position: "absolute", top: 8, right: 8,
                padding: "2px 8px", background: "rgba(0,0,0,0.6)",
                borderRadius: 4, fontSize: 10, color: "#a4aea6",
                fontFamily: "JetBrains Mono, monospace",
              }}>
                :{s.port}
              </div>
            </div>
            <div style={{ padding: 12 }}>
              <div style={{
                fontFamily: "JetBrains Mono, monospace", fontSize: 13,
                color: "#f0f6fc", marginBottom: 4,
              }}>
                {s.target}
              </div>
              <div style={{
                display: "flex", alignItems: "center", gap: 8, fontSize: 11, color: "#818b98",
              }}>
                <span>{formatDate(s.taken_at)}</span>
                {s.http_status && (
                  <span style={{
                    padding: "1px 6px", borderRadius: 60, fontSize: 10,
                    background: s.http_status < 300 ? "rgba(95,237,131,0.2)" : "rgba(240,192,0,0.2)",
                    color: s.http_status < 300 ? "#5fed83" : "#f0c000",
                  }}>
                    {s.http_status}
                  </span>
                )}
              </div>
              {s.title && (
                <div style={{ fontSize: 11, color: "#a4aea6", marginTop: 6, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {s.title}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {totalPages > 1 && !loading && (
        <div style={{
          display: "flex", alignItems: "center", justifyContent: "center",
          gap: 6, marginTop: 40,
        }}>
          <button
            className="secondary-btn"
            style={{ padding: "8px 14px", fontSize: 12, lineHeight: 1 }}
            disabled={page === 1}
            onClick={() => goToPage(1)}
          >
            {'<<'}
          </button>
          <button
            className="secondary-btn"
            style={{ padding: "8px 14px", fontSize: 12, lineHeight: 1 }}
            disabled={page === 1}
            onClick={() => goToPage(page - 1)}
          >
            {'<'}
          </button>
          {pages.map((p) => (
            <button
              key={p}
              className={p === page ? "search-btn" : "secondary-btn"}
              style={p === page
                ? { padding: "8px 14px", fontSize: 12, lineHeight: 1, minWidth: 36 }
                : { padding: "8px 14px", fontSize: 12, lineHeight: 1, minWidth: 36 }
              }
              onClick={() => goToPage(p)}
            >
              {p}
            </button>
          ))}
          <button
            className="secondary-btn"
            style={{ padding: "8px 14px", fontSize: 12, lineHeight: 1 }}
            disabled={page === totalPages}
            onClick={() => goToPage(page + 1)}
          >
            {'>'}
          </button>
          <button
            className="secondary-btn"
            style={{ padding: "8px 14px", fontSize: 12, lineHeight: 1 }}
            disabled={page === totalPages}
            onClick={() => goToPage(totalPages)}
          >
            {'>>'}
          </button>
          <span style={{
            fontSize: 11, color: "#818b98", fontFamily: "JetBrains Mono, monospace",
            marginLeft: 8,
          }}>
            {page} / {totalPages}
          </span>
        </div>
      )}

      {loading && (
        <div style={{ textAlign: "center", padding: 40, color: "#818b98" }}>
          Loading...
        </div>
      )}

      {selected && (
        <DetailModal s={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}