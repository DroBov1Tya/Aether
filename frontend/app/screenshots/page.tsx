"use client";

import { useEffect, useState } from "react";
import { listScreenshots, ScreenshotWithMeta } from "@/lib/api";
import Link from "next/link";

function formatDate(d: string) {
  try {
    return new Date(d).toLocaleDateString();
  } catch {
    return d;
  }
}

export default function ScreenshotsPage() {
  const [screenshots, setScreenshots] = useState<ScreenshotWithMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);

  const loadMore = async () => {
    setLoading(true);
    try {
      const data = await listScreenshots(page, 40);
      setScreenshots((prev) => (page === 1 ? data : [...prev, ...data]));
      setHasMore(data.length === 40);
    } catch (e) {
      console.error("Failed to load screenshots:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMore();
  }, [page]);

  return (
    <div className="page-container">
      <h1 className="page-title">SCREENSHOTS GALLERY</h1>
      <p style={{ color: "#818b98", marginBottom: 32 }}>
        Visual reconnaissance of discovered web services
      </p>

      {screenshots.length === 0 && !loading && (
        <div style={{ textAlign: "center", padding: 80 }}>
          <div style={{ marginBottom: 16, opacity: 0.6 }}>
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ margin: "0 auto" }}>
              <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z" />
              <circle cx="12" cy="13" r="4" />
            </svg>
          </div>
          <p style={{ color: "#f0f6fc", marginBottom: 8 }}>
            No screenshots yet
          </p>
          <p style={{ color: "#818b98" }}>
            Screenshots will appear here after scans with HXN enabled
          </p>
        </div>
      )}

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
          gap: 16,
          position: "relative",
        }}
      >
        {screenshots.map((s, i) => (
          <div
            key={`${s.target}-${s.port}-${i}`}
            onMouseEnter={() => setHoveredIdx(i)}
            onMouseLeave={() => setHoveredIdx(null)}
            style={{ position: "relative" }}
          >
            <Link href={`/host/${s.target}`} style={{ textDecoration: "none" }}>
              <div
                style={{
                  border: "1px solid #21262d",
                  borderRadius: 8,
                  overflow: "hidden",
                  transition: "all 0.3s",
                  background: "rgba(21, 26, 34, 0.8)",
                  cursor: "pointer",
                }}
              >
                <div
                  style={{
                    aspectRatio: "16/10",
                    background: "rgba(0,0,0,0.4)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    position: "relative",
                    overflow: "hidden",
                  }}
                >
                  {s.image_base64 ? (
                    <img
                      src={`data:image/png;base64,${s.image_base64}`}
                      alt={`${s.target}:${s.port}`}
                      style={{
                        width: "100%",
                        height: "100%",
                        objectFit: "cover",
                      }}
                    />
                  ) : (
                    <>
                      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.3, position: "absolute" }}>
                        <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z" />
                        <circle cx="12" cy="13" r="4" />
                      </svg>
                      <div
                        style={{
                          position: "absolute",
                          top: 8,
                          right: 8,
                          padding: "2px 8px",
                          background: "rgba(0,0,0,0.6)",
                          borderRadius: 4,
                          fontSize: 10,
                          color: "#a4aea6",
                          fontFamily: "JetBrains Mono",
                        }}
                      >
                        :{s.port}
                      </div>
                    </>
                  )}
                </div>

                <div style={{ padding: 12 }}>
                  <div
                    style={{
                      fontFamily: "JetBrains Mono",
                      fontSize: 13,
                      color: "#f0f6fc",
                      marginBottom: 4,
                    }}
                  >
                    {s.target}
                  </div>
                  <div style={{ fontSize: 11, color: "#818b98" }}>
                    {formatDate(s.taken_at)}
                  </div>
                </div>
              </div>
            </Link>

            {hoveredIdx === i && (
              <div
                style={{
                  position: "absolute",
                  bottom: "100%",
                  left: "50%",
                  transform: "translateX(-50%)",
                  marginBottom: 8,
                  padding: 12,
                  background: "rgba(13, 17, 23, 0.98)",
                  border: "1px solid rgba(140, 147, 251, 0.3)",
                  borderRadius: 8,
                  minWidth: 240,
                  maxWidth: 300,
                  zIndex: 100,
                  boxShadow: "0 8px 24px rgba(0,0,0,0.5)",
                  pointerEvents: "none",
                }}
              >
                <div
                  style={{
                    fontFamily: "JetBrains Mono",
                    fontSize: 13,
                    color: "#f0f6fc",
                    marginBottom: 8,
                  }}
                >
                  {s.target}:{s.port}
                  {s.http_status && (
                    <span
                      style={{
                        marginLeft: 8,
                        padding: "1px 6px",
                        background:
                          s.http_status < 300
                            ? "rgba(95,237,131,0.2)"
                            : "rgba(240,192,0,0.2)",
                        color: s.http_status < 300 ? "#5fed83" : "#f0c000",
                        borderRadius: 60,
                        fontSize: 10,
                      }}
                    >
                      {s.http_status}
                    </span>
                  )}
                </div>
                {s.title && (
                  <div
                    style={{ fontSize: 12, color: "#a4aea6", marginBottom: 8 }}
                  >
                    {s.title}
                  </div>
                )}
                {s.technologies && s.technologies.length > 0 && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {s.technologies.slice(0, 6).map((t: string) => (
                      <span
                        key={t}
                        style={{
                          padding: "1px 6px",
                          background: "#283041",
                          borderRadius: 60,
                          fontSize: 10,
                          color: "#a4aea6",
                        }}
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                )}
                <div style={{ marginTop: 8, fontSize: 10, color: "#8c93fb" }}>
                  Click to view details →
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {hasMore && !loading && (
        <div style={{ textAlign: "center", marginTop: 40 }}>
          <button className="search-btn" onClick={() => setPage((p) => p + 1)}>
            Load More
          </button>
        </div>
      )}

      {loading && (
        <div style={{ textAlign: "center", padding: 40, color: "#818b98" }}>
          Loading...
        </div>
      )}
    </div>
  );
}
