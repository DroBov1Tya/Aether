"use client";

import { useState } from "react";
import {
  searchAggregated,
  searchByIp,
  searchByDomain,
  searchByPort,
  searchByTitle,
  searchByTechnology,
  searchByProtocol,
  searchByService,
  searchByDns,
  searchBySsl,
  AggregatedHost,
} from "@/lib/api";
import Link from "next/link";

type FilterType =
  | "aggregated"
  | "ip"
  | "domain"
  | "port"
  | "title"
  | "technology"
  | "protocol"
  | "service"
  | "dns"
  | "ssl";

const filters: { value: FilterType; label: string; placeholder: string }[] = [
  {
    value: "aggregated",
    label: "All (Grouped)",
    placeholder: "Any keyword...",
  },
  { value: "ip", label: "IP Address", placeholder: "192.168.1.1" },
  { value: "domain", label: "Domain", placeholder: "example.com" },
  { value: "port", label: "Port", placeholder: "443" },
  { value: "title", label: "Title", placeholder: "Apache" },
  { value: "technology", label: "Technology", placeholder: "WordPress" },
  { value: "protocol", label: "Protocol", placeholder: "tcp" },
  { value: "service", label: "Service", placeholder: "http" },
  { value: "dns", label: "DNS Record", placeholder: "example.com or IP" },
  { value: "ssl", label: "SSL/Cert", placeholder: "issuer, CN, SAN..." },
];

function formatDate(d: string) {
  try {
    return new Date(d).toLocaleDateString();
  } catch {
    return d;
  }
}

function HostSummaryCard({ host }: { host: AggregatedHost }) {
  const topTechs = (host.technologies || []).slice(0, 6);
  const topTitles = (host.titles || []).filter(Boolean).slice(0, 2);
  // ИСПРАВЛЕНО: добавлен encodeURIComponent
  const encodedTarget = encodeURIComponent(host.target);
  return (
    <Link
      href={`/host/${encodedTarget}`}
      className="host-card"
      style={{ display: "block", textDecoration: "none" }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          marginBottom: 16,
        }}
      >
        <div
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: "#5fed83",
            boxShadow: "0 0 6px #5fed83",
          }}
        />
        <span
          style={{
            fontFamily: "JetBrains Mono",
            fontSize: 16,
            fontWeight: 600,
            color: "#f0f6fc",
            flex: 1,
          }}
        >
          {host.target}
        </span>
        <span
          style={{
            padding: "2px 8px",
            background: "#283041",
            borderRadius: 60,
            fontSize: 11,
            color: "#8c93fb",
            fontFamily: "JetBrains Mono",
          }}
        >
          {host.scan_count} scan{host.scan_count !== 1 ? "s" : ""}
        </span>
      </div>
      {topTitles.length > 0 && (
        <div style={{ fontSize: 13, color: "#a4aea6", marginBottom: 12 }}>
          {topTitles[0]}
        </div>
      )}
      <div
        style={{
          display: "flex",
          gap: 16,
          marginBottom: 12,
          fontSize: 12,
          color: "#a4aea6",
        }}
      >
        <span>
          <strong style={{ color: "#f0f6fc" }}>
            {(host.ports || []).length}
          </strong>{" "}
          ports
        </span>
        <span>
          <strong style={{ color: "#f0f6fc" }}>
            {(host.technologies || []).length}
          </strong>{" "}
          techs
        </span>
      </div>
      {topTechs.length > 0 && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 4,
            marginBottom: 12,
          }}
        >
          {topTechs.map((t) => (
            <span
              key={t}
              style={{
                padding: "2px 8px",
                background: "#283041",
                border: "1px solid #21262d",
                borderRadius: 60,
                fontSize: 10,
                color: "#f0f6fc",
              }}
            >
              {t}
            </span>
          ))}
        </div>
      )}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          paddingTop: 12,
          borderTop: "1px solid #21262d",
          fontSize: 11,
          color: "#818b98",
        }}
      >
        <span>First: {formatDate(host.first_seen)}</span>
        <span>Last: {formatDate(host.last_seen)}</span>
      </div>
    </Link>
  );
}

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [filterType, setFilterType] = useState<FilterType>("aggregated");
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const doSearch = async () => {
    if (!query.trim() && filterType !== "aggregated") return;
    setLoading(true);
    setSearched(true);
    setError(null);
    setResults([]);
    try {
      let data;
      const q = filterType === "port" ? parseInt(query) : query;
      switch (filterType) {
        case "aggregated":
          data = await searchAggregated(query || "");
          break;
        case "ip":
          data = await searchByIp(query);
          break;
        case "domain":
          data = await searchByDomain(query);
          break;
        case "port":
          data = await searchByPort(q as number);
          break;
        case "title":
          data = await searchByTitle(query);
          break;
        case "technology":
          data = await searchByTechnology(query);
          break;
        case "protocol":
          data = await searchByProtocol(query);
          break;
        case "service":
          data = await searchByService(query);
          break;
        case "dns":
          data = await searchByDns(query);
          break;
        case "ssl":
          data = await searchBySsl(query);
          break;
      }
      setResults(Array.isArray(data) ? data : []);
    } catch (e: any) {
      setError(e.message || "Unknown error");
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  const isAggregated = filterType === "aggregated";

  return (
    <div className="page-container">
      <h1 className="page-title">ADVANCED SEARCH</h1>
      <div className="card-panel">
        <div className="search-row" style={{ marginBottom: 24 }}>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value as FilterType)}
            className="search-select"
          >
            {filters.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
          <input
            type={filterType === "port" ? "number" : "text"}
            className="search-input"
            placeholder={
              filters.find((f) => f.value === filterType)?.placeholder || ""
            }
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && doSearch()}
          />
          <button className="search-btn" onClick={doSearch} disabled={loading}>
            {loading ? "Searching..." : "Search"}
          </button>
        </div>
      </div>

      {error && (
        <div
          className="card-panel"
          style={{
            marginTop: 16,
            background: "rgba(239,68,68,0.05)",
            border: "1px solid rgba(239,68,68,0.3)",
          }}
        >
          <div
            style={{
              fontSize: 12,
              fontFamily: "JetBrains Mono",
              color: "#ef4444",
            }}
          >
            ERROR: {error}
          </div>
        </div>
      )}

      {searched && (
        <div style={{ marginTop: 32 }}>
          <h2
            className="panel-title"
            style={{ marginBottom: 16, color: "#a4aea6", fontSize: 14 }}
          >
            {loading ? "Searching..." : `Results (${results.length})`}
            {isAggregated && !loading && (
              <span style={{ color: "#8c93fb", marginLeft: 8 }}>
                • grouped by IP
              </span>
            )}
          </h2>
          {loading ? (
            <div style={{ textAlign: "center", padding: 40, color: "#818b98" }}>
              Searching...
            </div>
          ) : results.length === 0 ? (
            <div style={{ textAlign: "center", padding: 60 }}>
              <div style={{ marginBottom: 16, opacity: 0.6 }}>
                <svg
                  width="48"
                  height="48"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  style={{ margin: "0 auto" }}
                >
                  <circle cx="11" cy="11" r="7" />
                  <line x1="16.5" y1="16.5" x2="21" y2="21" />
                </svg>
              </div>
              <p style={{ color: "#f0f6fc", marginBottom: 8 }}>
                No results found
              </p>
            </div>
          ) : isAggregated ? (
            <div className="cards-grid">
              {results.map((host, i) => (
                <HostSummaryCard key={i} host={host as AggregatedHost} />
              ))}
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {results.map((r, i) => {
                // ИСПРАВЛЕНО: безопасное извлечение target с encodeURIComponent
                const target = r.target || r.host || "";
                const encodedTarget = encodeURIComponent(target);
                return (
                  <Link
                    key={i}
                    href={`/host/${encodedTarget}`}
                    style={{
                      display: "block",
                      padding: 16,
                      background: "rgba(0,0,0,0.3)",
                      border: "1px solid #21262d",
                      borderRadius: 8,
                      textDecoration: "none",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 12,
                        flexWrap: "wrap",
                      }}
                    >
                      <div
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: "50%",
                          background: "#5fed83",
                        }}
                      />
                      <span
                        style={{
                          fontFamily: "JetBrains Mono",
                          fontSize: 14,
                          color: "#f0f6fc",
                        }}
                      >
                        {target}
                        {r.port ? `:${r.port}` : ""}
                      </span>
                      {r.http_status && (
                        <span
                          style={{
                            padding: "2px 8px",
                            borderRadius: 60,
                            fontSize: 11,
                            background:
                              r.http_status < 300
                                ? "rgba(95,237,131,0.2)"
                                : "rgba(240,192,0,0.2)",
                            color: r.http_status < 300 ? "#5fed83" : "#f0c000",
                          }}
                        >
                          {r.http_status}
                        </span>
                      )}
                      {(r.title || r.subject) && (
                        <span style={{ fontSize: 13, color: "#a4aea6" }}>
                          {r.title || r.subject}
                        </span>
                      )}
                    </div>
                    {r.technologies && r.technologies.length > 0 && (
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: 4,
                          marginTop: 8,
                        }}
                      >
                        {r.technologies.slice(0, 6).map((t: string) => (
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
                    {r.san && r.san.length > 0 && (
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: 4,
                          marginTop: 8,
                        }}
                      >
                        {r.san.slice(0, 4).map((s: string) => (
                          <span
                            key={s}
                            style={{
                              padding: "1px 6px",
                              background: "rgba(141,214,255,0.1)",
                              borderRadius: 60,
                              fontSize: 10,
                              color: "#8dd6ff",
                            }}
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    )}
                  </Link>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
