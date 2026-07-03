"use client";

import { useState, useMemo } from "react";
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
  { value: "aggregated", label: "All (Grouped)", placeholder: "Any keyword..." },
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
  try { return new Date(d).toLocaleDateString(); } catch { return d; }
}

function formatRelTime(d: string): string {
  if (!d) return "";
  const diff = Date.now() - new Date(d).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

interface CardItem {
  target: string;
  scan_uids: string[];
  ports: number[];
  technologies: string[];
  titles: string[];
  first_seen: string;
  last_seen: string;
  url?: string;
  http_status?: number;
}

function asCard(r: any): CardItem {
  const techs = Array.isArray(r.technologies) ? r.technologies : [];
  const titles: string[] = [];
  if (r.title) titles.push(r.title);
  if (r.subject) titles.push(r.subject);
  const ports: number[] = r.port != null ? [r.port] : (Array.isArray(r.ports) ? r.ports : []);
  const scanUids: string[] = [];
  if (r.scan_uid) scanUids.push(r.scan_uid);
  if (Array.isArray(r.scan_uids)) scanUids.push(...r.scan_uids);
  return {
    target: r.target || r.host || "",
    scan_uids: [...new Set(scanUids)],
    ports,
    technologies: techs,
    titles,
    first_seen: r.first_seen || r.scanned_at || "",
    last_seen: r.last_seen || r.scanned_at || "",
    url: r.url,
    http_status: r.http_status,
  };
}

function TargetCard({ card }: { card: CardItem }) {
  const hasPorts = card.ports.length > 0;
  const hasTechs = card.technologies.length > 0;
  const hasTitles = card.titles.length > 0;
  const topTitles = card.titles.filter(Boolean).slice(0, 2);
  const topTechs = card.technologies.slice(0, 6);

  return (
    <Link
      href={`/host/${card.target}`}
      className="host-card"
      style={{ display: "flex", flexDirection: "column", textDecoration: "none" }}
    >
      <div style={{ flex: 1 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#5fed83", boxShadow: "0 0 6px #5fed83" }} />
          <span style={{ fontFamily: "JetBrains Mono", fontSize: 16, fontWeight: 600, color: "#f0f6fc", flex: 1, wordBreak: "break-all" }}>
            {card.target}
          </span>
          {card.scan_uids.length > 0 && (
            <span style={{ padding: "2px 8px", background: "#283041", borderRadius: 60, fontSize: 11, color: "#8c93fb", fontFamily: "JetBrains Mono", whiteSpace: "nowrap" }}>
              {card.scan_uids.length} scan{card.scan_uids.length !== 1 ? "s" : ""}
            </span>
          )}
        </div>

        {hasTitles && (
          <div style={{ fontSize: 13, color: "#a4aea6", marginBottom: 12 }}>
            {topTitles[0]}
            {card.http_status != null && (
              <span style={{ marginLeft: 8, padding: "1px 6px", borderRadius: 4, fontSize: 10, background: card.http_status < 300 ? "rgba(95,237,131,0.2)" : "rgba(239,68,68,0.2)", color: card.http_status < 300 ? "#5fed83" : "#ef4444" }}>
                {card.http_status}
              </span>
            )}
          </div>
        )}

        <div style={{ display: "flex", gap: 16, marginBottom: 12, fontSize: 12, color: "#a4aea6" }}>
          <span><strong style={{ color: "#f0f6fc" }}>{hasPorts ? card.ports.length : 0}</strong> ports</span>
          <span><strong style={{ color: "#f0f6fc" }}>{hasTechs ? card.technologies.length : 0}</strong> techs</span>
        </div>

        {hasTechs && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 12 }}>
            {topTechs.map((t) => (
              <span key={t} style={{ padding: "2px 8px", background: "#283041", border: "1px solid #21262d", borderRadius: 60, fontSize: 10, color: "#f0f6fc" }}>
                {t}
              </span>
            ))}
          </div>
        )}

        {card.url && (
          <div style={{ fontSize: 11, color: "#8dd6ff", marginBottom: 8, wordBreak: "break-all", fontFamily: "JetBrains Mono" }}>
            {card.url}
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "space-between", paddingTop: 12, borderTop: "1px solid #21262d", fontSize: 11, color: "#818b98" }}>
          <span>First: {formatDate(card.first_seen)}</span>
          <span>Last: {formatDate(card.last_seen)}</span>
        </div>
      </div>

      {card.scan_uids.length > 1 && (
        <div style={{ display: "flex", gap: 6, paddingTop: 12, borderTop: "1px solid #21262d", flexWrap: "wrap" }}>
          {card.scan_uids.map((s) => (
            <span key={s} style={{ padding: "3px 10px", borderRadius: 60, fontFamily: "JetBrains Mono", fontSize: 10, background: "#283041", color: "#818b98" }}>
              {s.slice(0, 8)}
            </span>
          ))}
          <span style={{ marginLeft: "auto", fontSize: 10, color: "#818b98", alignSelf: "center" }}>
            click anywhere for full view →
          </span>
        </div>
      )}
    </Link>
  );
}

const PER_PAGE = 20;
const PAGE_WINDOW = 3;

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [filterType, setFilterType] = useState<FilterType>("aggregated");
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const isAggregated = filterType === "aggregated";
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  const cards = useMemo(() => {
    if (!results || results.length === 0) return [];
    return results.map(asCard);
  }, [results]);

  const doSearch = async (p = 1) => {
    if (!query.trim() && filterType !== "aggregated") return;
    setLoading(true);
    setSearched(true);
    setError(null);
    setPage(p);
    try {
      let res: any;
      const q = filterType === "port" ? parseInt(query) : query;
      switch (filterType) {
        case "aggregated":
          res = await searchAggregated(query || "", p, PER_PAGE);
          break;
        case "ip":
          res = await searchByIp(query, p, PER_PAGE);
          break;
        case "domain":
          res = await searchByDomain(query, p, PER_PAGE);
          break;
        case "port":
          res = await searchByPort(q as number, p, PER_PAGE);
          break;
        case "title":
          res = await searchByTitle(query, p, PER_PAGE);
          break;
        case "technology":
          res = await searchByTechnology(query, p, PER_PAGE);
          break;
        case "protocol":
          res = await searchByProtocol(query, p, PER_PAGE);
          break;
        case "service":
          res = await searchByService(query, p, PER_PAGE);
          break;
        case "dns":
          res = await searchByDns(query, p, PER_PAGE);
          break;
        case "ssl":
          res = await searchBySsl(query, p, PER_PAGE);
          break;
      }
      setResults(res?.data ?? []);
      setTotal(res?.total ?? 0);
    } catch (e: any) {
      setError(e.message || "Unknown error");
      setResults([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  const goToPage = (p: number) => {
    if (p < 1 || p > totalPages || loading) return;
    doSearch(p);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const pageNumbers: number[] = [];
  let startPage = Math.max(1, page - PAGE_WINDOW);
  let endPage = Math.min(totalPages, page + PAGE_WINDOW);
  if (endPage - startPage < PAGE_WINDOW * 2) {
    if (startPage === 1) endPage = Math.min(totalPages, startPage + PAGE_WINDOW * 2);
    else startPage = Math.max(1, endPage - PAGE_WINDOW * 2);
  }
  for (let i = startPage; i <= endPage; i++) pageNumbers.push(i);

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
              <option key={f.value} value={f.value}>{f.label}</option>
            ))}
          </select>
          <input
            type={filterType === "port" ? "number" : "text"}
            className="search-input"
            placeholder={filters.find((f) => f.value === filterType)?.placeholder || ""}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && doSearch()}
          />
          <button className="search-btn" onClick={() => doSearch()} disabled={loading}>
            {loading ? "Searching..." : "Search"}
          </button>
        </div>
      </div>

      {error && (
        <div className="card-panel" style={{ marginTop: 16, background: "rgba(239,68,68,0.05)", border: "1px solid rgba(239,68,68,0.3)" }}>
          <div style={{ fontSize: 12, fontFamily: "JetBrains Mono", color: "#ef4444" }}>
            ERROR: {error}
          </div>
        </div>
      )}

      {searched && (
        <div style={{ marginTop: 32 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
            <h2 className="panel-title" style={{ color: "#a4aea6", fontSize: 14, margin: 0 }}>
              {loading ? "Searching..." : `Results (${total})`}
            </h2>
            {isAggregated && !loading && (
              <span style={{ color: "#8c93fb", fontSize: 12 }}>grouped by IP</span>
            )}
            {!loading && total > 0 && (
              <span style={{ color: "#818b98", fontSize: 12, marginLeft: "auto" }}>
                Page {page} of {totalPages}
              </span>
            )}
          </div>
          {loading ? (
            <div style={{ textAlign: "center", padding: 40, color: "#818b98" }}>Searching...</div>
          ) : cards.length === 0 ? (
            <div style={{ textAlign: "center", padding: 60 }}>
              <div style={{ marginBottom: 16, opacity: 0.6 }}>
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"
                  strokeLinecap="round" strokeLinejoin="round" style={{ margin: "0 auto" }}>
                  <circle cx="11" cy="11" r="7" /><line x1="16.5" y1="16.5" x2="21" y2="21" />
                </svg>
              </div>
              <p style={{ color: "#f0f6fc", marginBottom: 8 }}>No results found</p>
            </div>
          ) : (
            <div className="cards-grid">
              {cards.map((card, i) => (
                <TargetCard key={card.target + i} card={card} />
              ))}
            </div>
          )}

          {totalPages > 1 && !loading && (
            <div className="pagination">
              <button className="page-btn" disabled={page <= 1} onClick={() => goToPage(1)} title="First page">
                ‹‹
              </button>
              <button className="page-btn" disabled={page <= 1} onClick={() => goToPage(page - 1)} title="Previous page">
                ‹
              </button>
              {startPage > 1 && <span className="page-ellipsis">…</span>}
              {pageNumbers.map((i) => (
                <button key={i} className={`page-btn${i === page ? " active" : ""}`} onClick={() => goToPage(i)}>
                  {i}
                </button>
              ))}
              {endPage < totalPages && <span className="page-ellipsis">…</span>}
              <button className="page-btn" disabled={page >= totalPages} onClick={() => goToPage(page + 1)} title="Next page">
                ›
              </button>
              <button className="page-btn" disabled={page >= totalPages} onClick={() => goToPage(totalPages)} title="Last page">
                ››
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
