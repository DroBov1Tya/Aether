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

interface CardTarget {
  target: string;
  scan_uids: string[];
  ports: number[];
  technologies: string[];
  titles: string[];
  first_seen: string;
  last_seen: string;
}

function groupResults(rows: any[]): CardTarget[] {
  if (!rows || rows.length === 0) return [];

  const map = new Map<string, CardTarget>();

  for (const r of rows) {
    const t = r.target || r.host || "";
    if (!t) continue;

    let c = map.get(t);
    if (!c) {
      c = { target: t, scan_uids: [], ports: [], technologies: [], titles: [], first_seen: "", last_seen: "" };
      map.set(t, c);
    }

    if (r.scan_uid && !c.scan_uids.includes(r.scan_uid)) c.scan_uids.push(r.scan_uid);

    if (r.port && !c.ports.includes(r.port)) c.ports.push(r.port);

    if (r.technologies) {
      const techs = Array.isArray(r.technologies) ? r.technologies : [];
      for (const tech of techs) { if (!c.technologies.includes(tech)) c.technologies.push(tech); }
    }

    if (r.title && !c.titles.includes(r.title)) c.titles.push(r.title);
    if (r.subject && !c.titles.includes(r.subject)) c.titles.push(r.subject);

    if (r.scanned_at) {
      if (!c.first_seen || r.scanned_at < c.first_seen) c.first_seen = r.scanned_at;
      if (!c.last_seen || r.scanned_at > c.last_seen) c.last_seen = r.scanned_at;
    }
  }

  for (const c of map.values()) {
    c.scan_uids.sort((a, b) => b.localeCompare(a));
    c.ports.sort((a, b) => a - b);
  }

  return Array.from(map.values());
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

function TargetCard({ card }: { card: CardTarget }) {
  const [selIdx, setSelIdx] = useState(0);
  const topTechs = card.technologies.slice(0, 6);
  const topTitles = card.titles.filter(Boolean).slice(0, 2);

  return (
    <Link
      href={`/host/${card.target}`}
      className="host-card"
      style={{ display: "flex", flexDirection: "column", textDecoration: "none" }}
    >
      <div style={{ flex: 1 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#5fed83", boxShadow: "0 0 6px #5fed83" }} />
          <span style={{ fontFamily: "JetBrains Mono", fontSize: 16, fontWeight: 600, color: "#f0f6fc", flex: 1 }}>
            {card.target}
          </span>
          <span style={{ padding: "2px 8px", background: "#283041", borderRadius: 60, fontSize: 11, color: "#8c93fb", fontFamily: "JetBrains Mono" }}>
            {card.scan_uids.length} scan{card.scan_uids.length !== 1 ? "s" : ""}
          </span>
        </div>
        {topTitles.length > 0 && (
          <div style={{ fontSize: 13, color: "#a4aea6", marginBottom: 12 }}>{topTitles[0]}</div>
        )}
        <div style={{ display: "flex", gap: 16, marginBottom: 12, fontSize: 12, color: "#a4aea6" }}>
          <span><strong style={{ color: "#f0f6fc" }}>{card.ports.length}</strong> ports</span>
          <span><strong style={{ color: "#f0f6fc" }}>{card.technologies.length}</strong> techs</span>
        </div>
        {topTechs.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 12 }}>
            {topTechs.map((t) => (
              <span key={t} style={{ padding: "2px 8px", background: "#283041", border: "1px solid #21262d", borderRadius: 60, fontSize: 10, color: "#f0f6fc" }}>
                {t}
              </span>
            ))}
          </div>
        )}
        <div style={{ display: "flex", justifyContent: "space-between", paddingTop: 12, borderTop: "1px solid #21262d", fontSize: 11, color: "#818b98" }}>
          <span>First: {formatDate(card.first_seen)}</span>
          <span>Last: {formatDate(card.last_seen)}</span>
        </div>
      </div>

      {card.scan_uids.length > 1 && (
        <div style={{ display: "flex", gap: 6, paddingTop: 12, borderTop: "1px solid #21262d", flexWrap: "wrap" }}>
          {card.scan_uids.map((s, i) => (
            <button
              key={s}
              onClick={(e) => { e.stopPropagation(); setSelIdx(i); }}
              style={{
                padding: "3px 10px", borderRadius: 60, border: "none", cursor: "pointer",
                fontFamily: "JetBrains Mono", fontSize: 10,
                background: i === selIdx ? "#8c93fb" : "#283041",
                color: i === selIdx ? "#0d1117" : "#818b98",
              }}
              title={`Scan ${s} — ${formatRelTime(card.last_seen)}`}
            >
              {s.slice(0, 8)}
            </button>
          ))}
          <span style={{ marginLeft: "auto", fontSize: 10, color: "#818b98", alignSelf: "center" }}>
            click anywhere for full view →
          </span>
        </div>
      )}
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

  const isAggregated = filterType === "aggregated";

  const cards = useMemo(() => {
    if (!results || results.length === 0) return [];
    if (isAggregated) {
      const seen = new Set<string>();
      return (results as AggregatedHost[]).filter((r) => {
        if (seen.has(r.target)) return false;
        seen.add(r.target);
        return true;
      }).map((r) => ({
        target: r.target,
        scan_uids: r.scan_uids || [],
        ports: r.ports || [],
        technologies: r.technologies || [],
        titles: r.titles || [],
        first_seen: r.first_seen,
        last_seen: r.last_seen,
      }));
    }
    return groupResults(results);
  }, [results, isAggregated]);

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
          <button className="search-btn" onClick={doSearch} disabled={loading}>
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
          <h2 className="panel-title" style={{ marginBottom: 16, color: "#a4aea6", fontSize: 14 }}>
            {loading ? "Searching..." : `Targets (${cards.length})`}
            {isAggregated && !loading && (
              <span style={{ color: "#8c93fb", marginLeft: 8 }}>• grouped by IP</span>
            )}
          </h2>
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
        </div>
      )}
    </div>
  );
}
