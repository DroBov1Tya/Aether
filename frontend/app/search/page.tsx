"use client";

import { useState, useMemo, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  searchAggregated,
  searchByIp,
  searchByDomain,
  searchByPort,
  searchByTitle,
  searchByHeader,
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
  | "header"
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
  { value: "header", label: "HTTP Header", placeholder: "Server: nginx" },
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
  headers?: Record<string, string>;
  country?: string;
  country_code?: string;
  asn?: string;
  org?: string;
}

function parseHeaders(raw: any): Record<string, string> | undefined {
  if (!raw) return undefined;
  if (typeof raw === "object") return raw as Record<string, string>;
  if (typeof raw === "string") {
    try {
      const o = JSON.parse(raw);
      return o && Object.keys(o).length > 0 ? o : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
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
    headers: parseHeaders(r.headers),
    country: r.country || undefined,
    country_code: r.country_code || undefined,
    asn: r.asn || undefined,
    org: r.org || undefined,
  };
}

const PER_PAGE = 20;
const PAGE_WINDOW = 3;

// facet metadata: label + example queries (Shodan/IVRE-style guided querying)
const FACET_EXAMPLES: Record<FilterType, string[]> = {
  aggregated: ["nginx", "apache", "cloudflare"],
  ip: ["45.33", "93.184.216.34"],
  domain: ["example.com", "iana.org"],
  port: ["443", "22", "8080"],
  title: ["Example Domain", "login"],
  header: ["Server: nginx", "X-Powered-By: PHP", "cloudflare"],
  technology: ["nginx", "WordPress", "PHP"],
  protocol: ["tcp", "udp"],
  service: ["http", "https", "ssh"],
  dns: ["example.com", "8.8.8.8"],
  ssl: ["DigiCert", "example.com"],
};

function SearchInner() {
  const router = useRouter();
  const params = useSearchParams();
  const [query, setQuery] = useState("");
  const [filterType, setFilterType] = useState<FilterType>("aggregated");
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState(0);

  const isAggregated = filterType === "aggregated";
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  const cards = useMemo(() => {
    if (!results || results.length === 0) return [];
    return results.map(asCard);
  }, [results]);

  const runSearch = async (
    q: string,
    type: FilterType,
    p = 1,
  ) => {
    if (!q.trim() && type !== "aggregated") return;
    setLoading(true);
    setSearched(true);
    setError(null);
    setPage(p);
    try {
      let res: any;
      const numeric = type === "port" ? parseInt(q) : q;
      switch (type) {
        case "aggregated": res = await searchAggregated(q || "", p, PER_PAGE); break;
        case "ip": res = await searchByIp(q, p, PER_PAGE); break;
        case "domain": res = await searchByDomain(q, p, PER_PAGE); break;
        case "port": res = await searchByPort(numeric as number, p, PER_PAGE); break;
        case "title": res = await searchByTitle(q, p, PER_PAGE); break;
        case "header": res = await searchByHeader(q, p, PER_PAGE); break;
        case "technology": res = await searchByTechnology(q, p, PER_PAGE); break;
        case "protocol": res = await searchByProtocol(q, p, PER_PAGE); break;
        case "service": res = await searchByService(q, p, PER_PAGE); break;
        case "dns": res = await searchByDns(q, p, PER_PAGE); break;
        case "ssl": res = await searchBySsl(q, p, PER_PAGE); break;
      }
      setResults(res?.data ?? []);
      setTotal(res?.total ?? 0);
      setSelected(0);
    } catch (e: any) {
      setError(e.message || "Unknown error");
      setResults([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  // deep-link: hydrate from ?q= &type= (home hero + command palette drive this)
  useEffect(() => {
    const q = params.get("q") ?? "";
    const t = (params.get("type") as FilterType) ?? "aggregated";
    const validType = FACET_EXAMPLES[t] ? t : "aggregated";
    setQuery(q);
    setFilterType(validType);
    if (q || validType === "aggregated") {
      runSearch(q, validType, 1);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params]);

  const submit = (q = query, t = filterType) => {
    // reflect in URL so the search is shareable / palette-driven
    const usp = new URLSearchParams();
    if (q) usp.set("q", q);
    usp.set("type", t);
    router.replace(`/search?${usp.toString()}`);
    runSearch(q, t, 1);
  };

  const pickFacet = (t: FilterType) => {
    setFilterType(t);
    if (query || t === "aggregated") submit(query, t);
  };

  const goToPage = (p: number) => {
    if (p < 1 || p > totalPages || loading) return;
    runSearch(query, filterType, p);
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

  const activeFacet = filters.find((f) => f.value === filterType)!;
  const sel = cards[selected];

  return (
    <div className="page-container search-page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Search</h1>
          <p className="page-subtitle">
            Query the index by host, port, technology, DNS or certificate
          </p>
        </div>
      </div>

      {/* Query bar (full width) */}
      <div className="query-bar" style={{ marginBottom: 18 }}>
        <span className="query-facet-tag">{activeFacet.label}</span>
        <input
          type={filterType === "port" ? "number" : "text"}
          className="query-input"
          placeholder={activeFacet.placeholder}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
          autoFocus
        />
        <button className="query-run" onClick={() => submit()} disabled={loading}>
          {loading ? "…" : "Search"}
        </button>
      </div>

      {error && <div className="query-error" style={{ marginTop: 0, marginBottom: 18 }}>ERROR: {error}</div>}

      {/* Three-pane analyst layout */}
      <div className="analyst">
        {/* left: dimension facets */}
        <aside className="analyst-facets">
          <div className="panel">
            <div className="pt">Dimension</div>
            <div className="dim-list">
              {filters.map((f) => (
                <button
                  key={f.value}
                  className={`dim-item${filterType === f.value ? " is-active" : ""}`}
                  onClick={() => pickFacet(f.value)}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>
          {!searched && (
            <div className="panel">
              <div className="pt">Examples</div>
              <div className="dim-examples">
                {FACET_EXAMPLES[filterType].map((ex) => (
                  <button key={ex} className="query-example-chip" onClick={() => { setQuery(ex); submit(ex, filterType); }}>
                    {ex}
                  </button>
                ))}
              </div>
            </div>
          )}
        </aside>

        {/* center: result list */}
        <main className="analyst-list">
          <div className="results-head">
            <span className="results-count">
              {loading ? "Searching…" : searched ? `${total} result${total !== 1 ? "s" : ""}` : "Ready"}
            </span>
            {isAggregated && !loading && searched && <span className="results-note">grouped by host</span>}
            {!loading && total > 0 && <span className="results-page">Page {page} / {totalPages}</span>}
          </div>

          {loading ? (
            <div>
              {[0, 1, 2, 3].map((i) => (
                <div key={i} className="host-row compact" style={{ pointerEvents: "none" }}>
                  <div className="skeleton" style={{ minHeight: 46, borderRadius: 8, gridColumn: "1 / -1" }} />
                </div>
              ))}
            </div>
          ) : !searched ? (
            <div className="analyst-hint">
              <p>Pick a dimension and enter a query, or try an example.</p>
            </div>
          ) : cards.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon" aria-hidden="true">
                <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" style={{ margin: "0 auto" }}>
                  <circle cx="11" cy="11" r="7" /><line x1="16.5" y1="16.5" x2="21" y2="21" />
                </svg>
              </div>
              <p className="empty-title">No results</p>
              <p className="empty-desc">Try a different dimension or a broader term.</p>
            </div>
          ) : (
            <div>
              {cards.map((card, i) => (
                <button
                  key={card.target + i}
                  className={`host-row compact analyst-row${i === selected ? " is-selected" : ""}`}
                  onClick={() => setSelected(i)}
                >
                  <div className="hr-flag" aria-hidden="true">
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.35" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="8" cy="8" r="6" /><ellipse cx="8" cy="8" rx="3" ry="6" /><line x1="2.2" y1="8" x2="13.8" y2="8" />
                    </svg>
                  </div>
                  <div className="hr-main">
                    <div className="hr-top">
                      <span className="hr-ip">{card.target}</span>
                      {card.titles[0] && <span className="hr-host">{card.titles[0]}</span>}
                    </div>
                    <div className="hr-meta">
                      {card.ports.length > 0 && <span><b>{card.ports.length}</b> ports</span>}
                      {card.technologies.length > 0 && <span><b>{card.technologies.length}</b> tech</span>}
                      {card.scan_uids.length > 1 && <span><b>{card.scan_uids.length}</b> scans</span>}
                      {card.country && <span className="hr-geo">{card.country_code || card.country}</span>}
                    </div>
                  </div>
                  <div className="hr-side">
                    {card.last_seen && <span className="hr-time">{formatRelTime(card.last_seen)}</span>}
                  </div>
                </button>
              ))}
            </div>
          )}

          {totalPages > 1 && !loading && (
            <div className="pagination">
              <button className="page-btn" disabled={page <= 1} onClick={() => goToPage(1)} title="First page">‹‹</button>
              <button className="page-btn" disabled={page <= 1} onClick={() => goToPage(page - 1)} title="Previous page">‹</button>
              {startPage > 1 && <span className="page-ellipsis">…</span>}
              {pageNumbers.map((i) => (
                <button key={i} className={`page-btn${i === page ? " active" : ""}`} onClick={() => goToPage(i)}>{i}</button>
              ))}
              {endPage < totalPages && <span className="page-ellipsis">…</span>}
              <button className="page-btn" disabled={page >= totalPages} onClick={() => goToPage(page + 1)} title="Next page">›</button>
              <button className="page-btn" disabled={page >= totalPages} onClick={() => goToPage(totalPages)} title="Last page">››</button>
            </div>
          )}
        </main>

        {/* right: detail inspector */}
        <aside className="analyst-detail">
          {sel ? (
            <div className="panel inspector">
              <div className="insp-ip">{sel.target}</div>
              {sel.titles[0] && <div className="insp-title">{sel.titles[0]}</div>}
              <div className="insp-metrics">
                <div className="insp-metric"><div className="mv" style={{ color: "var(--state-ok)" }}>{sel.ports.length}</div><div className="ml">Ports</div></div>
                <div className="insp-metric"><div className="mv" style={{ color: "var(--color-champagne)" }}>{sel.technologies.length}</div><div className="ml">Tech</div></div>
                <div className="insp-metric"><div className="mv" style={{ color: "var(--state-active)" }}>{sel.scan_uids.length}</div><div className="ml">Scans</div></div>
              </div>

              {sel.ports.length > 0 && (
                <>
                  <div className="insp-label">Open Ports</div>
                  <div className="hr-ports" style={{ marginTop: 0 }}>
                    {sel.ports.slice(0, 16).map((p) => <span key={p} className="pchip hot">{p}</span>)}
                  </div>
                </>
              )}

              {sel.technologies.length > 0 && (
                <>
                  <div className="insp-label" style={{ marginTop: 18 }}>Technologies</div>
                  <div className="hr-techs" style={{ justifyContent: "flex-start", maxWidth: "none" }}>
                    {sel.technologies.slice(0, 12).map((t) => <span key={t} className="tchip">{t}</span>)}
                  </div>
                </>
              )}

              {(sel.country || sel.asn || sel.org) && (
                <>
                  <div className="insp-label" style={{ marginTop: 18 }}>Location</div>
                  <div className="insp-geo">
                    {sel.country && (
                      <div className="insp-geo-row">
                        <span className="insp-geo-k">Country</span>
                        <span className="insp-geo-v">
                          {sel.country}{sel.country_code ? ` (${sel.country_code})` : ""}
                        </span>
                      </div>
                    )}
                    {sel.asn && (
                      <div className="insp-geo-row">
                        <span className="insp-geo-k">ASN</span>
                        <span className="insp-geo-v">{sel.asn}</span>
                      </div>
                    )}
                    {sel.org && (
                      <div className="insp-geo-row">
                        <span className="insp-geo-k">Org</span>
                        <span className="insp-geo-v">{sel.org}</span>
                      </div>
                    )}
                  </div>
                </>
              )}

              {sel.headers && Object.keys(sel.headers).length > 0 && (
                <>
                  <div className="insp-label" style={{ marginTop: 18 }}>HTTP Headers</div>
                  <div className="insp-headers">
                    {Object.entries(sel.headers)
                      .sort(([a], [b]) => a.localeCompare(b))
                      .slice(0, 12)
                      .map(([k, v]) => (
                        <div key={k} className="insp-hdr-row">
                          <span className="insp-hdr-k">{k}</span>
                          <span className="insp-hdr-v">{v}</span>
                        </div>
                      ))}
                  </div>
                </>
              )}

              {sel.url && (
                <>
                  <div className="insp-label" style={{ marginTop: 18 }}>URL</div>
                  <div className="insp-url">{sel.url}</div>
                </>
              )}

              <div className="insp-times">
                <span>First {formatDate(sel.first_seen)}</span>
                <span>Last {formatDate(sel.last_seen)}</span>
              </div>

              <Link href={`/host/${encodeURIComponent(sel.target)}`} className="insp-open">
                Open full report →
              </Link>
            </div>
          ) : (
            <div className="panel inspector-empty">
              <p>Select a result to inspect it here.</p>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

export default function SearchPage() {
  return (
    <Suspense fallback={<div className="page-container"><div style={{ color: "var(--color-text-muted)" }}>Loading…</div></div>}>
      <SearchInner />
    </Suspense>
  );
}
