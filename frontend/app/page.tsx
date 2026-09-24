import {
  getStatsSummary,
  getTopPorts,
  getTopTechnologies,
  searchAggregated,
  type AggregatedHost,
} from "@/lib/api";
import HostRow, { type HostRowData } from "@/components/host-row";
import FacetPanel from "@/components/facet-panel";
import HomeSearch from "@/components/home-search";
import Link from "next/link";

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toString();
}

function relTime(s?: string): string {
  if (!s) return "";
  const d = new Date(s.includes("T") ? s : s.replace(" ", "T") + "Z");
  if (isNaN(d.getTime())) return "";
  const mins = Math.floor((Date.now() - d.getTime()) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default async function HomePage() {
  const [stats, ports, techs, recent] = await Promise.all([
    getStatsSummary().catch(() => null),
    getTopPorts(6).catch(() => []),
    getTopTechnologies(6).catch(() => []),
    searchAggregated("", 1, 6)
      .then((r) => r.data ?? [])
      .catch(() => [] as AggregatedHost[]),
  ]);

  const topPortStr = ports.slice(0, 3).map((p) => p.port).join(" · ");
  const topTech = techs[0]?.technology;
  const lastSeen = recent[0]?.last_seen;

  const rows: HostRowData[] = recent.map((h) => ({
    target: h.target,
    title: h.titles?.[0],
    url: h.url,
    http_status: h.http_status,
    ports: (h.ports ?? []).map((p) => ({ port: p })),
    technologies: h.technologies ?? [],
    scanned_at: h.last_seen,
    scan_count: h.scan_count,
  }));

  return (
    <div className="page-container home-page">
      {/* Console hero */}
      <section className="console">
        <div className="console-eyebrow">
          {lastSeen ? `Index live · last scan ${relTime(lastSeen)}` : "Index ready"}
        </div>
        <h1 className="console-title">
          Private Internet
          <br />
          Observatory
        </h1>
        <p className="console-sub">
          Query indexed hosts, ports, services and certificates across your recon surface.
        </p>

        <HomeSearch />

        {stats && (
          <div className="metrics">
            <div className="m">
              <div className="mv">{fmt(stats.total_hosts)}</div>
              <div className="ml">Hosts</div>
              <div className="md">{recent.length > 0 ? "indexed" : "—"}</div>
            </div>
            <div className="m">
              <div className="mv">{fmt(stats.total_ports)}</div>
              <div className="ml">Open Ports</div>
              <div className="md">{topPortStr || "—"}</div>
            </div>
            <div className="m">
              <div className="mv">{fmt(stats.total_services)}</div>
              <div className="ml">Services</div>
              <div className="md">unique</div>
            </div>
            <div className="m">
              <div className="mv">{fmt(stats.total_technologies)}</div>
              <div className="ml">Technologies</div>
              <div className="md">{topTech ? `${topTech} leads` : "—"}</div>
            </div>
          </div>
        )}
      </section>

      {/* Activity + breakdown */}
      <div className="home-grid">
        <main>
          <div className="section-label">
            <h2>Recent Activity</h2>
            <span className="note">latest snapshots</span>
            <Link className="more" href="/search?type=aggregated">view all →</Link>
          </div>

          {rows.length > 0 ? (
            <div>
              {rows.map((h) => (
                <HostRow key={h.target} host={h} />
              ))}
            </div>
          ) : (
            <div className="empty-state" style={{ padding: "80px 24px" }}>
              <div className="empty-icon" aria-hidden="true">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" style={{ margin: "0 auto" }}>
                  <circle cx="12" cy="12" r="2" fill="currentColor" />
                  <path d="M16.24 7.76a6 6 0 0 1 0 8.49" />
                  <path d="M7.76 16.24a6 6 0 0 1 0-8.49" />
                </svg>
              </div>
              <p className="empty-title">No scans yet</p>
              <p className="empty-desc">Run your first scan to populate the index.</p>
              <Link href="/scans" className="empty-cta">Go to Scan Manager →</Link>
            </div>
          )}
        </main>

        <aside className="home-side">
          <FacetPanel
            title="Top Ports"
            statsHref="/stats"
            rows={ports.map((p) => ({ label: String(p.port), count: p.count }))}
            hrefFor={(l) => `/search?q=${l}&type=port`}
          />
          <FacetPanel
            title="Top Technologies"
            statsHref="/stats"
            rows={techs.map((t) => ({ label: t.technology, count: t.count }))}
            hrefFor={(l) => `/search?q=${encodeURIComponent(l)}&type=technology`}
          />
          <div className="panel">
            <div className="pt">Quick Actions</div>
            <div className="qa">
              <Link href="/scans" className="qa-item">
                <span className="qa-ico">
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><circle cx="8" cy="8" r="6" /><circle cx="8" cy="8" r="2" fill="currentColor" stroke="none" /></svg>
                </span>
                New scan
              </Link>
              <Link href="/screenshots" className="qa-item">
                <span className="qa-ico">
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><rect x="2" y="3" width="12" height="10" rx="1.5" /><path d="M3 12l3.5-3.5 3 3" /></svg>
                </span>
                Screenshots
              </Link>
              <Link href="/agents" className="qa-item">
                <span className="qa-ico">
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><rect x="2.5" y="3" width="11" height="7" rx="1.5" /><line x1="6" y1="13" x2="10" y2="13" /></svg>
                </span>
                Agents
              </Link>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
