import { getStatsSummary, getRecentScans } from "@/lib/api";
import StatBox from "@/components/stat-box";
import HostCard from "@/components/host-card";
import Link from "next/link";

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toString();
}

export default async function HomePage() {
  let stats = null;
  let scans: { target: string; port?: number; technologies: string[] }[] = [];

  try {
    stats = await getStatsSummary();
  } catch (e) {
    console.warn(e);
  }
  try {
    scans = await getRecentScans();
  } catch (e) {
    console.warn(e);
  }

  return (
    <div>
      <section className="hero">
        <h1 className="hero-title">
          Private Internet
          <br />
          Observatory
        </h1>

        <p className="hero-subtitle">
          Advanced network reconnaissance and intelligence platform
        </p>

        <div className="search-container">
          <form action="/search" className="search-row">
            <input
              name="q"
              type="text"
              placeholder="Search by IP, port, technology..."
              className="search-input"
            />
            <button type="submit" className="search-btn">
              Search
            </button>
          </form>
          <div className="search-hint">
            <kbd>↵</kbd>
            <span>to search</span>
          </div>
        </div>

        {stats && (
          <div className="stats-grid">
            <StatBox label="HOSTS" value={formatNumber(stats.total_hosts)} />
            <StatBox label="PORTS" value={formatNumber(stats.total_ports)} />
            <StatBox
              label="SERVICES"
              value={formatNumber(stats.total_services)}
            />
            <StatBox
              label="TECHNOLOGIES"
              value={formatNumber(stats.total_technologies)}
            />
          </div>
        )}
      </section>

      <div className="section-divider" />

      <section className="section">
        <h2 className="section-title">Recent Scans</h2>

        {scans.length > 0 ? (
          <div className="cards-grid">
            {scans.map((h) => (
              <HostCard key={h.target} host={h} />
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">
              <svg
                width="40"
                height="40"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                style={{ opacity: 0.5, margin: "0 auto" }}
              >
                <circle cx="12" cy="12" r="2" fill="currentColor" />
                <path d="M16.24 7.76a6 6 0 0 1 0 8.49" />
                <path d="M19.07 4.93a10 10 0 0 1 0 14.14" />
                <path d="M7.76 16.24a6 6 0 0 1 0-8.49" />
                <path d="M4.93 19.07a10 10 0 0 1 0-14.14" />
              </svg>
            </div>
            <p className="empty-title">No scans yet</p>
            <p className="empty-desc">
              Run your first scan to see results here
            </p>
            <Link
              href="/scans"
              className="mt-6 inline-block rounded-md bg-emerald px-6 py-3 text-sm font-semibold text-white"
            >
              Go to Scan Manager
            </Link>
          </div>
        )}
      </section>
    </div>
  );
}
