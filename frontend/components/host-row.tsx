import Link from "next/link";

export interface HostRowData {
  target: string;
  title?: string;
  url?: string;
  http_status?: number;
  ports?: Array<{ port: number; service?: string }>;
  technologies?: string[];
  scanned_at?: string;
  scan_count?: number;
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
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

const STATUS_TONE = (s?: number) =>
  s == null ? "var(--color-text-muted)" : s < 300 ? "var(--state-ok)" : s < 400 ? "var(--state-warn)" : "var(--state-danger)";

export default function HostRow({
  host,
  compact = false,
}: {
  host: HostRowData;
  compact?: boolean;
}) {
  const ports = host.ports ?? [];
  const techs = host.technologies ?? [];
  const shownTechs = techs.slice(0, compact ? 3 : 4);

  return (
    <Link
      href={`/host/${encodeURIComponent(host.target)}`}
      className={`host-row${compact ? " compact" : ""}`}
    >
      <div className="hr-flag" aria-hidden="true">
        <svg width="18" height="18" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.35" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="8" cy="8" r="6" />
          <ellipse cx="8" cy="8" rx="3" ry="6" />
          <line x1="2.2" y1="8" x2="13.8" y2="8" />
        </svg>
      </div>

      <div className="hr-main">
        <div className="hr-top">
          <span className="hr-ip">{host.target}</span>
          {host.title && <span className="hr-host">{host.title}</span>}
          {host.http_status != null && (
            <span className="hr-status" style={{ color: STATUS_TONE(host.http_status) }}>
              {host.http_status}
            </span>
          )}
        </div>
        <div className="hr-meta">
          {ports.length > 0 && <span><b>{ports.length}</b> open ports</span>}
          {techs.length > 0 && <span><b>{techs.length}</b> technologies</span>}
          {host.scan_count != null && host.scan_count > 1 && (
            <span><b>{host.scan_count}</b> scans</span>
          )}
          {host.url && <span className="hr-url">{host.url}</span>}
        </div>
        {ports.length > 0 && (
          <div className="hr-ports">
            {ports.slice(0, 8).map((p) => (
              <span key={p.port} className="pchip hot">
                {p.port}{p.service ? ` · ${p.service}` : ""}
              </span>
            ))}
            {ports.length > 8 && <span className="pchip">+{ports.length - 8}</span>}
          </div>
        )}
      </div>

      <div className="hr-side">
        {host.scanned_at && <span className="hr-time">{relTime(host.scanned_at)}</span>}
        {shownTechs.length > 0 && (
          <div className="hr-techs">
            {shownTechs.map((t) => (
              <span key={t} className="tchip">{t}</span>
            ))}
          </div>
        )}
      </div>
    </Link>
  );
}
