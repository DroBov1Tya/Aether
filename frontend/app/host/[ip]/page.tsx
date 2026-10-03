"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

interface NmapEntry {
  port: number;
  protocol: string;
  state: string;
  service?: string;
  product?: string;
  version?: string;
  confidence?: number;
  detection_method?: string;
  extra_info?: string;
  os_type?: string;
  state_reason?: string;
  banner?: string;
  cpe?: string;
  scripts?: string;
  os_name?: string;
  os_accuracy?: number;
  ttl?: number;
  scanned_at: string;
  scan_uid?: string;
}

interface WhatWebEntry {
  port: number;
  url?: string;
  http_status?: number;
  title?: string;
  technologies: string[];
  server?: string;
  powered_by?: string;
  meta_generator?: string;
  headers?: Record<string, string>;
  scanned_at: string;
  scan_uid?: string;
}

interface GeoInfo {
  target?: string;
  country?: string;
  country_code?: string;
  city?: string;
  lat?: number;
  lon?: number;
  asn?: string;
  org?: string;
  isp?: string;
}

interface ScreenshotEntry {
  port: number;
  s3_key: string;
  file_size: number;
  taken_at: string;
  scan_uid?: string;
}

interface DnsRecord {
  a?: string[];
  aaaa?: string[];
  cname?: string[];
  mx?: string[];
  ns?: string[];
  txt?: string[];
  ptr?: string[];
  scanned_at: string;
}

interface SslCert {
  port: number;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  serial: string;
  san: string[];
  ssl_version: string;
  cipher: string;
  chain_length: number;
  scanned_at: string;
  scan_uid?: string;
}

interface FuzzEntry {
  port: number;
  path: string;
  url: string;
  http_status: number;
  scanned_at: string;
}

interface ScanCluster {
  scan_uid: string;
  centerTime: number;
  nmap: NmapEntry[];
  whatweb: WhatWebEntry[];
  screenshots: ScreenshotEntry[];
  ssl: SslCert[];
}

function ScreenshotImage({ ip, port }: { ip: string; port: number }) {
  const [src, setSrc] = useState<string | null>(null);
  const [hasError, setHasError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // Прокси обрабатывает путь нативно — без encodeURIComponent.
        const res = await fetch(`/api/proxy/api/screenshots/${ip}/${port}`);
        if (!res.ok) {
          console.warn("screenshot fetch failed", res.status);
          setHasError(true);
          return;
        }
        const blob = await res.blob();
        if (!cancelled) setSrc(URL.createObjectURL(blob));
      } catch (e) {
        if (!cancelled) {
          console.warn("screenshot fetch error", e);
          setHasError(true);
        }
      }
    })();
    return () => {
      cancelled = true;
      if (src) URL.revokeObjectURL(src);
    };
  }, [ip, port]);

  if (hasError) return null;
  if (!src)
    return (
      <div className="screenshot-img-wrap">
        <div className="skeleton" />
      </div>
    );
  return (
    <div className="screenshot-img-wrap">
      <img src={src} alt={`Port ${port}`} className="screenshot-img" />
    </div>
  );
}

function formatDate(d: string | number): string {
  if (!d) return "—";
  try {
    let ts: number;
    if (typeof d === "number") {
      ts = d;
    } else {
      const iso = d.replace(" ", "T") + "+03:00";
      ts = new Date(iso).getTime();
    }
    if (isNaN(ts)) return String(d);
    return new Intl.DateTimeFormat("ru-RU", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
      timeZone: "Europe/Moscow",
    }).format(new Date(ts));
  } catch {
    return String(d);
  }
}

function formatRelative(d: string | number): string {
  if (!d) return "";
  try {
    const ts = typeof d === "number" ? d : (() => {
      const iso = (d as string).replace(" ", "T") + "+03:00";
      return new Date(iso).getTime();
    })();
    const diff = Date.now() - ts;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days === 1) return "yesterday";
    if (days < 7) return `${days}d ago`;
    if (days < 30) return `${Math.floor(days / 7)}w ago`;
    return `${Math.floor(days / 30)}mo ago`;
  } catch {
    return "";
  }
}

function extractDomainFromSubject(subject: string): string[] {
  const domains: string[] = [];
  const cnMatch = subject.match(/CN\s*=\s*([^,]+)/i);
  if (cnMatch) {
    const cn = cnMatch[1].trim();
    domains.push(cn);
    if (cn.startsWith("*.")) domains.push(cn.substring(2));
  }
  return domains;
}

function clusterEvents(
  nmap: NmapEntry[],
  whatweb: WhatWebEntry[],
  screenshots: ScreenshotEntry[],
  ssl: SslCert[],
): ScanCluster[] {
  const uidMap = new Map<string, ScanCluster>();

  const assign = (
    e: { scan_uid?: string; scanned_at?: string; taken_at?: string },
    type: "nmap" | "whatweb" | "screenshot" | "ssl",
    data: any,
  ) => {
    const uid = e.scan_uid || "unknown";
    let c = uidMap.get(uid);
    if (!c) {
      c = {
        scan_uid: uid,
        centerTime: 0,
        nmap: [],
        whatweb: [],
        screenshots: [],
        ssl: [],
      };
      uidMap.set(uid, c);
    }
    if (type === "nmap") c.nmap.push(data);
    else if (type === "whatweb") c.whatweb.push(data);
    else if (type === "screenshot") c.screenshots.push(data);
    else if (type === "ssl") c.ssl.push(data);
  };

  nmap.forEach((e) => assign(e, "nmap", e));
  whatweb.forEach((e) => assign(e, "whatweb", e));
  screenshots.forEach((e) => assign(e, "screenshot", e));
  ssl.forEach((e) => assign(e, "ssl", e));

  const clusters = Array.from(uidMap.values());

  for (const c of clusters) {
    const times = [
      ...c.nmap.map((e) => new Date(e.scanned_at).getTime()),
      ...c.whatweb.map((e) => new Date(e.scanned_at).getTime()),
      ...c.screenshots.map((e) => new Date(e.taken_at).getTime()),
      ...c.ssl.map((e) => new Date(e.scanned_at).getTime()),
    ].filter((t) => t > 0);
    c.centerTime =
      times.length > 0
        ? Math.round(times.reduce((a, b) => a + b, 0) / times.length)
        : 0;
  }

  clusters.sort((a, b) => b.centerTime - a.centerTime);
  return clusters;
}

function PortRow({
  port,
  screenshot,
  ip,
}: {
  port: NmapEntry;
  screenshot?: ScreenshotEntry;
  ip: string;
}) {
  const [showScreenshot, setShowScreenshot] = useState(false);

  const stateColor =
    port.state === "open"
      ? "#f6d9a6"
      : port.state === "filtered"
        ? "var(--state-warn)"
        : port.state === "closed"
          ? "var(--state-danger)"
          : "var(--color-text-muted)";
  const hasDetails =
    port.product ||
    port.version ||
    port.extra_info ||
    port.state_reason ||
    port.banner ||
    port.cpe ||
    port.os_type ||
    port.confidence != null ||
    port.scripts;

  return (
    <div
      className="port-row-wrap animate-slide-up"
      style={{ animationDelay: `${Math.random() * 0.1}s` }}
    >
      <details style={{ padding: 0 }}>
        <summary
          className="port-summary"
          style={{ cursor: hasDetails || screenshot ? "pointer" : "default" }}
        >
          <div
            className="port-status-dot"
            style={{
              background: stateColor,
              boxShadow: `0 0 8px ${stateColor}`,
            }}
          />
          <div className="port-info">
            <span className="port-number">
              {port.port}
              <span className="port-protocol"> / {port.protocol}</span>
            </span>
            <span
              className="port-state-badge"
              style={{ background: stateColor + "20", color: stateColor }}
            >
              {port.state}
            </span>
            {port.service && (
              <span className="port-service-badge">{port.service}</span>
            )}
            {port.product && (
              <span className="port-product-text">
                {port.product}
                {port.version ? (
                  <span style={{ color: "var(--color-text-muted)" }}> {port.version}</span>
                ) : (
                  ""
                )}
              </span>
            )}
          </div>
          {(hasDetails || screenshot) && (
            <>
              <span className="port-expand-icon">▶</span>
              <span className="port-expand-icon-open">▼</span>
            </>
          )}
        </summary>
        <div className="port-details">
          {hasDetails && (
            <table className="detail-table">
              <tbody>
                {port.service && (
                  <tr>
                    <td className="detail-key">Service</td>
                    <td className="detail-value">{port.service}</td>
                  </tr>
                )}
                {port.product && (
                  <tr>
                    <td className="detail-key">Product</td>
                    <td className="detail-value">{port.product}</td>
                  </tr>
                )}
                {port.version && (
                  <tr>
                    <td className="detail-key">Version</td>
                    <td className="detail-value">{port.version}</td>
                  </tr>
                )}
                {port.extra_info && (
                  <tr>
                    <td className="detail-key">Extra Info</td>
                    <td className="detail-value-muted">{port.extra_info}</td>
                  </tr>
                )}
                {port.os_type && (
                  <tr>
                    <td className="detail-key">OS Type</td>
                    <td className="detail-value-muted">{port.os_type}</td>
                  </tr>
                )}
                {port.os_name && (
                  <tr>
                    <td className="detail-key">OS Detection</td>
                    <td className="detail-value-muted">
                      {port.os_name}
                      {port.os_accuracy ? (
                        <span style={{ color: "var(--color-text-muted)" }}>
                          {" "}
                          ({port.os_accuracy}%)
                        </span>
                      ) : (
                        ""
                      )}
                    </td>
                  </tr>
                )}
                {port.state_reason && (
                  <tr>
                    <td className="detail-key">State Reason</td>
                    <td className="detail-value-muted">{port.state_reason}</td>
                  </tr>
                )}
                {port.detection_method && (
                  <tr>
                    <td className="detail-key">Detection Method</td>
                    <td className="detail-value-muted">
                      {port.detection_method}
                    </td>
                  </tr>
                )}
                {port.confidence != null && (
                  <tr>
                    <td className="detail-key">Confidence</td>
                    <td className="detail-value">{port.confidence}/10</td>
                  </tr>
                )}
                {port.cpe && (
                  <tr>
                    <td className="detail-key">CPE</td>
                    <td className="detail-value-violet">{port.cpe}</td>
                  </tr>
                )}
                {port.ttl && (
                  <tr>
                    <td className="detail-key">TTL</td>
                    <td className="detail-value">{port.ttl}</td>
                  </tr>
                )}
                {port.banner && (
                  <tr>
                    <td className="detail-key">Banner</td>
                    <td style={{ padding: "6px 0" }}>
                      <pre className="banner-block">{port.banner}</pre>
                    </td>
                  </tr>
                )}
                <tr>
                  <td className="detail-key">Last Scanned</td>
                  <td className="detail-timestamp">
                    {formatDate(port.scanned_at)}
                  </td>
                </tr>
              </tbody>
            </table>
          )}
          {screenshot && (
            <div style={{ marginTop: hasDetails ? 12 : 0 }}>
              <button
                className="secondary-btn"
                style={{
                  padding: "6px 12px",
                  fontSize: 11,
                  lineHeight: 1,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                }}
                onClick={() => setShowScreenshot((v) => !v)}
              >
                {showScreenshot ? "▼" : "▶"} Screenshot
                {screenshot.file_size
                  ? ` (${(screenshot.file_size / 1024).toFixed(1)} KB)`
                  : ""}
              </button>
              {showScreenshot && (
                <div style={{ marginTop: 10 }}>
                  <ScreenshotImage ip={ip} port={screenshot.port} />
                </div>
              )}
            </div>
          )}
        </div>
      </details>
    </div>
  );
}

function HttpServiceCard({ service }: { service: WhatWebEntry }) {
  const status = service.http_status ?? 200;
  const statusColor =
    status < 300 ? "#f6d9a6" : status < 400 ? "var(--state-warn)" : "var(--state-danger)";
  const statusBg =
    status < 300
      ? "rgba(246, 217, 166,0.2)"
      : status < 400
        ? "rgba(227, 194, 132,0.2)"
        : "rgba(221, 156, 143,0.2)";
  const statusBorder = `${statusColor}40`;

  return (
    <div
      className="http-card animate-slide-up"
      style={{ animationDelay: `${Math.random() * 0.08}s` }}
    >
      <div className="http-card-header">
        <div className="http-card-id">
          <div
            className="port-status-dot"
            style={{ background: "#f6d9a6", boxShadow: "0 0 6px #f6d9a6" }}
          />
          <span className="http-card-port">:{service.port}</span>
          {service.http_status != null && (
            <span
              className="status-badge"
              style={{
                background: statusBg,
                color: statusColor,
                border: `1px solid ${statusBorder}`,
              }}
            >
              {status}
            </span>
          )}
        </div>
        {service.url && <span className="http-card-url">{service.url}</span>}
      </div>
      {service.title && <div className="http-card-title">{service.title}</div>}
      {(service.server || service.powered_by || service.meta_generator) && (
        <div className="http-card-meta">
          {service.server && (
            <div className="http-card-meta-item">
              <span className="http-card-meta-label">Server: </span>
              <span className="http-card-meta-value">{service.server}</span>
            </div>
          )}
          {service.powered_by && (
            <div className="http-card-meta-item">
              <span className="http-card-meta-label">Powered by: </span>
              <span className="http-card-meta-value">{service.powered_by}</span>
            </div>
          )}
          {service.meta_generator && (
            <div className="http-card-meta-item">
              <span className="http-card-meta-label">Generator: </span>
              <span className="http-card-meta-value">
                {service.meta_generator}
              </span>
            </div>
          )}
        </div>
      )}
      {service.technologies && service.technologies.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div
            style={{
              fontSize: 11,
              textTransform: "uppercase",
              letterSpacing: "0.1em",
              color: "var(--color-text-muted)",
              marginBottom: 10,
              fontWeight: 700,
            }}
          >
            Technologies ({service.technologies.length})
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {service.technologies.map((t: string) => (
              <span key={t} className="tech-badge">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}
      <div
        style={{
          fontSize: 11,
          color: "var(--color-text-muted)",
          marginTop: 12,
          fontFamily: "JetBrains Mono, monospace",
        }}
      >
        Scanned: {formatDate(service.scanned_at)}
      </div>
    </div>
  );
}

function DnsRecordsCard({ dns }: { dns: DnsRecord }) {
  const recordTypes = [
    { label: "A", values: dns.a || [], color: "var(--state-ok)" },
    { label: "AAAA", values: dns.aaaa || [], color: "var(--color-champagne-deep)" },
    { label: "CNAME", values: dns.cname || [], color: "var(--color-champagne)" },
    { label: "MX", values: dns.mx || [], color: "var(--state-warn)" },
    { label: "NS", values: dns.ns || [], color: "var(--color-champagne-soft)" },
    { label: "TXT", values: dns.txt || [], color: "var(--color-text-soft)" },
    { label: "PTR", values: dns.ptr || [], color: "var(--state-active)" },
  ].filter((r) => r.values.length > 0);

  if (recordTypes.length === 0) return null;

  return (
    <div className="dns-card">
      <h2 className="dns-card-title">
        DNS Records
        <span className="dns-card-count">
          ({recordTypes.reduce((sum, r) => sum + r.values.length, 0)} records)
        </span>
      </h2>
      <div className="dns-grid">
        {recordTypes.map((record) => (
          <div
            key={record.label}
            className="dns-record-group"
            style={{ borderColor: `${record.color}30` }}
          >
            <div className="dns-record-type" style={{ color: record.color }}>
              {record.label}{" "}
              <span style={{ color: "var(--color-text-muted)", fontWeight: 400 }}>
                ({record.values.length})
              </span>
            </div>
            <div className="dns-record-values">
              {record.values.map((v: string, i: number) => (
                <span key={i} className="dns-record-value">
                  {v}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
      {dns.scanned_at && (
        <div className="dns-timestamp">
          Resolved: {formatDate(dns.scanned_at)}
        </div>
      )}
    </div>
  );
}

function SslCertificatesCard({ certs }: { certs: SslCert[] }) {
  if (certs.length === 0) return null;

  return (
    <div className="ssl-card">
      <h2 className="ssl-card-title">
        SSL Certificates
        <span className="ssl-card-count">({certs.length})</span>
      </h2>
      <div className="ssl-list">
        {certs.map((cert, i) => {
          const isExpired = new Date(cert.not_after) < new Date();
          const expiresSoon =
            !isExpired &&
            new Date(cert.not_after).getTime() - Date.now() < 30 * 86400000;
          const statusColor = isExpired
            ? "var(--state-danger)"
            : expiresSoon
              ? "var(--state-warn)"
              : "#f6d9a6";
          const statusBg = `${statusColor}20`;
          const statusText = isExpired
            ? "EXPIRED"
            : expiresSoon
              ? "EXPIRES SOON"
              : "VALID";
          const borderColor = isExpired
            ? "rgba(221, 156, 143,0.3)"
            : expiresSoon
              ? "rgba(227, 194, 132,0.3)"
              : "rgba(246, 217, 166,0.3)";
          const headerBg = isExpired
            ? "rgba(221, 156, 143,0.08)"
            : expiresSoon
              ? "rgba(227, 194, 132,0.08)"
              : "rgba(246, 217, 166,0.08)";
          const domains = extractDomainFromSubject(cert.subject);

          return (
            <div
              key={i}
              className="ssl-cert"
              style={{ border: `1px solid ${borderColor}` }}
            >
              <div className="ssl-cert-header" style={{ background: headerBg }}>
                <div className="ssl-cert-id">
                  <span className="ssl-cert-port">:{cert.port}</span>
                  <span
                    className="ssl-status-badge"
                    style={{
                      color: statusColor,
                      background: statusBg,
                      border: `1px solid ${borderColor}`,
                    }}
                  >
                    {statusText}
                  </span>
                  {domains.length > 0 && (
                    <span className="ssl-cert-domain">{domains[0]}</span>
                  )}
                </div>
                <span className="ssl-version">{cert.ssl_version}</span>
              </div>
              <div className="ssl-cert-body">
                <table className="detail-table">
                  <tbody>
                    <tr>
                      <td className="detail-key" style={{ fontWeight: 600 }}>
                        Subject
                      </td>
                      <td className="detail-value">{cert.subject}</td>
                    </tr>
                    <tr>
                      <td className="detail-key" style={{ fontWeight: 600 }}>
                        Issuer
                      </td>
                      <td className="detail-value-muted">{cert.issuer}</td>
                    </tr>
                    <tr>
                      <td className="detail-key" style={{ fontWeight: 600 }}>
                        Serial
                      </td>
                      <td
                        className="detail-value-muted"
                        style={{ fontSize: 11 }}
                      >
                        {cert.serial}
                      </td>
                    </tr>
                    <tr>
                      <td className="detail-key" style={{ fontWeight: 600 }}>
                        Valid From
                      </td>
                      <td className="detail-value-muted">
                        {formatDate(cert.not_before)}
                      </td>
                    </tr>
                    <tr>
                      <td className="detail-key" style={{ fontWeight: 600 }}>
                        Valid To
                      </td>
                      <td
                        className="detail-value-muted"
                        style={{ color: isExpired ? "var(--state-danger)" : undefined }}
                      >
                        {formatDate(cert.not_after)}
                      </td>
                    </tr>
                    <tr>
                      <td className="detail-key" style={{ fontWeight: 600 }}>
                        Cipher Suite
                      </td>
                      <td className="detail-value-muted">{cert.cipher}</td>
                    </tr>
                    <tr>
                      <td className="detail-key" style={{ fontWeight: 600 }}>
                        Chain Length
                      </td>
                      <td className="detail-value-muted">
                        {cert.chain_length}
                      </td>
                    </tr>
                  </tbody>
                </table>
                {cert.san && cert.san.length > 0 && (
                  <div className="ssl-san-header">
                    <div className="ssl-san-label">
                      Subject Alternative Names ({cert.san.length})
                    </div>
                    <div className="ssl-san-list">
                      {cert.san.map((s: string, j: number) => (
                        <span key={j} className="ssl-san-item">
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SvgIcon({ name }: { name: string }) {
  const icons: Record<string, React.ReactNode> = {
    overview: (
      <svg
        width="16"
        height="16"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <rect x="1" y="8" width="3" height="7" rx="0.5" />
        <rect x="6.5" y="5" width="3" height="10" rx="0.5" />
        <rect x="12" y="1" width="3" height="14" rx="0.5" />
      </svg>
    ),
    ports: (
      <svg
        width="16"
        height="16"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <circle cx="8" cy="8" r="6" />
        <circle cx="8" cy="8" r="2" fill="currentColor" />
        <line x1="8" y1="2" x2="8" y2="4" />
        <line x1="14" y1="8" x2="12" y2="8" />
        <line x1="8" y1="14" x2="8" y2="12" />
        <line x1="2" y1="8" x2="4" y2="8" />
      </svg>
    ),
    web: (
      <svg
        width="16"
        height="16"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <circle cx="8" cy="8" r="6" />
        <ellipse cx="8" cy="8" rx="3" ry="6" />
        <line x1="2" y1="8" x2="14" y2="8" />
      </svg>
    ),
    ssl: (
      <svg
        width="16"
        height="16"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <rect x="3.5" y="6" width="9" height="8" rx="1" />
        <path d="M5.5 6V4.5a2.5 2.5 0 0 1 5 0V6" />
        <circle cx="8" cy="10" r="1" fill="currentColor" />
      </svg>
    ),
    dns: (
      <svg
        width="16"
        height="16"
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M8 1C4.5 1 2 3.5 2 8s2.5 7 6 7 6-2.5 6-6-2.5-8-6-8z" />
        <circle cx="8" cy="8" r="2" fill="currentColor" />
        <line x1="8" y1="1" x2="8" y2="3" />
        <line x1="8" y1="13" x2="8" y2="15" />
        <line x1="1" y1="8" x2="3" y2="8" />
        <line x1="13" y1="8" x2="15" y2="8" />
      </svg>
    ),
    search: (
      <svg
        width="24"
        height="24"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        style={{ opacity: 0.4 }}
      >
        <circle cx="11" cy="11" r="7" />
        <line x1="16.5" y1="16.5" x2="21" y2="21" />
      </svg>
    ),
    chevron: (
      <svg
        width="12"
        height="12"
        viewBox="0 0 12 12"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      >
        <polyline points="4 2 8 6 4 10" />
      </svg>
    ),
  };
  return icons[name] || null;
}

export default function HostDetailPage() {
  const params = useParams();
  const ip = decodeURIComponent(params.ip as string);

  const [clusters, setClusters] = useState<ScanCluster[]>([]);
  const [dns, setDns] = useState<DnsRecord | null>(null);
  const [fuzzing, setFuzzing] = useState<FuzzEntry[]>([]);
  const [geo, setGeo] = useState<GeoInfo | null>(null);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<string>("overview");

  useEffect(() => {
    (async () => {
      try {
        // Путь передаётся прокси как есть — без encodeURIComponent (иначе double-encoding → 404).
        const res = await fetch(`/api/proxy/api/host/${ip}`, {
          cache: "no-store",
        });

        if (!res.ok) throw new Error(`API ${res.status}`);

        const json = await res.json();

        // Терпимость к форме ответа: поля могут лежать в корне или под data.
        const nmapData: NmapEntry[] =
          json.open_ports || json.data?.open_ports || [];
        const whatwebData: WhatWebEntry[] =
          json.web_services || json.data?.web_services || [];
        // Backend sends headers as a JSON string; parse into a record.
        for (const w of whatwebData) {
          if (typeof w.headers === "string") {
            try {
              w.headers = w.headers ? JSON.parse(w.headers) : undefined;
            } catch {
              w.headers = undefined;
            }
          }
        }
        const screenshotsData: ScreenshotEntry[] =
          json.screenshots || json.data?.screenshots || [];
        const sslData: SslCert[] = json.ssl || json.data?.ssl || [];
        const dnsData: DnsRecord | null = json.dns || json.data?.dns || null;
        const fuzzingData: FuzzEntry[] = json.fuzzing || json.data?.fuzzing || [];
        const geoData: GeoInfo | null = json.geo || json.data?.geo || null;

        setClusters(
          clusterEvents(nmapData, whatwebData, screenshotsData, sslData),
        );
        setDns(dnsData);
        setFuzzing(fuzzingData);
        setGeo(geoData && geoData.country ? geoData : null);
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    })();
  }, [ip]);

  if (loading) {
    return (
      <div className="loading-center">
        <div className="loading-box">
          <div className="spinner" />
          <div className="loading-text">Loading host intelligence...</div>
        </div>
      </div>
    );
  }

  if (error || clusters.length === 0) {
    return (
      <div className="host-layout" style={{ padding: 40 }}>
        <Link
          href="/"
          className="back-link"
          style={{ display: "inline-block", marginBottom: 20 }}
        >
          ← Back to Home
        </Link>
        <div className="empty-center">
          <div className="empty-icon-lg">
            <SvgIcon name="search" />
          </div>
          <h1 className="empty-ip">{ip}</h1>
          <p className="empty-message">
            {error || "No intelligence data available for this host"}
          </p>
        </div>
      </div>
    );
  }

  const current = clusters[selectedIndex];
  const firstSeen = clusters[clusters.length - 1]?.centerTime;
  const lastSeen = clusters[0]?.centerTime;
  const allServices = Array.from(
    new Set(current.nmap.map((r) => r.service).filter(Boolean)),
  );
  const allProducts = Array.from(
    new Set(current.nmap.map((r) => r.product).filter(Boolean)),
  );
  const allTechs: string[] = Array.from(
    new Set<string>(current.whatweb.flatMap((w) => w.technologies || [])),
  );
  const dnsRecordCount = dns
    ? (dns.a?.length || 0) +
      (dns.aaaa?.length || 0) +
      (dns.cname?.length || 0) +
      (dns.mx?.length || 0) +
      (dns.ns?.length || 0) +
      (dns.txt?.length || 0) +
      (dns.ptr?.length || 0)
    : 0;
  const openPorts = current.nmap.filter((r) => r.state === "open");
  const filteredPorts = current.nmap.filter((r) => r.state === "filtered");
  const closedPorts = current.nmap.filter((r) => r.state === "closed");
  const screenshotMap = new Map<number, ScreenshotEntry>();
  for (const s of current.screenshots) screenshotMap.set(s.port, s);
  const displayPorts =
    current.nmap.length > 0
      ? current.nmap
      : current.whatweb.map(
          (w) =>
            ({
              port: w.port,
              protocol: "tcp",
              state: "open",
              service: "http",
              scanned_at: w.scanned_at,
            }) as NmapEntry,
        );

  const sections = [
    { id: "overview", label: "Overview", icon: "overview" },
    { id: "ports", label: "Ports", icon: "ports" },
    { id: "web", label: "Web Services", icon: "web" },
    { id: "headers", label: "HTTP Headers", icon: "web" },
    { id: "fuzzing", label: "Fuzzing", icon: "web" },
    { id: "ssl", label: "SSL/TLS", icon: "ssl" },
    { id: "dns", label: "DNS", icon: "dns" },
  ];

  return (
    <div className="host-layout animate-fade-in">
      <div className="host-header">
        <Link href="/" className="back-link">
          ← Back to Home
        </Link>
        <span className="host-ip-title">{ip}</span>
      </div>
      <div className="host-body">
        <div className="host-sidebar">
          <div>
            <div className="sidebar-label">Navigation</div>
            <div className="nav-section-list">
              {sections.map((section) => (
                <button
                  key={section.id}
                  onClick={() => setActiveSection(section.id)}
                  className={`nav-section-btn${activeSection === section.id ? " active" : ""}`}
                >
                  <SvgIcon name={section.icon} />
                  <span>{section.label}</span>
                </button>
              ))}
            </div>
          </div>

          {clusters.length > 0 && (
            <div>
              <div className="sidebar-label">History</div>
              <div className="scan-timeline">
                {clusters.map((cluster, i) => {
                  const isSelected = i === selectedIndex;
                  const openCount = cluster.nmap.filter(
                    (r) => r.state === "open",
                  ).length;
                  const webCount = cluster.whatweb.length;
                  const sslCount = cluster.ssl.length;
                  const scanColor =
                    openCount > 0
                      ? "#f6d9a6"
                      : webCount > 0
                        ? "#cabca6"
                        : "var(--color-text-muted)";
                  return (
                    <button
                      key={i}
                      onClick={() => setSelectedIndex(i)}
                      className={`scan-timeline-item${isSelected ? " active" : ""}`}
                    >
                      <div
                        style={{
                          display: "flex",
                          gap: 10,
                          alignItems: "flex-start",
                        }}
                      >
                        <div
                          className="scan-timeline-dot"
                          style={{
                            background: scanColor,
                            boxShadow: isSelected
                              ? `0 0 8px ${scanColor}`
                              : "none",
                            marginTop: 3,
                          }}
                        />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div className="scan-timeline-date">
                            {formatRelative(cluster.centerTime)}
                          </div>
                          <div
                            style={{
                              fontSize: 9,
                              color: "var(--color-text-muted)",
                              marginTop: 1,
                            }}
                          >
                            {cluster.scan_uid.length > 8
                              ? cluster.scan_uid.slice(0, 8)
                              : cluster.scan_uid}
                          </div>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        <div className="host-content">
          <div className="timemachine">
            <div className="tm-head">
              <button
                className="snapshot-nav"
                disabled={selectedIndex === clusters.length - 1}
                onClick={() =>
                  setSelectedIndex(Math.min(clusters.length - 1, selectedIndex + 1))
                }
                aria-label="Older snapshot"
                title="Older scan"
              >
                ‹
              </button>

              <div className="tm-current">
                <span className="tm-badge">TIME MACHINE</span>
                <span className="tm-when">
                  {formatRelative(clusters[selectedIndex]?.centerTime)}
                </span>
                <span className="tm-date">
                  {formatDate(clusters[selectedIndex]?.centerTime)}
                </span>
              </div>

              <button
                className="snapshot-nav"
                disabled={selectedIndex === 0}
                onClick={() => setSelectedIndex(Math.max(0, selectedIndex - 1))}
                aria-label="Newer snapshot"
                title="Newer scan"
              >
                ›
              </button>

              <div className="tm-epoch">
                <select
                  className="tm-select"
                  value={selectedIndex}
                  onChange={(e) => setSelectedIndex(Number(e.target.value))}
                  aria-label="Jump to scan epoch"
                >
                  {clusters.map((c, i) => {
                    const open = c.nmap.filter((r) => r.state === "open").length;
                    return (
                      <option key={i} value={i}>
                        {`${formatDate(c.centerTime)} · ${open} open · ${c.whatweb.length} web`}
                      </option>
                    );
                  })}
                </select>
              </div>

              <span className="snapshot-count">
                {selectedIndex + 1}
                <span className="snapshot-count-total"> / {clusters.length}</span>
              </span>
            </div>

            {clusters.length > 1 && (
              <div
                className="tm-rail"
                role="tablist"
                aria-label="Scan history timeline"
              >
                <div className="tm-rail-line" />
                {(() => {
                  const times = clusters.map((c) => c.centerTime);
                  const max = Math.max(...times);
                  const min = Math.min(...times);
                  const span = max - min || 1;
                  return clusters.map((cluster, i) => {
                    const open = cluster.nmap.filter(
                      (r) => r.state === "open",
                    ).length;
                    // Position each mark by its real timestamp; newest on the right.
                    const pct = ((cluster.centerTime - min) / span) * 100;
                    return (
                      <button
                        key={i}
                        role="tab"
                        aria-selected={i === selectedIndex}
                        className={`tm-mark${i === selectedIndex ? " is-active" : ""}`}
                        style={{ left: `${pct}%` }}
                        onClick={() => setSelectedIndex(i)}
                        title={`${formatRelative(cluster.centerTime)} · ${open} open · ${cluster.whatweb.length} web`}
                      />
                    );
                  });
                })()}
                <span className="tm-rail-end tm-rail-oldest">
                  {formatRelative(clusters[clusters.length - 1]?.centerTime)}
                </span>
                <span className="tm-rail-end tm-rail-newest">
                  {formatRelative(clusters[0]?.centerTime)}
                </span>
              </div>
            )}
          </div>

          {activeSection === "overview" && (
            <div className="animate-fade-in">
              <div className="host-hero">
                <div className="host-hero-label">Host Intelligence Report</div>
                <h1 className="host-hero-ip">{ip}</h1>
                <div className="metrics-grid">
                  <div className="metric">
                    <div className="metric-value" style={{ color: "var(--state-ok)" }}>
                      {openPorts.length}
                    </div>
                    <div className="metric-label">Open Ports</div>
                  </div>
                  <div className="metric">
                    <div className="metric-value" style={{ color: "var(--state-warn)" }}>
                      {filteredPorts.length}
                    </div>
                    <div className="metric-label">Filtered</div>
                  </div>
                  <div className="metric">
                    <div className="metric-value" style={{ color: "var(--state-danger)" }}>
                      {closedPorts.length}
                    </div>
                    <div className="metric-label">Closed</div>
                  </div>
                  <div className="metric">
                    <div className="metric-value" style={{ color: "var(--color-champagne)" }}>
                      {current.whatweb.length}
                    </div>
                    <div className="metric-label">Web Services</div>
                  </div>
                  <div className="metric">
                    <div className="metric-value" style={{ color: "var(--color-champagne-deep)" }}>
                      {allTechs.length}
                    </div>
                    <div className="metric-label">Technologies</div>
                  </div>
                  <div className="metric">
                    <div className="metric-value" style={{ color: "var(--state-active)" }}>
                      {current.ssl.length}
                    </div>
                    <div className="metric-label">SSL/TLS</div>
                  </div>
                  <div className="metric">
                    <div className="metric-value" style={{ color: "var(--color-champagne-soft)" }}>
                      {dnsRecordCount}
                    </div>
                    <div className="metric-label">DNS Records</div>
                  </div>
                  <div className="metric">
                    <div className="metric-value" style={{ color: "var(--state-warn)" }}>
                      {fuzzing.length}
                    </div>
                    <div className="metric-label">Discovered Paths</div>
                  </div>
                  <div className="metric">
                    <div className="metric-value" style={{ color: "var(--color-text-muted)" }}>
                      {clusters.length}
                    </div>
                    <div className="metric-label">Scans</div>
                  </div>
                </div>
                <div className="meta-row">
                  <div>
                    <div className="meta-field-label">First Seen</div>
                    <div className="meta-field-value">
                      {firstSeen ? formatDate(firstSeen) : "—"}
                    </div>
                  </div>
                  <div>
                    <div className="meta-field-label">Last Seen</div>
                    <div className="meta-field-value">
                      {lastSeen ? formatDate(lastSeen) : "—"}
                    </div>
                    {lastSeen && (
                      <div className="meta-field-relative">
                        {formatRelative(lastSeen)}
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {allTechs.length > 0 && (
                <div className="card-panel" style={{ padding: "16px 20px", marginTop: 20 }}>
                  <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.1em", color: "var(--color-text-muted)", marginBottom: 12, fontWeight: 700 }}>
                    Technology Stack
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                    {allTechs.map((t) => (
                      <span key={t} className="tech-badge">{t}</span>
                    ))}
                  </div>
                </div>
              )}

              {geo && (
                <div className="card-panel geo-panel" style={{ padding: "16px 20px", marginTop: 20 }}>
                  <div className="geo-panel-title">Geolocation & Network</div>
                  <div className="geo-grid">
                    {geo.country && (
                      <div className="geo-item">
                        <div className="geo-item-label">Country</div>
                        <div className="geo-item-value">
                          {geo.country}
                          {geo.country_code ? ` (${geo.country_code})` : ""}
                        </div>
                      </div>
                    )}
                    {geo.city && (
                      <div className="geo-item">
                        <div className="geo-item-label">City</div>
                        <div className="geo-item-value">{geo.city}</div>
                      </div>
                    )}
                    {geo.asn && (
                      <div className="geo-item">
                        <div className="geo-item-label">ASN</div>
                        <div className="geo-item-value">{geo.asn}</div>
                      </div>
                    )}
                    {geo.org && (
                      <div className="geo-item">
                        <div className="geo-item-label">Organization</div>
                        <div className="geo-item-value">{geo.org}</div>
                      </div>
                    )}
                    {geo.isp && geo.isp !== geo.org && (
                      <div className="geo-item">
                        <div className="geo-item-label">ISP</div>
                        <div className="geo-item-value">{geo.isp}</div>
                      </div>
                    )}
                    {geo.lat != null && geo.lon != null && (geo.lat !== 0 || geo.lon !== 0) && (
                      <div className="geo-item">
                        <div className="geo-item-label">Coordinates</div>
                        <div className="geo-item-value">
                          {geo.lat.toFixed(4)}, {geo.lon.toFixed(4)}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeSection === "ports" && (
            <div className="animate-fade-in">
              <h2 className="section-heading">Network Services</h2>
              <div className="legend-row">
                <span className="legend-item" style={{ color: "#f6d9a6" }}>
                  ● {openPorts.length} open
                </span>
                <span className="legend-item" style={{ color: "var(--state-warn)" }}>
                  ● {filteredPorts.length} filtered
                </span>
                <span className="legend-item" style={{ color: "var(--state-danger)" }}>
                  ● {closedPorts.length} closed
                </span>
              </div>
              {displayPorts.map((r, i) => (
                <PortRow
                  key={i}
                  port={r}
                  screenshot={screenshotMap.get(r.port)}
                  ip={ip}
                />
              ))}
            </div>
          )}

          {activeSection === "web" && (
            <div className="animate-fade-in">
              <h2 className="section-heading">Web Services</h2>
              {current.whatweb.map((w, i) => (
                <HttpServiceCard key={i} service={w} />
              ))}
            </div>
          )}

          {activeSection === "headers" && (
            <div className="animate-fade-in">
              <h2 className="section-heading">HTTP Response Headers</h2>
              {current.whatweb.filter((w) => w.headers && Object.keys(w.headers).length > 0).length === 0 ? (
                <div className="empty-inline">No headers captured in this scan.</div>
              ) : (
                current.whatweb
                  .filter((w) => w.headers && Object.keys(w.headers).length > 0)
                  .map((w, i) => (
                    <div key={i} className="card-panel headers-card">
                      <div className="headers-card-head">
                        <span className="headers-port">:{w.port}</span>
                        <span className="headers-url">{w.url}</span>
                      </div>
                      <table className="headers-table">
                        <tbody>
                          {Object.entries(w.headers || {})
                            .sort(([a], [b]) => a.localeCompare(b))
                            .map(([k, v]) => (
                              <tr key={k}>
                                <td className="headers-key">{k}</td>
                                <td className="headers-val">{v}</td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  ))
              )}
            </div>
          )}

          {activeSection === "ssl" && (
            <div className="animate-fade-in">
              <SslCertificatesCard certs={current.ssl} />
            </div>
          )}

          {activeSection === "fuzzing" && (
            <div className="animate-fade-in">
              <h2 className="section-heading">Discovered Paths</h2>
              {fuzzing.length === 0 ? (
                <p style={{ color: "var(--color-text-muted)", fontSize: 13, padding: 20 }}>
                  No paths discovered by fuzzing.
                </p>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {fuzzing.map((f, i) => (
                    <div key={i} className="card-panel" style={{ padding: "12px 16px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                        <span className="badge" style={{ background: "#f6d9a620", color: "#f6d9a6", minWidth: 40, textAlign: "center" }}>
                          {f.http_status}
                        </span>
                        <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: 13, color: "#cabca6" }}>
                          {f.port}
                        </span>
                        <code style={{ fontSize: 13, color: "#f5efe4", wordBreak: "break-all" }}>
                          {f.path}
                        </code>
                        <a
                          href={f.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="external-link"
                          style={{ marginLeft: "auto", fontSize: 11, color: "var(--color-text-muted)", textDecoration: "underline" }}
                        >
                          open ↗
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeSection === "dns" && dns && (
            <div className="animate-fade-in">
              <DnsRecordsCard dns={dns} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
