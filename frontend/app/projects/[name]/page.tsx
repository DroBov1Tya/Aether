import Link from "next/link";
import { getProjectHosts, type AggregatedHost } from "@/lib/api";
import HostRow, { type HostRowData } from "@/components/host-row";

export const dynamic = "force-dynamic";

function toRow(h: AggregatedHost): HostRowData {
  return {
    target: h.target,
    title: h.titles?.[0],
    url: h.url,
    http_status: h.http_status,
    ports: (h.ports || []).map((p) => ({ port: p })),
    technologies: h.technologies || [],
    scan_count: h.scan_uids?.length,
    scanned_at: h.last_seen,
  };
}

export default async function ProjectDetailPage({
  params,
}: {
  params: Promise<{ name: string }>;
}) {
  const { name } = await params;
  const project = decodeURIComponent(name);

  let hosts: AggregatedHost[] = [];
  let error: string | null = null;
  try {
    hosts = await getProjectHosts(project);
  } catch (e: any) {
    error = e.message || "Failed to load project";
  }

  return (
    <div className="page-container">
      <div className="page-head">
        <div>
          <div className="crumb">
            <Link href="/projects">Projects</Link> / <span>{project}</span>
          </div>
          <h1 className="page-title">{project}</h1>
          <p className="page-subtitle">
            {hosts.length} host{hosts.length !== 1 ? "s" : ""} in this project — isolated from the public index
          </p>
        </div>
      </div>

      {error && <div className="query-error">ERROR: {error}</div>}

      {!error && hosts.length === 0 ? (
        <div className="empty-state">
          <p className="empty-title">No hosts</p>
          <p className="empty-desc">This project has no imported hosts yet.</p>
          <Link href="/import" className="empty-cta">Import data</Link>
        </div>
      ) : (
        <div>
          {hosts.map((h, i) => (
            <HostRow key={h.target + i} host={toRow(h)} />
          ))}
        </div>
      )}
    </div>
  );
}
