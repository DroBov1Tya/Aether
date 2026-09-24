import Link from "next/link";
import { listProjects, type ProjectSummary } from "@/lib/api";

export const dynamic = "force-dynamic";

function fmtDate(s?: string): string {
  if (!s || s.startsWith("1970")) return "—";
  return s.replace("T", " ").slice(0, 16);
}

export default async function ProjectsPage() {
  let projects: ProjectSummary[] = [];
  let error: string | null = null;
  try {
    projects = await listProjects();
  } catch (e: any) {
    error = e.message || "Failed to load projects";
  }

  return (
    <div className="page-container">
      <div className="page-head">
        <div>
          <h1 className="page-title">Projects</h1>
          <p className="page-subtitle">
            Isolated scan sets (client networks, manual imports) — separate from the public index
          </p>
        </div>
        <Link href="/import" className="empty-cta" style={{ marginTop: 0 }}>
          + Import data
        </Link>
      </div>

      {error && <div className="query-error">ERROR: {error}</div>}

      {!error && projects.length === 0 ? (
        <div className="empty-state">
          <p className="empty-title">No projects yet</p>
          <p className="empty-desc">
            Import scan results to create an isolated project.
          </p>
          <Link href="/import" className="empty-cta">Import data</Link>
        </div>
      ) : (
        <div className="projects-grid">
          {projects.map((p) => (
            <Link
              key={p.project}
              href={`/projects/${encodeURIComponent(p.project)}`}
              className="project-card"
            >
              <div className="project-name">{p.project}</div>
              <div className="project-meta">
                <span><b>{p.hosts}</b> host{p.hosts !== 1 ? "s" : ""}</span>
                <span className="project-date">{fmtDate(p.last_seen)}</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
