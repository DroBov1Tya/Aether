import { fetchApi } from "@/lib/api";

interface Agent {
  id: string;
  ip: string;
  name: string;
  version: string;
  port: number;
  os: string;
  arch: string;
  kernel: string;
  max_concurrent_tasks: number;
  status: string;
  last_seen_at: string;
}

async function getAgents(): Promise<Agent[]> {
  try {
    return await fetchApi<Agent[]>("/api/agents");
  } catch {
    return [];
  }
}

function relTime(s: string): string {
  if (!s) return "—";
  const d = new Date(s.includes("T") ? s : s.replace(" ", "T") + "Z");
  if (isNaN(d.getTime())) return s;
  const mins = Math.floor((Date.now() - d.getTime()) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default async function AgentsPage() {
  const agents = await getAgents();
  const online = agents.filter((a) => a.status === "active").length;

  return (
    <div className="page-container">
      <div className="page-head">
        <div>
          <h1 className="page-title">Agents</h1>
          <p className="page-subtitle">
            {agents.length} registered
            {agents.length > 0 && (
              <>
                {" · "}
                <span style={{ color: "var(--state-ok)" }}>{online} online</span>
              </>
            )}
          </p>
        </div>
      </div>

      {agents.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon" aria-hidden="true">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" style={{ margin: "0 auto" }}>
              <rect x="3" y="4" width="18" height="12" rx="2" />
              <line x1="7" y1="20" x2="17" y2="20" />
              <line x1="12" y1="16" x2="12" y2="20" />
              <circle cx="8" cy="10" r="1" fill="currentColor" />
            </svg>
          </div>
          <p className="empty-title">No agents registered</p>
          <p className="empty-desc">Agents appear here once they connect and authenticate.</p>
        </div>
      ) : (
        <div className="agents-grid">
          {agents.map((a) => {
            const isActive = a.status === "active";
            return (
              <div key={a.id} className="agent-card">
                <div className="agent-card-head">
                  <div className="agent-identity">
                    <span
                      className="agent-status-dot"
                      style={{ background: isActive ? "var(--state-ok)" : "var(--state-danger)" }}
                    />
                    <div>
                      <div className="agent-name">{a.name || "unnamed"}</div>
                      <div className="agent-id">{a.id.slice(0, 12)}</div>
                    </div>
                  </div>
                  <span
                    className="agent-status-label"
                    style={{ color: isActive ? "var(--state-ok)" : "var(--state-danger)" }}
                  >
                    {a.status}
                  </span>
                </div>

                <div className="agent-endpoint">
                  {a.ip}
                  <span className="agent-port">:{a.port}</span>
                </div>

                <dl className="agent-meta">
                  <div><dt>OS</dt><dd>{a.os || "—"}</dd></div>
                  <div><dt>Arch</dt><dd>{a.arch || "—"}</dd></div>
                  <div><dt>Version</dt><dd>{a.version || "—"}</dd></div>
                  <div><dt>Kernel</dt><dd className="truncate" title={a.kernel}>{a.kernel || "—"}</dd></div>
                </dl>

                <div className="agent-card-foot">
                  <div className="agent-capacity">
                    <span className="agent-capacity-label">Capacity</span>
                    <span className="agent-capacity-value">{a.max_concurrent_tasks} tasks</span>
                  </div>
                  <span className="agent-lastseen" title={a.last_seen_at}>
                    {relTime(a.last_seen_at)}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
