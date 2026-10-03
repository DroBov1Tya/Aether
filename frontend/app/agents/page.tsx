import { fetchApi } from "@/lib/api";
import AgentCard, { AgentCardData } from "./agent-card";

async function getAgents(): Promise<AgentCardData[]> {
  try {
    return await fetchApi<AgentCardData[]>("/api/agents");
  } catch {
    return [];
  }
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
          {agents.map((a) => (
            <AgentCard key={a.agent_id} agent={a} />
          ))}
        </div>
      )}
    </div>
  );
}
