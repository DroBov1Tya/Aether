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

export default async function AgentsPage() {
  const agents = await getAgents();

  return (
    <div className="page-container">
      <h1 className="page-title">AGENTS</h1>
      <p style={{ color: "#818b98", marginBottom: 24 }}>
        {agents.length} registered agent{agents.length !== 1 ? "s" : ""}
      </p>

      <div className="card-panel" style={{ overflowX: "auto" }}>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 12,
          }}
        >
          <thead>
            <tr style={{ borderBottom: "1px solid #30363d" }}>
              <th style={thStyle}>ID</th>
              <th style={thStyle}>IP</th>
              <th style={thStyle}>Name</th>
              <th style={thStyle}>Version</th>
              <th style={thStyle}>Port</th>
              <th style={thStyle}>OS</th>
              <th style={thStyle}>Arch</th>
              <th style={thStyle}>Kernel</th>
              <th style={thStyle}>Max Tasks</th>
              <th style={thStyle}>Status</th>
              <th style={thStyle}>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {agents.length === 0 && (
              <tr>
                <td colSpan={11} style={{ textAlign: "center", padding: 32, color: "#818b98" }}>
                  No agents registered
                </td>
              </tr>
            )}
            {agents.map((a) => (
              <tr
                key={a.id}
                style={{ borderBottom: "1px solid #21262d" }}
              >
                <td style={tdStyle}>
                  <span style={{ color: "#8c93fb" }}>{a.id.slice(0, 8)}</span>
                </td>
                <td style={tdStyle}>{a.ip}</td>
                <td style={tdStyle}>{a.name}</td>
                <td style={tdStyle}>{a.version}</td>
                <td style={tdStyle}>{a.port}</td>
                <td style={tdStyle}>{a.os}</td>
                <td style={tdStyle}>{a.arch}</td>
                <td style={tdStyle}>{a.kernel}</td>
                <td style={tdStyle}>
                  <StatusBadge value={a.max_concurrent_tasks} />
                </td>
                <td style={tdStyle}>
                  <span
                    style={{
                      color: a.status === "active" ? "#3fb950" : "#f85149",
                      fontWeight: 600,
                    }}
                  >
                    {a.status}
                  </span>
                </td>
                <td style={{ ...tdStyle, color: "#818b98" }}>
                  {a.last_seen_at}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatusBadge({ value }: { value: number }) {
  const color = value >= 10 ? "#3fb950" : value >= 5 ? "#d29922" : "#f85149";
  return <span style={{ color, fontWeight: 600 }}>{value}</span>;
}

const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "10px 12px",
  color: "#818b98",
  fontWeight: 600,
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "0.05em",
};

const tdStyle: React.CSSProperties = {
  padding: "10px 12px",
  color: "#f0f6fc",
  whiteSpace: "nowrap",
};
