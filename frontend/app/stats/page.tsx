import {
  getStatsSummary,
  getTopPorts,
  getTopServices,
  getTopTechnologies,
} from "@/lib/api";

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toString();
}

function BarRow({
  label,
  count,
  maxCount,
}: {
  label: string;
  count: number;
  maxCount: number;
}) {
  const pct = maxCount > 0 ? `${(count / maxCount) * 100}%` : "0%";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
      <span
        style={{
          fontFamily: "JetBrains Mono",
          fontSize: 13,
          color: "#f0f6fc",
          minWidth: 140,
        }}
      >
        {label}
      </span>
      <div
        style={{
          flex: 1,
          height: 8,
          background: "#21262d",
          borderRadius: 4,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: pct,
            height: "100%",
            background: "linear-gradient(90deg, #8c93fb, #5fed83)",
            borderRadius: 4,
          }}
        />
      </div>
      <span
        style={{
          fontFamily: "JetBrains Mono",
          fontSize: 13,
          color: "#a4aea6",
          minWidth: 60,
          textAlign: "right",
        }}
      >
        {formatNumber(count)}
      </span>
    </div>
  );
}

export default async function StatsPage() {
  let summary = null;
  let ports: any[] = [];
  let services: any[] = [];
  let techs: any[] = [];

  try {
    summary = await getStatsSummary();
  } catch {}
  try {
    ports = await getTopPorts(10);
  } catch {}
  try {
    services = await getTopServices(10);
  } catch {}
  try {
    techs = await getTopTechnologies(20);
  } catch {}

  const maxPortCount = ports.length > 0 ? ports[0].count : 1;
  const maxServiceCount = services.length > 0 ? services[0].count : 1;

  return (
    <div className="page-container">
      <h1 className="page-title">STATISTICS</h1>
      <p style={{ color: "#818b98", marginBottom: 48 }}>
        Network intelligence overview
      </p>

      {summary && (
        <div className="stats-grid">
          <div className="stat-box">
            <div className="stat-value">
              {formatNumber(summary.total_hosts)}
            </div>
            <div className="stat-label">TOTAL HOSTS</div>
          </div>
          <div className="stat-box">
            <div className="stat-value">
              {formatNumber(summary.total_ports)}
            </div>
            <div className="stat-label">OPEN PORTS</div>
          </div>
          <div className="stat-box">
            <div className="stat-value">
              {formatNumber(summary.total_services)}
            </div>
            <div className="stat-label">SERVICES</div>
          </div>
          <div className="stat-box">
            <div className="stat-value">
              {formatNumber(summary.total_technologies)}
            </div>
            <div className="stat-label">TECHNOLOGIES</div>
          </div>
        </div>
      )}

      {ports.length > 0 && (
        <div className="card-panel" style={{ marginTop: 32 }}>
          <h2 className="panel-title">Top Ports</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {ports.map((p) => (
              <BarRow
                key={p.port}
                label={`${p.port}`}
                count={p.count}
                maxCount={maxPortCount}
              />
            ))}
          </div>
        </div>
      )}

      {services.length > 0 && (
        <div className="card-panel" style={{ marginTop: 32 }}>
          <h2 className="panel-title">Top Services</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {services.map((s) => (
              <BarRow
                key={s.service}
                label={s.service}
                count={s.count}
                maxCount={maxServiceCount}
              />
            ))}
          </div>
        </div>
      )}

      {techs.length > 0 && (
        <div className="card-panel" style={{ marginTop: 32 }}>
          <h2 className="panel-title">Top Technologies</h2>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {techs.map((t) => (
              <div key={t.technology} className="tech-stat-pill">
                <span>{t.technology}</span>
                <span style={{ color: "#8c93fb", marginLeft: 6 }}>
                  {formatNumber(t.count)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
