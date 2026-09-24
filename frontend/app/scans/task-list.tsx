"use client";

import { useCallback, useEffect, useState } from "react";

type Task = {
  task_id: string;
  id: number;
  target: string;
  status: string;
  agent_id: string | null;
  attempts: number;
  error: string | null;
  created_at: string;
  updated_at: string;
};

const STATUS_COLOR: Record<string, string> = {
  queued: "var(--state-idle)",
  claimed: "var(--state-warn)",
  running: "var(--state-active)",
  done: "var(--state-ok)",
  failed: "var(--state-danger)",
};

const POLL_MS = 4000;

export default function TaskList() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/proxy/api/tasks?limit=50");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setTasks(body.data ?? []);
      setError(null);
    } catch (e: any) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    if (paused) return;
    load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, [load, paused]);

  return (
    <div className="card-panel" style={{ marginTop: 24 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 12,
        }}
      >
        <div
          style={{
            fontSize: 12,
            fontFamily: "JetBrains Mono",
            color: "var(--color-text-muted)",
            fontWeight: 600,
            letterSpacing: "0.05em",
          }}
        >
          TASK QUEUE ({tasks.length})
        </div>
        <button
          onClick={() => setPaused((p) => !p)}
          className="pill-btn"
          style={{ fontSize: 11 }}
        >
          {paused ? "▶ Resume" : "❚❚ Pause"}
        </button>
      </div>

      {error && (
        <div style={{ fontSize: 12, color: "var(--state-danger)", marginBottom: 8 }}>
          {error}
        </div>
      )}

      {tasks.length === 0 ? (
        <div style={{ fontSize: 13, color: "var(--color-text-muted)", padding: "12px 0" }}>
          queue is empty
        </div>
      ) : (
        <div style={{ overflowX: "auto", margin: "0 -4px", padding: "0 4px" }}>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontSize: 12,
            fontFamily: "JetBrains Mono",
            minWidth: 640,
          }}
        >
          <thead>
            <tr style={{ color: "#818b98", textAlign: "left" }}>
              <th style={th}>TASK</th>
              <th style={th}>TARGET</th>
              <th style={th}>STATUS</th>
              <th style={th}>AGENT</th>
              <th style={th}>ATTEMPTS</th>
              <th style={th}>UPDATED</th>
              <th style={th}>ERROR</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map((t) => (
              <tr key={`${t.task_id}-${t.id}`} style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                <td style={td} title={t.task_id}>
                  {t.task_id.slice(0, 8)}
                </td>
                <td style={td}>{t.target}</td>
                <td style={td}>
                  <span
                    style={{
                      color: STATUS_COLOR[t.status] ?? "var(--state-idle)",
                      textTransform: "uppercase",
                      fontWeight: 600,
                    }}
                  >
                    {t.status}
                  </span>
                </td>
                <td style={td}>{t.agent_id ? t.agent_id.slice(0, 8) : "—"}</td>
                <td style={td}>{t.attempts}</td>
                <td style={td}>{fmt(t.updated_at)}</td>
                <td style={{ ...td, color: "var(--state-danger)", maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={t.error ?? ""}>
                  {t.error ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
    </div>
  );
}

const th: React.CSSProperties = {
  padding: "6px 8px",
  fontSize: 11,
  fontWeight: 600,
};
const td: React.CSSProperties = { padding: "6px 8px" };

function fmt(s: string): string {
  if (!s) return "—";
  const d = new Date(s.includes("T") ? s : s.replace(" ", "T") + "Z");
  if (isNaN(d.getTime())) return s;
  return d.toLocaleString("ru-RU", { hour12: false });
}
