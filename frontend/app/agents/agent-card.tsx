"use client";

import { useState } from "react";
import { updateAgentConcurrency } from "@/lib/api";

export interface AgentCardData {
  agent_id: string;
  ip: string;
  name: string;
  version: string;
  port: number;
  os: string;
  arch: string;
  kernel: string;
  max_concurrent_tasks: number;
  busy_tasks: number;
  status: string;
  last_seen_at: string;
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

export default function AgentCard({ agent }: { agent: AgentCardData }) {
  const isActive = agent.status === "active";
  const [cap, setCap] = useState(agent.max_concurrent_tasks);
  const [draft, setDraft] = useState(agent.max_concurrent_tasks);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const dirty = draft !== cap;

  async function save() {
    if (!dirty || saving) return;
    setSaving(true);
    setError(null);
    try {
      const clamped = Math.max(1, Math.min(100, Math.round(draft)));
      await updateAgentConcurrency(agent.agent_id, clamped);
      setCap(clamped);
      setDraft(clamped);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e: any) {
      setError(e?.message || "failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="agent-card">
      <div className="agent-card-head">
        <div className="agent-identity">
          <span
            className="agent-status-dot"
            style={{ background: isActive ? "var(--state-ok)" : "var(--state-danger)" }}
          />
          <div>
            <div className="agent-name">{agent.name || "unnamed"}</div>
            <div className="agent-id">{(agent.agent_id || "").slice(0, 12)}</div>
          </div>
        </div>
        <span
          className="agent-status-label"
          style={{ color: isActive ? "var(--state-ok)" : "var(--state-danger)" }}
        >
          {agent.status}
        </span>
      </div>

      <div className="agent-endpoint">
        {agent.ip}
        <span className="agent-port">:{agent.port}</span>
      </div>

      <dl className="agent-meta">
        <div><dt>OS</dt><dd>{agent.os || "—"}</dd></div>
        <div><dt>Arch</dt><dd>{agent.arch || "—"}</dd></div>
        <div><dt>Version</dt><dd>{agent.version || "—"}</dd></div>
        <div><dt>Kernel</dt><dd className="truncate" title={agent.kernel}>{agent.kernel || "—"}</dd></div>
      </dl>

      <div className="agent-concurrency">
        <div className="agent-concurrency-label">
          <span>Max concurrent scans</span>
          <span className="agent-concurrency-hint">applied live · lower this to protect your network</span>
        </div>
        <div className="agent-concurrency-control">
          <button
            type="button"
            className="conc-step"
            onClick={() => setDraft((d) => Math.max(1, d - 1))}
            disabled={saving || draft <= 1}
            aria-label="decrease"
          >
            −
          </button>
          <input
            type="number"
            min={1}
            max={100}
            value={draft}
            onChange={(e) => setDraft(parseInt(e.target.value || "1", 10))}
            className="conc-input"
          />
          <button
            type="button"
            className="conc-step"
            onClick={() => setDraft((d) => Math.min(100, d + 1))}
            disabled={saving || draft >= 100}
            aria-label="increase"
          >
            +
          </button>
          <button
            type="button"
            className="conc-apply"
            onClick={save}
            disabled={!dirty || saving}
          >
            {saving ? "…" : saved ? "✓" : "Apply"}
          </button>
        </div>
        {error && <div className="conc-error">{error}</div>}
      </div>

      <div className="agent-card-foot">
        <div className="agent-capacity">
          <span className="agent-capacity-label">Busy</span>
          <span className="agent-capacity-value">{agent.busy_tasks}/{cap}</span>
        </div>
        <span className="agent-lastseen" title={agent.last_seen_at}>
          {relTime(agent.last_seen_at)}
        </span>
      </div>
    </div>
  );
}
