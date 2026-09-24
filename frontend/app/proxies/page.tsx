"use client";

import { useEffect, useMemo, useState } from "react";
import {
  listProxies,
  addProxies,
  deleteProxy,
  deleteAllProxies,
  type ProxyEntry,
} from "@/lib/api";

export default function ProxiesPage() {
  const [proxies, setProxies] = useState<ProxyEntry[]>([]);
  const [raw, setRaw] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function refresh() {
    setLoading(true);
    try {
      const data = await listProxies();
      setProxies(Array.isArray(data) ? data : []);
      setError(null);
    } catch (e: any) {
      setError(e.message || "Failed to load proxies");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  // Count non-empty lines in the add box for the button label.
  const pending = useMemo(
    () => raw.split("\n").map((l) => l.trim()).filter(Boolean).length,
    [raw],
  );

  async function onAdd() {
    if (pending === 0) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await addProxies(raw);
      setNotice(`Added ${res.added ?? pending} proxies`);
      setRaw("");
      await refresh();
    } catch (e: any) {
      setError(e.message || "Add failed");
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteOne(url: string) {
    setBusy(true);
    try {
      await deleteProxy(url);
      await refresh();
    } catch (e: any) {
      setError(e.message || "Delete failed");
    } finally {
      setBusy(false);
    }
  }

  async function onClearAll() {
    if (!confirm("Remove ALL proxies from the pool?")) return;
    setBusy(true);
    try {
      await deleteAllProxies();
      await refresh();
    } catch (e: any) {
      setError(e.message || "Clear failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page-container proxies-page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Proxies</h1>
          <p className="page-subtitle">
            Shared proxy pool — agents try direct first, then walk this list in order on blocks
          </p>
        </div>
      </div>

      <div className="proxies-grid">
        {/* Active pool */}
        <div className="panel proxies-active">
          <div className="pt">
            Active pool
            <span className="proxies-count">{proxies.length}</span>
            {proxies.length > 0 && (
              <button className="copy-btn danger" onClick={onClearAll} disabled={busy}>
                Clear all
              </button>
            )}
          </div>

          {loading ? (
            <p className="field-hint">Loading…</p>
          ) : proxies.length === 0 ? (
            <p className="field-hint">Pool is empty — agents scan direct only.</p>
          ) : (
            <ul className="proxy-list">
              {proxies.map((p) => (
                <li key={p.url} className="proxy-row">
                  <span className="proxy-url">{p.url}</span>
                  <button
                    className="proxy-del"
                    title="Remove"
                    onClick={() => onDeleteOne(p.url)}
                    disabled={busy}
                  >
                    ✕
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Add box */}
        <aside className="panel proxies-add">
          <div className="pt">Add proxies</div>
          <p className="field-hint" style={{ marginTop: 0 }}>
            One per line. Format: <code>scheme://[user:pass@]host:port</code> —
            e.g. <code>socks5://10.0.0.1:1080</code> or <code>http://user:pass@1.2.3.4:8080</code>.
          </p>
          <textarea
            className="import-textarea"
            placeholder={"socks5://1.2.3.4:1080\nhttp://user:pass@5.6.7.8:8080"}
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            spellCheck={false}
          />
          <button className="query-run" onClick={onAdd} disabled={busy || pending === 0}>
            {busy ? "Saving…" : pending > 0 ? `Add ${pending}` : "Add"}
          </button>
          {notice && <div className="preview-ok" style={{ marginTop: 12 }}>{notice}</div>}
          {error && <div className="query-error" style={{ marginTop: 12 }}>ERROR: {error}</div>}
        </aside>
      </div>
    </div>
  );
}
