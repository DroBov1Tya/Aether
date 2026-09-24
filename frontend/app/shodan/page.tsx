"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  getShodanInfo,
  shodanSearch,
  shodanImport,
  shodanHostLookup,
  shodanImportHosts,
  type ShodanUsage,
  type ShodanMatch,
  type ShodanHostInfo,
} from "@/lib/api";

const EXAMPLES = [
  { label: "ClickHouse (открытые)", q: "product:ClickHouse" },
  { label: "Elasticsearch RU", q: "product:Elasticsearch country:RU" },
  { label: "MongoDB без auth", q: 'product:MongoDB "Set-Cookie"' },
  { label: "nginx 200 в RU", q: "http.status:200 country:RU product:nginx" },
];

function Usage({ usage }: { usage: ShodanUsage }) {
  const cells = [
    { k: "Query credits", v: usage.query_credits ?? 0, accent: true },
    { k: "Scan credits", v: usage.scan_credits ?? 0 },
    { k: "Plan", v: usage.plan || "—" },
    { k: "Monitored IPs", v: usage.monitored_ips ?? 0 },
  ];
  return (
    <div className="option-grid cols-settings" style={{ marginTop: 4 }}>
      {cells.map((c) => (
        <div key={c.k} className="launch-summary-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: 4 }}>
          <span className="launch-summary-label">{c.k}</span>
          <span
            className="launch-summary-value"
            style={{
              fontSize: 22,
              fontFamily: "JetBrains Mono",
              color: c.accent ? "var(--color-champagne)" : "var(--color-text-soft)",
            }}
          >
            {c.v}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function ShodanPage() {
  const router = useRouter();

  const [usage, setUsage] = useState<ShodanUsage | null>(null);
  const [usageErr, setUsageErr] = useState<string | null>(null);
  const [usageBusy, setUsageBusy] = useState(false);

  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [searching, setSearching] = useState(false);
  const [searchErr, setSearchErr] = useState<string | null>(null);
  const [matches, setMatches] = useState<ShodanMatch[]>([]);
  const [total, setTotal] = useState(0);

  const [pages, setPages] = useState("1");
  const [project, setProject] = useState("");
  const [importing, setImporting] = useState(false);
  const [importRes, setImportRes] = useState<any>(null);
  const [importErr, setImportErr] = useState<string | null>(null);

  const [mode, setMode] = useState<"search" | "host">("search");
  const [ipInput, setIpInput] = useState("");
  const [hostBusy, setHostBusy] = useState(false);
  const [hostErr, setHostErr] = useState<string | null>(null);
  const [hostInfo, setHostInfo] = useState<ShodanHostInfo | null>(null);
  const [hostImporting, setHostImporting] = useState(false);
  const [hostImportRes, setHostImportRes] = useState<any>(null);

  const ipList = ipInput
    .split(/[\n,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  async function lookupHost() {
    if (ipList.length === 0) return;
    setHostBusy(true);
    setHostErr(null);
    setHostInfo(null);
    setHostImportRes(null);
    try {
      const res = await shodanHostLookup(ipList[0]);
      setHostInfo(res);
    } catch (e: any) {
      setHostErr(e.message || "Lookup failed");
    } finally {
      setHostBusy(false);
    }
  }

  async function importHosts() {
    if (ipList.length === 0) return;
    setHostImporting(true);
    setHostErr(null);
    setHostImportRes(null);
    try {
      const res = await shodanImportHosts(ipList, project.trim() || undefined);
      setHostImportRes(res);
      loadUsage();
    } catch (e: any) {
      setHostErr(e.message || "Import failed");
    } finally {
      setHostImporting(false);
    }
  }

  const loadUsage = useCallback(async () => {
    setUsageBusy(true);
    setUsageErr(null);
    try {
      const res = await getShodanInfo();
      setUsage(res.info);
    } catch (e: any) {
      setUsageErr(e.message || "Failed to load usage");
    } finally {
      setUsageBusy(false);
    }
  }, []);

  useEffect(() => {
    loadUsage();
  }, [loadUsage]);

  async function runSearch(p = 1) {
    if (!query.trim()) return;
    setSearching(true);
    setSearchErr(null);
    setImportRes(null);
    try {
      const res = await shodanSearch(query.trim(), p);
      setMatches(res.matches);
      setTotal(res.total);
      setPage(res.page);
    } catch (e: any) {
      setSearchErr(e.message || "Search failed");
      setMatches([]);
      setTotal(0);
    } finally {
      setSearching(false);
    }
  }

  async function runImport() {
    if (!query.trim()) return;
    setImporting(true);
    setImportErr(null);
    setImportRes(null);
    try {
      const n = Math.max(1, Math.min(20, parseInt(pages) || 1));
      const res = await shodanImport(query.trim(), n, project.trim() || undefined);
      setImportRes(res);
      loadUsage();
    } catch (e: any) {
      setImportErr(e.message || "Import failed");
    } finally {
      setImporting(false);
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / 100));

  return (
    <div className="page-container">
      <div className="page-head">
        <div>
          <h1 className="page-title">Shodan</h1>
          <p className="page-subtitle">
            Импорт знаний из Shodan — поиск по всей базе, результаты складываются в БД
            и появляются в общем Search
          </p>
        </div>
      </div>

      <div className="card-panel">
        <h2 className="panel-title" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <span>Остаток квоты</span>
          <button
            className="copy-btn"
            onClick={loadUsage}
            disabled={usageBusy}
          >
            {usageBusy ? "…" : "Обновить"}
          </button>
        </h2>
        {usageErr && (
          <div className="query-error" style={{ marginTop: 4 }}>
            {usageErr.includes("not configured")
              ? "SHODAN_API_KEY не задан в .env бэкенда"
              : `ERROR: ${usageErr}`}
          </div>
        )}
        {usage && <Usage usage={usage} />}
        {!usage && !usageErr && (
          <div className="field-hint">Загрузка…</div>
        )}
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        <button
          className={`option-card${mode === "search" ? " is-selected" : ""}`}
          style={{ flex: 1, cursor: "pointer" }}
          onClick={() => setMode("search")}
        >
          <div>
            <div className="option-card-title">Поиск по базе</div>
            <div className="option-card-desc">host/search · требует query-credits</div>
          </div>
        </button>
        <button
          className={`option-card${mode === "host" ? " is-selected" : ""}`}
          style={{ flex: 1, cursor: "pointer" }}
          onClick={() => setMode("host")}
        >
          <div>
            <div className="option-card-title">Lookup по IP</div>
            <div className="option-card-desc">host/{"{ip}"} · бесплатно на dev</div>
          </div>
        </button>
      </div>

      {mode === "search" && (
      <>
      <div className="card-panel">
        <h2 className="panel-title">Запрос</h2>
        <div style={{ display: "flex", gap: 10 }}>
          <input
            className="form-input"
            placeholder='product:ClickHouse country:RU port:8123'
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") runSearch(1);
            }}
            spellCheck={false}
            style={{ flex: 1, fontFamily: "JetBrains Mono" }}
          />
          <button
            className="scan-btn"
            style={{ width: "auto", marginTop: 0, padding: "0 26px" }}
            onClick={() => runSearch(1)}
            disabled={searching || !query.trim()}
          >
            {searching ? "Поиск…" : "Найти"}
          </button>
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 12 }}>
          {EXAMPLES.map((ex) => (
            <button
              key={ex.q}
              className="copy-btn"
              onClick={() => setQuery(ex.q)}
            >
              {ex.label}
            </button>
          ))}
        </div>
        <div className="field-hint" style={{ marginTop: 10 }}>
          Синтаксис Shodan: <code>product:</code>, <code>country:</code>,{" "}
          <code>port:</code>, <code>org:</code>, <code>http.title:</code>. Одна
          страница поиска ≈ 1 query-credit.
        </div>
        {searchErr && <div className="query-error" style={{ marginTop: 12 }}>ERROR: {searchErr}</div>}
      </div>

      {(matches.length > 0 || total > 0) && (
        <div className="card-panel">
          <h2 className="panel-title" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>
              Результаты · всего{" "}
              <span style={{ color: "var(--color-champagne)" }}>{total.toLocaleString()}</span>
            </span>
            <span style={{ fontSize: 12, color: "var(--color-text-muted)", fontFamily: "var(--font-mono)" }}>
              стр. {page} / {totalPages}
            </span>
          </h2>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, fontFamily: "JetBrains Mono" }}>
              <thead>
                <tr style={{ textAlign: "left", color: "var(--color-text-muted)", fontSize: 11, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                  <th style={{ padding: "8px 10px" }}>IP</th>
                  <th style={{ padding: "8px 10px" }}>Порт</th>
                  <th style={{ padding: "8px 10px" }}>Продукт</th>
                  <th style={{ padding: "8px 10px" }}>Org</th>
                  <th style={{ padding: "8px 10px" }}>CC</th>
                  <th style={{ padding: "8px 10px" }}>Hostnames</th>
                </tr>
              </thead>
              <tbody>
                {matches.map((m, i) => (
                  <tr key={i} style={{ borderTop: "1px solid var(--color-border-subtle)" }}>
                    <td style={{ padding: "8px 10px" }}>
                      <button
                        className="copy-btn"
                        style={{ padding: 0, background: "none", border: "none", color: "var(--color-champagne)" }}
                        onClick={() => router.push(`/host/${encodeURIComponent(m.ip)}`)}
                      >
                        {m.ip}
                      </button>
                    </td>
                    <td style={{ padding: "8px 10px" }}>{m.port}</td>
                    <td style={{ padding: "8px 10px", color: "var(--color-text-soft)" }}>{m.product || "—"}</td>
                    <td style={{ padding: "8px 10px", color: "var(--color-text-muted)", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.org || "—"}</td>
                    <td style={{ padding: "8px 10px" }}>{m.country_code || "—"}</td>
                    <td style={{ padding: "8px 10px", color: "var(--color-text-muted)", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {m.hostnames?.join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div style={{ display: "flex", gap: 10, marginTop: 14, alignItems: "center" }}>
            <button className="copy-btn" disabled={page <= 1 || searching} onClick={() => runSearch(page - 1)}>← Назад</button>
            <button className="copy-btn" disabled={page >= totalPages || searching} onClick={() => runSearch(page + 1)}>Вперёд →</button>
          </div>
        </div>
      )}

      <div className="card-panel">
        <h2 className="panel-title">Импорт в базу</h2>
        <p className="field-hint" style={{ marginTop: 0 }}>
          Забирает N страниц текущего запроса и раскладывает по scan_results (порты,
          web, TLS, DNS, гео). Каждая страница ≈ 1 query-credit.
        </p>
        <div className="option-grid cols-settings" style={{ marginTop: 12 }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Страниц (по 100 хостов)</label>
            <input
              type="number"
              className="form-input"
              min={1}
              max={20}
              value={pages}
              onChange={(e) => setPages(e.target.value)}
            />
          </div>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Проект (пусто = общий индекс)</label>
            <input
              className="form-input"
              placeholder="global"
              value={project}
              onChange={(e) => setProject(e.target.value)}
              spellCheck={false}
            />
          </div>
        </div>
        <button
          className="scan-btn"
          style={{ marginTop: 16 }}
          onClick={runImport}
          disabled={importing || !query.trim()}
        >
          {importing ? "Импорт…" : `Импортировать «${query.trim() || "…"}»`}
        </button>

        {importErr && <div className="query-error" style={{ marginTop: 14 }}>ERROR: {importErr}</div>}
        {importRes && importRes.status === "ok" && (
          <div className="import-result" style={{ marginTop: 16 }}>
            <p className="import-result-title">
              Импортировано в <b>{importRes.project}</b> · страниц: {importRes.pages_fetched} / доступно ~{importRes.total_available?.toLocaleString?.() ?? importRes.total_available}
            </p>
            <div className="import-result-grid">
              <div><span>{importRes.imported?.hosts ?? 0}</span>hosts</div>
              <div><span>{importRes.imported?.ports ?? 0}</span>ports</div>
              <div><span>{importRes.imported?.http ?? 0}</span>http</div>
              <div><span>{importRes.imported?.tls ?? 0}</span>tls</div>
              <div><span>{importRes.imported?.geo ?? 0}</span>geo</div>
            </div>
            <button
              className="insp-open"
              style={{ maxWidth: 260 }}
              onClick={() =>
                importRes.project && importRes.project !== "global"
                  ? router.push(`/projects/${encodeURIComponent(importRes.project)}`)
                  : router.push(`/search`)
              }
            >
              {importRes.project && importRes.project !== "global" ? "Открыть проект →" : "Открыть поиск →"}
            </button>
          </div>
        )}
      </div>
      </>
      )}

      {mode === "host" && (
        <div className="card-panel">
          <h2 className="panel-title">Lookup по IP (бесплатно на dev-плане)</h2>
          <p className="field-hint" style={{ marginTop: 0 }}>
            Один IP на строку или через запятую. «Проверить» тянет один IP для
            предпросмотра, «Импортировать» забирает все IP в БД. host/{"{ip}"} не
            тратит query-credits.
          </p>
          <textarea
            className="form-textarea"
            placeholder={"8.8.8.8\n1.1.1.1\n45.33.32.156"}
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            spellCheck={false}
            style={{ height: 120, fontFamily: "JetBrains Mono" }}
          />
          <div className="form-group" style={{ marginTop: 12, marginBottom: 0, maxWidth: 320 }}>
            <label className="form-label">Проект (пусто = общий индекс)</label>
            <input
              className="form-input"
              placeholder="global"
              value={project}
              onChange={(e) => setProject(e.target.value)}
              spellCheck={false}
            />
          </div>
          <div style={{ display: "flex", gap: 10, marginTop: 16, flexWrap: "wrap" }}>
            <button
              className="copy-btn"
              onClick={lookupHost}
              disabled={hostBusy || ipList.length === 0}
            >
              {hostBusy ? "Проверка…" : "Проверить первый IP"}
            </button>
            <button
              className="scan-btn"
              style={{ width: "auto", marginTop: 0, padding: "0 24px" }}
              onClick={importHosts}
              disabled={hostImporting || ipList.length === 0}
            >
              {hostImporting ? "Импорт…" : `Импортировать ${ipList.length || ""} IP в БД`}
            </button>
          </div>

          {hostErr && <div className="query-error" style={{ marginTop: 14 }}>ERROR: {hostErr}</div>}

          {hostInfo && hostInfo.status === "ok" && (
            <div className="import-result" style={{ marginTop: 16 }}>
              <p className="import-result-title">
                <b>{hostInfo.ip}</b>
                {hostInfo.org ? ` · ${hostInfo.org}` : ""}
                {hostInfo.country_code ? ` · ${hostInfo.country_code}` : ""}
                {hostInfo.asn ? ` · ${hostInfo.asn}` : ""}
              </p>
              <div style={{ fontSize: 13, fontFamily: "JetBrains Mono", color: "var(--color-text-soft)", marginTop: 8 }}>
                Порты: {hostInfo.ports?.length ? hostInfo.ports.join(", ") : "—"}
              </div>
              {hostInfo.hostnames?.length > 0 && (
                <div style={{ fontSize: 13, fontFamily: "JetBrains Mono", color: "var(--color-text-muted)", marginTop: 6 }}>
                  Hostnames: {hostInfo.hostnames.join(", ")}
                </div>
              )}
            </div>
          )}

          {hostImportRes && hostImportRes.status === "ok" && (
            <div className="import-result" style={{ marginTop: 16 }}>
              <p className="import-result-title">
                Импортировано в <b>{hostImportRes.project || "global"}</b>
                {hostImportRes.requested ? ` · запрошено ${hostImportRes.requested} IP` : ""}
                {hostImportRes.failed?.length ? ` · не удалось ${hostImportRes.failed.length}` : ""}
              </p>
              <div className="import-result-grid">
                <div><span>{hostImportRes.imported?.hosts ?? 0}</span>hosts</div>
                <div><span>{hostImportRes.imported?.ports ?? 0}</span>ports</div>
                <div><span>{hostImportRes.imported?.http ?? 0}</span>http</div>
                <div><span>{hostImportRes.imported?.tls ?? 0}</span>tls</div>
                <div><span>{hostImportRes.imported?.geo ?? 0}</span>geo</div>
              </div>
              <button
                className="insp-open"
                style={{ maxWidth: 260 }}
                onClick={() =>
                  hostImportRes.project && hostImportRes.project !== "global"
                    ? router.push(`/projects/${encodeURIComponent(hostImportRes.project)}`)
                    : router.push(`/search`)
                }
              >
                {hostImportRes.project && hostImportRes.project !== "global" ? "Открыть проект →" : "Открыть поиск →"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
