"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { importProject } from "@/lib/api";

const SAMPLE = `{
  "project": "acme-internal",
  "source": "nmap manual 2026-09-20",
  "hosts": [
    {
      "target": "10.0.4.12",
      "country": "US",
      "ports": [
        { "port": 443, "service": "https", "product": "nginx", "version": "1.25.3" },
        { "port": 22,  "service": "ssh",   "product": "OpenSSH", "version": "9.6" }
      ],
      "technologies": ["nginx", "PHP", "Bootstrap"],
      "http": {
        "port": 443,
        "url": "https://10.0.4.12",
        "status": 200,
        "title": "Admin Login",
        "webserver": "nginx",
        "favicon_hash": "-1203481"
      },
      "tls": {
        "port": 443,
        "subject": "CN=vpn.acme.local",
        "issuer": "Internal CA",
        "san": ["vpn.acme.local"],
        "not_after": "2027-01-01",
        "jarm": "29d3fd00029d..."
      },
      "dns": {
        "a": ["10.0.4.12"],
        "ptr": ["dc01.acme.local"]
      },
      "notes": "domain controller"
    }
  ]
}`;

const AI_PROMPT = `You convert raw network-scan output into Aether's import JSON.

Rules:
- Output ONLY valid JSON, no markdown fences, no commentary.
- Top level: { "project": "<name>", "source": "<where it came from>", "hosts": [ ... ] }.
- Each host: { "target" (IP or hostname, required), "country"?, "ports": [ { "port", "service"?, "product"?, "version"? } ], "technologies": [str], "http": { "port","url","status","title","webserver"?,"favicon_hash"? }, "tls": { "port","subject","issuer","san":[str],"not_after"?,"jarm"? }, "dns": { "a":[],"aaaa":[],"cname":[],"mx":[],"ns":[],"txt":[],"ptr":[] } }.
- Every field except target is optional; omit what you don't have.
- Merge all records for one host into a single hosts[] entry.

Here is the scan output to convert:
<PASTE SCAN OUTPUT HERE>`;

function Copyable({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="copy-btn"
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? "Copied ✓" : label}
    </button>
  );
}

export default function ImportPage() {
  const router = useRouter();
  const [project, setProject] = useState("");
  const [raw, setRaw] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  // live validation / preview
  const preview = useMemo(() => {
    if (!raw.trim()) return null;
    try {
      const parsed = JSON.parse(raw);
      const hosts = Array.isArray(parsed.hosts) ? parsed.hosts : [];
      const ports = hosts.reduce(
        (n: number, h: any) => n + (Array.isArray(h.ports) ? h.ports.length : 0),
        0,
      );
      return { ok: true as const, hosts: hosts.length, ports, embeddedProject: parsed.project };
    } catch (e: any) {
      return { ok: false as const, error: e.message };
    }
  }, [raw]);

  const effectiveProject = project.trim() || (preview?.ok ? preview.embeddedProject : "") || "";
  const canSubmit =
    !busy && preview?.ok && preview.hosts > 0 && !!effectiveProject &&
    effectiveProject.toLowerCase() !== "global";

  async function onFile(f: File) {
    const text = await f.text();
    setRaw(text);
  }

  async function submit() {
    setError(null);
    setResult(null);
    if (!preview?.ok) {
      setError("Invalid JSON");
      return;
    }
    setBusy(true);
    try {
      const parsed = JSON.parse(raw);
      parsed.project = effectiveProject; // project field wins
      const res = await importProject(parsed);
      setResult(res);
    } catch (e: any) {
      setError(e.message || "Import failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page-container import-page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Import</h1>
          <p className="page-subtitle">
            Load scan results into an isolated project — kept out of the public index
          </p>
        </div>
      </div>

      <div className="import-grid">
        {/* left: the form */}
        <div className="import-main">
          <label className="field-label" htmlFor="proj">Project name <span className="req">*</span></label>
          <input
            id="proj"
            className="query-input import-input"
            placeholder="e.g. acme-internal"
            value={project}
            onChange={(e) => setProject(e.target.value)}
            spellCheck={false}
            autoComplete="off"
          />
          <p className="field-hint">
            Results are stored under this project and shown only in the Projects tab —
            never mixed into the public search index. (Reserved name <code>global</code> = public index.)
          </p>

          <label className="field-label" style={{ marginTop: 20 }}>Payload (JSON)</label>
          <div
            className="dropzone"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              const f = e.dataTransfer.files?.[0];
              if (f) onFile(f);
            }}
          >
            <textarea
              className="import-textarea"
              placeholder="Paste JSON here, or drag & drop a .json file…"
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              spellCheck={false}
            />
          </div>

          <div className="import-actions">
            {preview && !preview.ok && (
              <span className="preview-bad">Invalid JSON: {preview.error}</span>
            )}
            {preview && preview.ok && (
              <span className="preview-ok">
                {preview.hosts} host{preview.hosts !== 1 ? "s" : ""} · {preview.ports} port
                {preview.ports !== 1 ? "s" : ""} → project <b>{effectiveProject || "?"}</b>
              </span>
            )}
            <button className="query-run import-submit" disabled={!canSubmit} onClick={submit}>
              {busy ? "Importing…" : "Import"}
            </button>
          </div>

          {error && <div className="query-error" style={{ marginTop: 14 }}>ERROR: {error}</div>}
          {result && (
            <div className="import-result">
              <p className="import-result-title">Imported into <b>{result.project}</b></p>
              <div className="import-result-grid">
                <div><span>{result.imported?.hosts ?? 0}</span>hosts</div>
                <div><span>{result.imported?.ports ?? 0}</span>ports</div>
                <div><span>{result.imported?.http ?? 0}</span>http</div>
                <div><span>{result.imported?.tls ?? 0}</span>tls</div>
                <div><span>{result.imported?.dns ?? 0}</span>dns</div>
                <div><span>{result.imported?.geo ?? 0}</span>geo</div>
              </div>
              <button
                className="insp-open"
                style={{ maxWidth: 260 }}
                onClick={() => router.push(`/projects/${encodeURIComponent(result.project)}`)}
              >
                Open project →
              </button>
            </div>
          )}
        </div>

        {/* right: format reference for humans + AI */}
        <aside className="import-side">
          <div className="panel">
            <div className="pt">
              Format sample
              <Copyable label="Copy JSON" text={SAMPLE} />
            </div>
            <pre className="code-sample">{SAMPLE}</pre>
          </div>

          <div className="panel">
            <div className="pt">
              AI prompt
              <Copyable label="Copy prompt" text={AI_PROMPT} />
            </div>
            <p className="field-hint" style={{ marginTop: 0 }}>
              Give this to any LLM together with raw nmap / masscan / manual output —
              it returns the exact JSON this page accepts.
            </p>
            <pre className="code-sample small">{AI_PROMPT}</pre>
          </div>
        </aside>
      </div>
    </div>
  );
}
