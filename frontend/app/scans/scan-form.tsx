"use client";

import { useState } from "react";

import CountryAsnPicker from "./country-asn-picker";

type ScanMethod = "rustscan" | "nmap" | "whatweb" | "hxn" | "fuzzing";
type ScanProfile = "full" | "quick" | "deep" | "custom";

const METHODS: {
  id: ScanMethod;
  label: string;
  description: string;
  requiresHttp: boolean;
}[] = [
  {
    id: "rustscan",
    label: "RustScan",
    description: "Fast port scanner (required for full port range)",
    requiresHttp: false,
  },
  {
    id: "nmap",
    label: "Nmap",
    description: "Service & version detection",
    requiresHttp: false,
  },
  {
    id: "whatweb",
    label: "WhatWeb",
    description: "Web technology fingerprinting",
    requiresHttp: true,
  },
  {
    id: "hxn",
    label: "HXN",
    description: "HTTP screenshots & headers",
    requiresHttp: true,
  },
];

const PROFILES: {
  id: ScanProfile;
  label: string;
  description: string;
  methods: ScanMethod[];
  portMode: string;
}[] = [
  {
    id: "full",
    label: "Full Scan",
    description: "All methods, all 65535 ports",
    methods: ["rustscan", "nmap", "whatweb", "hxn"],
    portMode: "all",
  },
  {
    id: "quick",
    label: "Quick Scan",
    description: "Top 1000 ports, fast",
    methods: ["rustscan"],
    portMode: "top1000",
  },
  {
    id: "deep",
    label: "Deep Scan",
    description: "All ports + service detection",
    methods: ["rustscan", "nmap"],
    portMode: "all",
  },
  {
    id: "custom",
    label: "Custom",
    description: "Configure manually",
    methods: [],
    portMode: "custom",
  },
];

function parseTargets(input: string) {
  const lines = input
    .split(/[\n,]+/)
    .map((l) => l.trim())
    .filter(Boolean);
  const result = {
    ips: [] as string[],
    domains: [] as string[],
    cidrs: [] as string[],
    ranges: [] as string[],
    invalid: [] as string[],
  };

  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const cidr = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
  const range =
    /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$|^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$/;
  const domain =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

  for (const line of lines) {
    if (cidr.test(line)) result.cidrs.push(line);
    else if (range.test(line)) result.ranges.push(line);
    else if (ipv4.test(line)) result.ips.push(line);
    else if (domain.test(line)) result.domains.push(line);
    else result.invalid.push(line);
  }
  return result;
}

export default function ScansPage() {
  const [targetInput, setTargetInput] = useState("");
  const [profile, setProfile] = useState<ScanProfile>("full");
  const [selectedMethods, setSelectedMethods] = useState<Set<ScanMethod>>(
    new Set(["rustscan", "nmap", "whatweb", "hxn"]),
  );
  const [portMode, setPortMode] = useState<
    "top1000" | "top10000" | "all" | "custom"
  >("all");
  const [customPorts, setCustomPorts] = useState("");
  const [httpPort, setHttpPort] = useState("");
  const [proxy, setProxy] = useState("");
  const [threads, setThreads] = useState("100");
  const [timeout, setTimeout_] = useState("1000");
  const [priority, setPriority] = useState<"low" | "normal" | "high">("normal");
  const [isScanning, setIsScanning] = useState(false);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [launchResult, setLaunchResult] = useState<string | null>(null);

  const parsed = parseTargets(targetInput);

  const injectCidrs = (cidrs: string[]) => {
    setTargetInput((prev) => {
      const existing = new Set(
        prev.split(/[\n,]+/).map((l) => l.trim()).filter(Boolean),
      );
      const fresh = cidrs.filter((c) => !existing.has(c));
      if (fresh.length === 0) return prev;
      const sep = prev.trim() ? "\n" : "";
      return prev + sep + fresh.join("\n");
    });
  };
  const totalTargets =
    parsed.ips.length +
    parsed.domains.length +
    parsed.cidrs.length +
    parsed.ranges.length;

  const handleProfileChange = (p: ScanProfile) => {
    setProfile(p);
    const profileData = PROFILES.find((pr) => pr.id === p);
    if (profileData && p !== "custom") {
      setSelectedMethods(new Set(profileData.methods));
      setPortMode(profileData.portMode as any);
    }
  };

  const toggleMethod = (m: ScanMethod) => {
    const next = new Set(selectedMethods);
    if (next.has(m)) next.delete(m);
    else next.add(m);
    setSelectedMethods(next);
    setProfile("custom");
  };

  const validate = (): string[] => {
    const errors: string[] = [];

    if (totalTargets === 0) errors.push("Add at least one target");
    if (parsed.invalid.length > 0)
      errors.push(
        `${parsed.invalid.length} invalid entries: ${parsed.invalid.slice(0, 3).join(", ")}${parsed.invalid.length > 3 ? "..." : ""}`,
      );
    if (selectedMethods.size === 0)
      errors.push("Select at least one scan method");

    const hasRustscan = selectedMethods.has("rustscan");
    const hasNmap = selectedMethods.has("nmap");
    const hasHttpMethods =
      selectedMethods.has("whatweb") || selectedMethods.has("hxn");

    if (hasHttpMethods && !hasRustscan && !hasNmap) {
      if (!httpPort) {
        errors.push(
          'WhatWeb/HXN require an HTTP port when used without RustScan/Nmap. Specify port in "HTTP Port" field.',
        );
      }
    }

    if (portMode === "all" && !hasRustscan) {
      errors.push(
        "Full port scan (all 65535) requires RustScan. Nmap alone is limited to top 1000.",
      );
    }

    if (hasNmap && !hasRustscan && portMode === "all") {
      errors.push(
        "Nmap without RustScan is limited to top 1000 ports. Add RustScan for full scan or change port mode.",
      );
    }

    if (portMode === "custom" && !customPorts.trim()) {
      errors.push("Specify custom port range");
    }

    return errors;
  };

  const buildPayload = () => {
    const hasRustscan = selectedMethods.has("rustscan");
    const hasHttpMethods =
      selectedMethods.has("whatweb") || selectedMethods.has("hxn");

    let effectivePortMode = portMode;
    if (!hasRustscan && portMode === "all") {
      effectivePortMode = "top1000";
    }

    let portRange: string | null = null;
    if (effectivePortMode === "custom") portRange = customPorts;
    else if (
      hasHttpMethods &&
      !hasRustscan &&
      !selectedMethods.has("nmap") &&
      httpPort
    ) {
      portRange = httpPort;
    }

    return {
      targets: {
        ips: parsed.ips,
        domains: parsed.domains,
        cidrs: parsed.cidrs,
        ranges: parsed.ranges,
      },
      methods: Array.from(selectedMethods),
      settings: {
        port_range: portRange,
        port_mode: effectivePortMode,
        threads: parseInt(threads) || 100,
        timeout_ms: parseInt(timeout) || 1000,
        proxy: proxy || null,
        require_http_port: httpPort ? parseInt(httpPort) : null,
      },
      priority,
      scheduled_at: null,
    };
  };

  const startScan = async () => {
    const errors = validate();
    setValidationErrors(errors);
    if (errors.length > 0) return;

    const payload = buildPayload();
    setIsScanning(true);
    setLaunchResult(null);

    try {
      const res = await fetch("/api/proxy/api/tasks/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (res.ok) {
        setLaunchResult(
          `✅ Scan launched\nTask ID: ${data.task_id}\n\n${JSON.stringify(payload, null, 2)}`,
        );
      } else {
        setLaunchResult(`❌ ${data.error || res.statusText}`);
      }
    } catch (e: any) {
      setLaunchResult(`❌ ${e.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div>
      {validationErrors.length > 0 && (
        <div
          className="card-panel"
          style={{
            marginBottom: 24,
            background: "rgba(221, 156, 143,0.06)",
            border: "1px solid rgba(221, 156, 143,0.28)",
          }}
        >
          <div
            style={{
              fontSize: 12,
              fontFamily: "JetBrains Mono",
              color: "var(--state-danger)",
              marginBottom: 8,
              fontWeight: 600,
              letterSpacing: "0.05em",
            }}
          >
            VALIDATION
          </div>
          <ul
            style={{
              margin: 0,
              paddingLeft: 20,
              color: "var(--color-text-soft)",
              fontSize: 13,
            }}
          >
            {validationErrors.map((e, i) => (
              <li key={i} style={{ marginBottom: 4 }}>
                {e}
              </li>
            ))}
          </ul>
        </div>
      )}

      {launchResult && (
        <div
          className="card-panel"
          style={{
            marginBottom: 24,
            background: launchResult.startsWith("✅")
              ? "rgba(169, 190, 140,0.06)"
              : "rgba(221, 156, 143,0.06)",
            border: `1px solid ${launchResult.startsWith("✅") ? "rgba(169, 190, 140,0.28)" : "rgba(221, 156, 143,0.28)"}`,
          }}
        >
          <pre
            style={{
              margin: 0,
              fontFamily: "JetBrains Mono",
              fontSize: 12,
              color: launchResult.startsWith("✅") ? "var(--state-ok)" : "var(--state-danger)",
              whiteSpace: "pre-wrap",
            }}
          >
            {launchResult}
          </pre>
        </div>
      )}

      <div className="scan-layout">
        <div className="scan-config">
          <div className="card-panel">
            <h2 className="panel-title">Targets</h2>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">
                IP addresses, domains, CIDR ranges, or IP ranges — one per line
                or comma-separated
              </label>
              <textarea
                className="form-textarea"
                placeholder={`192.168.1.1\n10.0.0.0/24\n172.16.0.1-172.16.0.100\nexample.com\n8.8.8.8, 1.1.1.1`}
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                style={{ height: 160 }}
              />
              <div className="form-hint">
                Supported: single IPs, domains, CIDR (10.0.0.0/24), ranges
                (192.168.1.1-100)
              </div>
            </div>

            {totalTargets > 0 && (
              <div className="target-summary">
                {parsed.ips.length > 0 && (
                  <span><strong>{parsed.ips.length}</strong> IPs</span>
                )}
                {parsed.domains.length > 0 && (
                  <span><strong>{parsed.domains.length}</strong> domains</span>
                )}
                {parsed.cidrs.length > 0 && (
                  <span><strong>{parsed.cidrs.length}</strong> CIDRs</span>
                )}
                {parsed.ranges.length > 0 && (
                  <span><strong>{parsed.ranges.length}</strong> ranges</span>
                )}
                {parsed.invalid.length > 0 && (
                  <span className="invalid"><strong>{parsed.invalid.length}</strong> invalid</span>
                )}
                <span className="total">
                  Total: <strong style={{ color: "var(--color-champagne)" }}>{totalTargets}</strong>
                </span>
              </div>
            )}

            <CountryAsnPicker onInject={injectCidrs} />
          </div>

          <div className="card-panel">
            <h2 className="panel-title">Scan Profile</h2>
            <div className="option-grid cols-profile">
              {PROFILES.map((p) => (
                <button
                  key={p.id}
                  onClick={() => handleProfileChange(p.id)}
                  className={`option-card${profile === p.id ? " is-selected" : ""}`}
                >
                  <div>
                    <div className="option-card-title">{p.label}</div>
                    <div className="option-card-desc">{p.description}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>

          <div className="card-panel">
            <h2 className="panel-title">Scan Methods</h2>
            <div className="option-grid cols-method">
              {METHODS.map((m) => {
                const checked = selectedMethods.has(m.id);
                return (
                  <label
                    key={m.id}
                    className={`option-card${checked ? " is-selected" : ""}`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleMethod(m.id)}
                      style={{ marginTop: 3, accentColor: "#f6d9a6" }}
                    />
                    <div>
                      <div className="option-card-title">
                        {m.label}
                        {m.requiresHttp && <span className="option-tag">HTTP</span>}
                      </div>
                      <div className="option-card-desc">{m.description}</div>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          <div className="card-panel">
            <h2 className="panel-title">Port Configuration</h2>
            <div className="option-grid cols-port" style={{ marginBottom: 16 }}>
              {[
                { id: "top1000", label: "Top 1000", desc: "Fast, ~1 min/host" },
                { id: "top10000", label: "Top 10000", desc: "Balanced" },
                { id: "all", label: "All 65535", desc: "Full (needs RustScan)" },
                { id: "custom", label: "Custom", desc: "Specify manually" },
              ].map((m) => {
                const disabled = m.id === "all" && !selectedMethods.has("rustscan");
                return (
                  <button
                    key={m.id}
                    onClick={() => {
                      setPortMode(m.id as any);
                      setProfile("custom");
                    }}
                    disabled={disabled}
                    className={`option-card${portMode === m.id ? " is-selected" : ""}${disabled ? " is-disabled" : ""}`}
                  >
                    <div>
                      <div className="option-card-title">{m.label}</div>
                      <div className="option-card-desc">{m.desc}</div>
                    </div>
                  </button>
                );
              })}
            </div>

            {portMode === "custom" && (
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Custom port range</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="80,443,8080 or 1-1000"
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                />
              </div>
            )}

            {(selectedMethods.has("whatweb") || selectedMethods.has("hxn")) &&
              !selectedMethods.has("rustscan") &&
              !selectedMethods.has("nmap") && (
                <div
                  className="form-group"
                  style={{
                    marginTop: 16,
                    marginBottom: 0,
                    padding: 16,
                    background: "rgba(227, 194, 132,0.05)",
                    border: "1px solid rgba(227, 194, 132,0.2)",
                    borderRadius: 10,
                  }}
                >
                  <label className="form-label" style={{ color: "var(--state-warn)" }}>
                    HTTP Port — required for WhatWeb/HXN without port discovery
                  </label>
                  <input
                    type="number"
                    className="form-input"
                    placeholder="80 or 443 or 8080"
                    value={httpPort}
                    onChange={(e) => setHttpPort(e.target.value)}
                  />
                  <div className="form-hint">
                    Without RustScan/Nmap, these tools need an explicit HTTP port
                  </div>
                </div>
              )}
          </div>

          <div className="card-panel">
            <h2 className="panel-title">Advanced Settings</h2>
            <div className="option-grid cols-settings">
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Threads</label>
                <input
                  type="number"
                  className="form-input"
                  value={threads}
                  onChange={(e) => setThreads(e.target.value)}
                />
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Timeout (ms)</label>
                <input
                  type="number"
                  className="form-input"
                  value={timeout}
                  onChange={(e) => setTimeout_(e.target.value)}
                />
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Priority</label>
                <select
                  className="form-select"
                  value={priority}
                  onChange={(e) => setPriority(e.target.value as any)}
                >
                  <option value="low">Low</option>
                  <option value="normal">Normal</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Proxy (optional)</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="socks5://127.0.0.1:9050"
                  value={proxy}
                  onChange={(e) => setProxy(e.target.value)}
                />
              </div>
            </div>
          </div>

          <div
            className="card-panel"
            style={{ opacity: 0.55, border: "1px dashed var(--color-border-subtle)" }}
          >
            <h2 className="panel-title" style={{ marginBottom: 0, display: "flex", alignItems: "center", gap: 10 }}>
              Fuzzing
              <span
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: "0.08em",
                  padding: "3px 9px",
                  background: "var(--color-obsidian-3)",
                  borderRadius: 60,
                  color: "var(--color-text-muted)",
                  textTransform: "uppercase",
                }}
              >
                Coming soon
              </span>
            </h2>
          </div>
        </div>

        <aside className="scan-aside">
          <div className="card-panel" style={{ marginBottom: 0 }}>
            <h2 className="panel-title">Summary</h2>
            <div className="launch-summary-row">
              <span className="launch-summary-label">Targets</span>
              <span className="launch-summary-value">{totalTargets}</span>
            </div>
            <div className="launch-summary-row">
              <span className="launch-summary-label">Methods</span>
              <span className="launch-summary-value">
                {selectedMethods.size > 0
                  ? Array.from(selectedMethods).join(", ")
                  : "—"}
              </span>
            </div>
            <div className="launch-summary-row">
              <span className="launch-summary-label">Ports</span>
              <span className="launch-summary-value">
                {portMode === "custom" ? customPorts || "custom" : portMode}
              </span>
            </div>
            <div className="launch-summary-row">
              <span className="launch-summary-label">Priority</span>
              <span className="launch-summary-value">{priority}</span>
            </div>

            <button
              className="scan-btn"
              onClick={startScan}
              disabled={
                isScanning ||
                totalTargets === 0 ||
                selectedMethods.size === 0 ||
                validationErrors.length > 0
              }
              style={{ marginTop: 20 }}
            >
              {isScanning
                ? "Launching…"
                : validationErrors.length > 0
                  ? `Fix ${validationErrors.length} error${validationErrors.length > 1 ? "s" : ""}`
                  : totalTargets === 0
                    ? "Add targets to start"
                    : selectedMethods.size === 0
                      ? "Select a method"
                      : `Launch scan · ${totalTargets} target${totalTargets > 1 ? "s" : ""}`}
            </button>
          </div>

          <details className="card-panel" style={{ marginBottom: 0 }}>
            <summary
              style={{
                cursor: "pointer",
                fontSize: 12,
                color: "var(--color-text-muted)",
                fontFamily: "var(--font-mono)",
                letterSpacing: "0.03em",
                listStyle: "none",
              }}
            >
              ▸ Payload preview
            </summary>
            <pre
              style={{
                margin: "14px 0 0",
                fontFamily: "JetBrains Mono",
                fontSize: 11,
                color: "var(--color-text-muted)",
                background: "var(--color-void-black)",
                padding: 14,
                borderRadius: 8,
                overflowX: "auto",
                maxHeight: 320,
                boxShadow: "inset 0 1px 6px rgba(0,0,0,0.5)",
              }}
            >
              {JSON.stringify(buildPayload(), null, 2)}
            </pre>
          </details>
        </aside>
      </div>
    </div>
  );
}
