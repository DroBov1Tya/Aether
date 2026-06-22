"use client";

import { useState } from "react";

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
    <div className="page-container">
      <h1 className="page-title">SCAN MANAGER</h1>
      <p style={{ color: "#818b98", marginBottom: 32 }}>
        Configure and launch network reconnaissance scans
      </p>

      {validationErrors.length > 0 && (
        <div
          className="card-panel"
          style={{
            marginBottom: 24,
            background: "rgba(239,68,68,0.05)",
            border: "1px solid rgba(239,68,68,0.3)",
          }}
        >
          <div
            style={{
              fontSize: 12,
              fontFamily: "JetBrains Mono",
              color: "#ef4444",
              marginBottom: 8,
              fontWeight: 600,
            }}
          >
            ⚠ VALIDATION ERRORS
          </div>
          <ul
            style={{
              margin: 0,
              paddingLeft: 20,
              color: "#fca5a5",
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
              ? "rgba(95,237,131,0.05)"
              : "rgba(239,68,68,0.05)",
            border: `1px solid ${launchResult.startsWith("✅") ? "rgba(95,237,131,0.3)" : "rgba(239,68,68,0.3)"}`,
          }}
        >
          <pre
            style={{
              margin: 0,
              fontFamily: "JetBrains Mono",
              fontSize: 12,
              color: launchResult.startsWith("✅") ? "#5fed83" : "#ef4444",
              whiteSpace: "pre-wrap",
            }}
          >
            {launchResult}
          </pre>
        </div>
      )}

      <div style={{ display: "grid", gap: 24 }}>
        <div className="card-panel">
          <h2 className="panel-title">Targets</h2>
          <div className="form-group">
            <label className="form-label">
              IP addresses, domains, CIDR ranges, or IP ranges (one per line or
              comma-separated)
            </label>
            <textarea
              className="form-textarea"
              placeholder={`192.168.1.1\n10.0.0.0/24\n172.16.0.1-172.16.0.100\nexample.com\n8.8.8.8, 1.1.1.1`}
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              style={{ height: 180 }}
            />
            <div className="form-hint">
              Supported: single IPs, domains, CIDR (e.g. 10.0.0.0/24), ranges
              (e.g. 192.168.1.1-100)
            </div>
          </div>

          {totalTargets > 0 && (
            <div
              style={{
                display: "flex",
                gap: 16,
                flexWrap: "wrap",
                marginTop: 16,
                padding: 16,
                background: "rgba(95,237,131,0.05)",
                border: "1px solid rgba(95,237,131,0.2)",
                borderRadius: 8,
              }}
            >
              {parsed.ips.length > 0 && (
                <span style={{ fontSize: 13, color: "#5fed83" }}>
                  <strong>{parsed.ips.length}</strong> IPs
                </span>
              )}
              {parsed.domains.length > 0 && (
                <span style={{ fontSize: 13, color: "#5fed83" }}>
                  <strong>{parsed.domains.length}</strong> domains
                </span>
              )}
              {parsed.cidrs.length > 0 && (
                <span style={{ fontSize: 13, color: "#5fed83" }}>
                  <strong>{parsed.cidrs.length}</strong> CIDRs
                </span>
              )}
              {parsed.ranges.length > 0 && (
                <span style={{ fontSize: 13, color: "#5fed83" }}>
                  <strong>{parsed.ranges.length}</strong> ranges
                </span>
              )}
              {parsed.invalid.length > 0 && (
                <span style={{ fontSize: 13, color: "#ef4444" }}>
                  <strong>{parsed.invalid.length}</strong> invalid
                </span>
              )}
              <span
                style={{ fontSize: 13, color: "#8c93fb", marginLeft: "auto" }}
              >
                Total: <strong>{totalTargets}</strong> targets
              </span>
            </div>
          )}
        </div>

        <div className="card-panel">
          <h2 className="panel-title">Scan Profile</h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: 12,
            }}
          >
            {PROFILES.map((p) => (
              <button
                key={p.id}
                onClick={() => handleProfileChange(p.id)}
                style={{
                  padding: 16,
                  textAlign: "left",
                  cursor: "pointer",
                  background:
                    profile === p.id
                      ? "rgba(140,147,251,0.15)"
                      : "rgba(0,0,0,0.3)",
                  border: `1px solid ${profile === p.id ? "rgba(140,147,251,0.5)" : "#21262d"}`,
                  borderRadius: 8,
                  transition: "all 0.2s",
                }}
              >
                <div
                  style={{
                    fontSize: 14,
                    fontWeight: 600,
                    color: "#f0f6fc",
                    marginBottom: 4,
                  }}
                >
                  {p.label}
                </div>
                <div style={{ fontSize: 12, color: "#818b98" }}>
                  {p.description}
                </div>
              </button>
            ))}
          </div>
        </div>

        <div className="card-panel">
          <h2 className="panel-title">Scan Methods</h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
              gap: 12,
            }}
          >
            {METHODS.map((m) => {
              const checked = selectedMethods.has(m.id);
              return (
                <label
                  key={m.id}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 12,
                    padding: 16,
                    cursor: "pointer",
                    background: checked
                      ? "rgba(95,237,131,0.05)"
                      : "rgba(0,0,0,0.3)",
                    border: `1px solid ${checked ? "rgba(95,237,131,0.3)" : "#21262d"}`,
                    borderRadius: 8,
                    transition: "all 0.2s",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleMethod(m.id)}
                    style={{ marginTop: 2, accentColor: "#5fed83" }}
                  />
                  <div style={{ flex: 1 }}>
                    <div
                      style={{
                        fontSize: 14,
                        fontWeight: 600,
                        color: "#f0f6fc",
                        marginBottom: 4,
                      }}
                    >
                      {m.label}
                      {m.requiresHttp && (
                        <span
                          style={{
                            fontSize: 10,
                            marginLeft: 6,
                            padding: "2px 6px",
                            background: "#283041",
                            borderRadius: 4,
                            color: "#f0c000",
                          }}
                        >
                          HTTP
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 12, color: "#818b98" }}>
                      {m.description}
                    </div>
                  </div>
                </label>
              );
            })}
          </div>
        </div>

        <div className="card-panel">
          <h2 className="panel-title">Port Configuration</h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: 12,
              marginBottom: 16,
            }}
          >
            {[
              {
                id: "top1000",
                label: "Top 1000",
                desc: "Fast, ~1 min per host",
              },
              { id: "top10000", label: "Top 10000", desc: "Balanced" },
              {
                id: "all",
                label: "All 65535",
                desc: "Full scan (requires RustScan)",
              },
              { id: "custom", label: "Custom", desc: "Specify manually" },
            ].map((m) => (
              <button
                key={m.id}
                onClick={() => {
                  setPortMode(m.id as any);
                  setProfile("custom");
                }}
                disabled={m.id === "all" && !selectedMethods.has("rustscan")}
                style={{
                  padding: 12,
                  textAlign: "left",
                  cursor:
                    m.id === "all" && !selectedMethods.has("rustscan")
                      ? "not-allowed"
                      : "pointer",
                  background:
                    portMode === m.id
                      ? "rgba(140,147,251,0.15)"
                      : "rgba(0,0,0,0.3)",
                  border: `1px solid ${portMode === m.id ? "rgba(140,147,251,0.5)" : "#21262d"}`,
                  borderRadius: 8,
                  opacity:
                    m.id === "all" && !selectedMethods.has("rustscan")
                      ? 0.4
                      : 1,
                }}
              >
                <div
                  style={{ fontSize: 13, fontWeight: 600, color: "#f0f6fc" }}
                >
                  {m.label}
                </div>
                <div style={{ fontSize: 11, color: "#818b98" }}>{m.desc}</div>
              </button>
            ))}
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
                  background: "rgba(240,192,0,0.05)",
                  border: "1px solid rgba(240,192,0,0.2)",
                  borderRadius: 8,
                }}
              >
                <label className="form-label" style={{ color: "#f0c000" }}>
                  ⚠ HTTP Port (required for WhatWeb/HXN without port discovery)
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
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: 16,
            }}
          >
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
          style={{ opacity: 0.5, border: "1px dashed #21262d" }}
        >
          <h2 className="panel-title">
            Fuzzing{" "}
            <span
              style={{
                fontSize: 11,
                padding: "2px 8px",
                background: "#283041",
                borderRadius: 60,
                marginLeft: 8,
                color: "#818b98",
              }}
            >
              COMING SOON
            </span>
          </h2>
          <p style={{ fontSize: 13, color: "#818b98" }}>
            URL/parameter fuzzing, directory brute-force, and vulnerability
            scanning will be available in a future release.
          </p>
        </div>

        <div
          className="card-panel"
          style={{
            background: "rgba(140,147,251,0.03)",
            border: "1px dashed rgba(140,147,251,0.3)",
          }}
        >
          <h2 className="panel-title">📋 Payload Preview (sent to backend)</h2>
          <pre
            style={{
              margin: 0,
              fontFamily: "JetBrains Mono",
              fontSize: 11,
              color: "#a4aea6",
              background: "rgba(0,0,0,0.4)",
              padding: 16,
              borderRadius: 6,
              overflowX: "auto",
              maxHeight: 400,
            }}
          >
            {JSON.stringify(buildPayload(), null, 2)}
          </pre>
        </div>

        <div className="card-panel">
          <button
            className="scan-btn"
            onClick={startScan}
            disabled={
              isScanning ||
              totalTargets === 0 ||
              selectedMethods.size === 0 ||
              validationErrors.length > 0
            }
            style={{ fontSize: 16, padding: 18 }}
          >
            {isScanning
              ? "⏳ LAUNCHING..."
              : validationErrors.length > 0
                ? `⚠ FIX ${validationErrors.length} ERROR(S)`
                : totalTargets === 0
                  ? "ADD TARGETS TO START"
                  : selectedMethods.size === 0
                    ? "SELECT AT LEAST ONE METHOD"
                    : `▶ LAUNCH SCAN (${totalTargets} targets, ${selectedMethods.size} methods)`}
          </button>
        </div>
      </div>
    </div>
  );
}
