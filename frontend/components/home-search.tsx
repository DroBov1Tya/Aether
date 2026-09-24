"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const PORT_RE = /^\d{1,5}$/;

const EXAMPLES: { label: string; q: string; type: string }[] = [
  { label: "product:nginx", q: "nginx", type: "technology" },
  { label: "port:443", q: "443", type: "port" },
  { label: "45.33.32.156", q: "45.33.32.156", type: "ip" },
  { label: "ssl:example.com", q: "example.com", type: "ssl" },
];

/** Home console query bar. Routes to the search page (or a host, for a bare IP). */
export default function HomeSearch() {
  const router = useRouter();
  const [q, setQ] = useState("");

  const submit = (value = q) => {
    const term = value.trim();
    if (!term) {
      router.push("/search?type=aggregated");
      return;
    }
    if (IP_RE.test(term)) {
      router.push(`/host/${encodeURIComponent(term)}`);
      return;
    }
    const type = PORT_RE.test(term) && Number(term) <= 65535 ? "port" : "aggregated";
    router.push(`/search?q=${encodeURIComponent(term)}&type=${type}`);
  };

  return (
    <div className="console-search">
      <div className="query-bar">
        <span className="query-facet-tag">SEARCH</span>
        <input
          className="query-input"
          placeholder="IP, port, product:nginx, ssl:example.com …"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
          spellCheck={false}
          autoComplete="off"
        />
        <button className="query-run" onClick={() => submit()}>
          Search
        </button>
      </div>
      <div className="query-examples">
        <span className="query-examples-label">Try</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex.label}
            className="query-example-chip"
            onClick={() => router.push(`/search?q=${encodeURIComponent(ex.q)}&type=${ex.type}`)}
          >
            {ex.label}
          </button>
        ))}
      </div>
    </div>
  );
}
