"use client";

import { useEffect, useRef, useState, useMemo, useCallback } from "react";
import { useRouter } from "next/navigation";

/**
 * Aether command palette — the keyboard-first control surface.
 * Open with ⌘K / Ctrl-K (or the nav trigger, which dispatches "aether:command").
 * Inspired by Shodan/IVRE power-user workflows: one bar to search, jump to a
 * host, or navigate — no hunting through menus.
 */

type Cmd = {
  id: string;
  label: string;
  hint?: string;
  group: "Navigate" | "Search" | "Action";
  icon: string; // single glyph, drawn as SVG path key
  run: () => void;
};

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPISH_RE = /^\d{1,3}(\.\d{1,3}){0,3}$/;
const PORT_RE = /^\d{1,5}$/;

const PAGES: { label: string; href: string; icon: string; hint: string }[] = [
  { label: "Overview", href: "/", icon: "home", hint: "Recent scans & summary" },
  { label: "Search", href: "/search", icon: "search", hint: "Query the index" },
  { label: "Scan Manager", href: "/scans", icon: "scan", hint: "Launch recon" },
  { label: "Shodan", href: "/shodan", icon: "search", hint: "Import from Shodan" },
  { label: "Screenshots", href: "/screenshots", icon: "image", hint: "Visual recon gallery" },
  { label: "Agents", href: "/agents", icon: "node", hint: "Registered workers" },
  { label: "Statistics", href: "/stats", icon: "chart", hint: "Index breakdown" },
];

function Glyph({ name }: { name: string }) {
  const common = {
    width: 16,
    height: 16,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.4,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };
  switch (name) {
    case "home":
      return (<svg {...common}><path d="M2.5 7 8 2.5 13.5 7" /><path d="M4 6.5V13h8V6.5" /></svg>);
    case "search":
      return (<svg {...common}><circle cx="7" cy="7" r="4.5" /><line x1="10.5" y1="10.5" x2="14" y2="14" /></svg>);
    case "scan":
      return (<svg {...common}><circle cx="8" cy="8" r="6" /><circle cx="8" cy="8" r="2" fill="currentColor" stroke="none" /></svg>);
    case "image":
      return (<svg {...common}><rect x="2" y="3" width="12" height="10" rx="1.5" /><circle cx="5.5" cy="6.5" r="1" /><path d="M3 12l3.5-3.5 3 3 2-2L14 12" /></svg>);
    case "node":
      return (<svg {...common}><rect x="2.5" y="3" width="11" height="7" rx="1.5" /><line x1="6" y1="13" x2="10" y2="13" /><line x1="8" y1="10" x2="8" y2="13" /></svg>);
    case "chart":
      return (<svg {...common}><line x1="2.5" y1="13.5" x2="13.5" y2="13.5" /><rect x="3.5" y="8" width="2.2" height="4" /><rect x="7" y="5" width="2.2" height="7" /><rect x="10.5" y="9.5" width="2.2" height="2.5" /></svg>);
    case "host":
      return (<svg {...common}><rect x="2.5" y="4" width="11" height="8" rx="1.5" /><line x1="2.5" y1="7" x2="13.5" y2="7" /><circle cx="4.6" cy="5.5" r="0.5" fill="currentColor" /></svg>);
    case "port":
      return (<svg {...common}><circle cx="8" cy="8" r="5.5" /><path d="M8 5v3l2 2" /></svg>);
    default:
      return (<svg {...common}><circle cx="8" cy="8" r="6" /></svg>);
  }
}

export default function CommandPalette() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const [recent, setRecent] = useState<string[]>([]);

  const close = useCallback(() => {
    setOpen(false);
    setQ("");
    setActive(0);
  }, []);

  const go = useCallback(
    (href: string) => {
      close();
      router.push(href);
    },
    [router, close],
  );

  // remember searches
  const pushRecent = useCallback((term: string) => {
    if (!term.trim()) return;
    setRecent((r) => {
      const next = [term, ...r.filter((x) => x !== term)].slice(0, 6);
      try {
        localStorage.setItem("aether:recent", JSON.stringify(next));
      } catch {}
      return next;
    });
  }, []);

  useEffect(() => {
    try {
      const raw = localStorage.getItem("aether:recent");
      if (raw) setRecent(JSON.parse(raw));
    } catch {}
  }, []);

  // open / close hotkeys
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      } else if (e.key === "Escape") {
        setOpen(false);
      }
    };
    const onTrigger = () => setOpen(true);
    window.addEventListener("keydown", onKey);
    window.addEventListener("aether:command", onTrigger as EventListener);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("aether:command", onTrigger as EventListener);
    };
  }, []);

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 20);
      document.documentElement.style.overflow = "hidden";
    } else {
      document.documentElement.style.overflow = "";
    }
    return () => {
      document.documentElement.style.overflow = "";
    };
  }, [open]);

  const commands = useMemo<Cmd[]>(() => {
    const term = q.trim();
    const list: Cmd[] = [];

    // Contextual, query-driven actions come first (Shodan-like intent parsing)
    if (term) {
      const runSearch = (type: string, label: string, icon: string) => ({
        id: `s-${type}`,
        label,
        hint: type === "aggregated" ? "grouped by host" : `filter: ${type}`,
        group: "Search" as const,
        icon,
        run: () => {
          pushRecent(term);
          go(`/search?q=${encodeURIComponent(term)}&type=${type}`);
        },
      });

      if (IP_RE.test(term)) {
        list.push({
          id: "host",
          label: `Inspect host ${term}`,
          hint: "open host report",
          group: "Action",
          icon: "host",
          run: () => go(`/host/${encodeURIComponent(term)}`),
        });
        list.push(runSearch("ip", `Search IP contains “${term}”`, "search"));
      } else if (PORT_RE.test(term) && Number(term) <= 65535) {
        list.push(runSearch("port", `Search port ${term}`, "port"));
        list.push(runSearch("aggregated", `Search “${term}” everywhere`, "search"));
      } else if (IPISH_RE.test(term)) {
        list.push(runSearch("ip", `Search IP starts with “${term}”`, "search"));
      } else {
        list.push(runSearch("aggregated", `Search “${term}” everywhere`, "search"));
        list.push(runSearch("technology", `Search technology “${term}”`, "search"));
        list.push(runSearch("title", `Search page title “${term}”`, "search"));
        list.push(runSearch("domain", `Search domain “${term}”`, "search"));
      }
    }

    // Navigation (filtered by query)
    const nav = PAGES.filter(
      (p) => !term || p.label.toLowerCase().includes(term.toLowerCase()),
    ).map<Cmd>((p) => ({
      id: `nav-${p.href}`,
      label: p.label,
      hint: p.hint,
      group: "Navigate",
      icon: p.icon,
      run: () => go(p.href),
    }));
    list.push(...nav);

    return list;
  }, [q, go, pushRecent]);

  useEffect(() => {
    if (active >= commands.length) setActive(Math.max(0, commands.length - 1));
  }, [commands.length, active]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, commands.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      commands[active]?.run();
    }
  };

  if (!open) return null;

  // group headers in render order
  const groupsOrder: Cmd["group"][] = ["Action", "Search", "Navigate"];
  let flatIndex = -1;

  return (
    <div className="cmdk-overlay" onMouseDown={close}>
      <div className="cmdk-panel" onMouseDown={(e) => e.stopPropagation()}>
        <div className="cmdk-input-row">
          <span className="cmdk-input-icon">
            <Glyph name="search" />
          </span>
          <input
            ref={inputRef}
            className="cmdk-input"
            placeholder="Search hosts, ports, tech — or jump to a page…"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setActive(0);
            }}
            onKeyDown={onKeyDown}
            spellCheck={false}
            autoComplete="off"
          />
          <kbd className="cmdk-esc">esc</kbd>
        </div>

        <div className="cmdk-list">
          {commands.length === 0 && (
            <div className="cmdk-empty">No matches</div>
          )}
          {groupsOrder.map((group) => {
            const items = commands.filter((c) => c.group === group);
            if (items.length === 0) return null;
            return (
              <div key={group} className="cmdk-group">
                <div className="cmdk-group-label">{group}</div>
                {items.map((c) => {
                  flatIndex += 1;
                  const idx = flatIndex;
                  return (
                    <button
                      key={c.id}
                      className={`cmdk-item${idx === active ? " is-active" : ""}`}
                      onMouseEnter={() => setActive(idx)}
                      onClick={() => c.run()}
                    >
                      <span className="cmdk-item-icon">
                        <Glyph name={c.icon} />
                      </span>
                      <span className="cmdk-item-label">{c.label}</span>
                      {c.hint && <span className="cmdk-item-hint">{c.hint}</span>}
                    </button>
                  );
                })}
              </div>
            );
          })}

          {!q && recent.length > 0 && (
            <div className="cmdk-group">
              <div className="cmdk-group-label">Recent</div>
              {recent.map((r) => (
                <button
                  key={r}
                  className="cmdk-item cmdk-item-recent"
                  onClick={() => {
                    pushRecent(r);
                    go(`/search?q=${encodeURIComponent(r)}&type=aggregated`);
                  }}
                >
                  <span className="cmdk-item-icon">
                    <Glyph name="search" />
                  </span>
                  <span className="cmdk-item-label">{r}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="cmdk-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> select</span>
          <span><kbd>⌘</kbd><kbd>K</kbd> toggle</span>
        </div>
      </div>
    </div>
  );
}
