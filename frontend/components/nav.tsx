"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useRef, useEffect } from "react";
import clsx from "clsx";

type Leaf = { href: string; label: string };
type Group = { id: string; label: string; children: Leaf[] };

const FLAT: Leaf[] = [
  { href: "/", label: "Home" },
  { href: "/search", label: "Search" },
];

const GROUPS: Group[] = [
  {
    id: "collect",
    label: "Collect",
    children: [
      { href: "/scans", label: "Scans" },
      { href: "/shodan", label: "Shodan" },
      { href: "/import", label: "Import" },
    ],
  },
  {
    id: "data",
    label: "Data",
    children: [
      { href: "/projects", label: "Projects" },
      { href: "/screenshots", label: "Screenshots" },
      { href: "/stats", label: "Stats" },
    ],
  },
  {
    id: "system",
    label: "System",
    children: [
      { href: "/agents", label: "Agents" },
      { href: "/proxies", label: "Proxies" },
    ],
  },
];

export default function Nav() {
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const navRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!openGroup) return;
    const onDoc = (e: MouseEvent) => {
      if (navRef.current && !navRef.current.contains(e.target as Node)) {
        setOpenGroup(null);
      }
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [openGroup]);

  useEffect(() => {
    setOpenGroup(null);
    setMenuOpen(false);
  }, [pathname]);

  const groupActive = (g: Group) => g.children.some((c) => c.href === pathname);

  return (
    <nav>
      <div className="nav-container" ref={navRef}>
        <Link href="/" className="nav-logo">
          AETHER
        </Link>

        <button
          type="button"
          className="nav-cmdk"
          onClick={() => window.dispatchEvent(new Event("aether:command"))}
          aria-label="Open command palette"
        >
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="7" cy="7" r="4.5" />
            <line x1="10.5" y1="10.5" x2="14" y2="14" />
          </svg>
          <span className="nav-cmdk-label">Search or jump…</span>
          <kbd className="nav-cmdk-kbd">⌘K</kbd>
        </button>

        <div className={clsx("nav-links", menuOpen && "open")}>
          {FLAT.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={clsx("nav-link", pathname === link.href && "active")}
            >
              {link.label}
            </Link>
          ))}

          {GROUPS.map((group) => {
            const isOpen = openGroup === group.id;
            return (
              <div
                key={group.id}
                className="nav-group"
                onMouseEnter={() => setOpenGroup(group.id)}
                onMouseLeave={() =>
                  setOpenGroup((cur) => (cur === group.id ? null : cur))
                }
              >
                <button
                  type="button"
                  className={clsx(
                    "nav-link nav-group-trigger",
                    groupActive(group) && "active",
                    isOpen && "is-open",
                  )}
                  onClick={() =>
                    setOpenGroup((cur) => (cur === group.id ? null : group.id))
                  }
                  aria-expanded={isOpen}
                >
                  {group.label}
                  <svg className="nav-caret" width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M2.5 4 L5 6.5 L7.5 4" />
                  </svg>
                </button>

                <div className={clsx("nav-dropdown", isOpen && "open")}>
                  {group.children.map((child) => (
                    <Link
                      key={child.href}
                      href={child.href}
                      className={clsx(
                        "nav-dropdown-item",
                        pathname === child.href && "active",
                      )}
                    >
                      {child.label}
                    </Link>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        <button
          className="mobile-menu-btn"
          onClick={() => setMenuOpen(!menuOpen)}
          aria-label={menuOpen ? "Close menu" : "Open menu"}
        >
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            {menuOpen ? (
              <>
                <line x1="4" y1="4" x2="16" y2="16" />
                <line x1="16" y1="4" x2="4" y2="16" />
              </>
            ) : (
              <>
                <line x1="3" y1="5" x2="17" y2="5" />
                <line x1="3" y1="10" x2="17" y2="10" />
                <line x1="3" y1="15" x2="17" y2="15" />
              </>
            )}
          </svg>
        </button>
      </div>
    </nav>
  );
}
