"use client";

import { useState } from "react";
import {
  getCountryAsns,
  getAsnPrefixes,
  type CountryAsn,
} from "@/lib/api";

const COUNTRIES = [
  ["ru", "Россия"],
  ["ua", "Украина"],
  ["by", "Беларусь"],
  ["kz", "Казахстан"],
  ["us", "США"],
  ["de", "Германия"],
  ["nl", "Нидерланды"],
  ["fr", "Франция"],
  ["gb", "Великобритания"],
  ["cn", "Китай"],
  ["ir", "Иран"],
  ["tr", "Турция"],
];

export default function CountryAsnPicker({
  onInject,
}: {
  onInject: (cidrs: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [country, setCountry] = useState("ru");
  const [filter, setFilter] = useState("");
  const [page, setPage] = useState(0);
  const [asns, setAsns] = useState<CountryAsn[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [fetching, setFetching] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const SIZE = 30;
  const totalPages = Math.max(1, Math.ceil(total / SIZE));

  async function load(p = 0) {
    setLoading(true);
    setErr(null);
    try {
      const res = await getCountryAsns(country, filter.trim(), p, SIZE);
      setAsns(res.asns);
      setTotal(res.total);
      setPage(res.page);
    } catch (e: any) {
      setErr(e.message || "Ошибка загрузки ASN");
      setAsns([]);
    } finally {
      setLoading(false);
    }
  }

  function toggle(asn: number) {
    const next = new Set(selected);
    if (next.has(asn)) next.delete(asn);
    else next.add(asn);
    setSelected(next);
  }

  async function inject() {
    if (selected.size === 0) return;
    setFetching(true);
    setNote(null);
    setErr(null);
    try {
      const res = await getAsnPrefixes(Array.from(selected));
      if (res.cidrs.length === 0) {
        setNote("У выбранных ASN нет анонсированных IPv4-префиксов");
      } else {
        onInject(res.cidrs);
        setNote(`Добавлено ${res.cidrs.length} CIDR из ${selected.size} ASN`);
      }
    } catch (e: any) {
      setErr(e.message || "Ошибка получения префиксов");
    } finally {
      setFetching(false);
    }
  }

  return (
    <div style={{ marginTop: 16, borderTop: "1px solid var(--color-border-subtle)", paddingTop: 16 }}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        style={{
          background: "none",
          border: "none",
          cursor: "pointer",
          color: "var(--color-text-soft)",
          fontFamily: "var(--font-mono)",
          fontSize: 13,
          padding: 0,
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}
      >
        <span>{open ? "▾" : "▸"}</span>
        Добавить сети по стране (ASN → CIDR)
      </button>

      {open && (
        <div style={{ marginTop: 14 }}>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
            <div className="form-group" style={{ marginBottom: 0, minWidth: 160 }}>
              <label className="form-label">Страна</label>
              <select
                className="form-select"
                value={country}
                onChange={(e) => {
                  setCountry(e.target.value);
                  setAsns([]);
                  setSelected(new Set());
                }}
              >
                {COUNTRIES.map(([code, name]) => (
                  <option key={code} value={code}>{name} ({code.toUpperCase()})</option>
                ))}
              </select>
            </div>
            <div className="form-group" style={{ marginBottom: 0, flex: 1, minWidth: 140 }}>
              <label className="form-label">Фильтр по номеру ASN</label>
              <input
                className="form-input"
                placeholder="напр. 8359"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") load(0); }}
              />
            </div>
            <button
              type="button"
              className="scan-btn"
              style={{ width: "auto", marginTop: 0, padding: "0 22px", height: 42 }}
              onClick={() => load(0)}
              disabled={loading}
            >
              {loading ? "…" : "Найти ASN"}
            </button>
          </div>

          {err && <div className="query-error" style={{ marginTop: 12 }}>ERROR: {err}</div>}

          {asns.length > 0 && (
            <>
              <div style={{ fontSize: 11, color: "var(--color-text-muted)", fontFamily: "var(--font-mono)", margin: "14px 0 8px", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                Всего ASN: {total.toLocaleString()} · выбрано: {selected.size}
              </div>
              <div style={{ maxHeight: 280, overflowY: "auto", border: "1px solid var(--color-border-subtle)", borderRadius: 8 }}>
                {asns.map((a) => {
                  const checked = selected.has(a.asn);
                  return (
                    <label
                      key={a.asn}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "8px 12px",
                        borderBottom: "1px solid var(--color-border-subtle)",
                        cursor: "pointer",
                        background: checked ? "rgba(241,207,180,0.06)" : "transparent",
                        fontSize: 13,
                        fontFamily: "JetBrains Mono",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggle(a.asn)}
                        style={{ accentColor: "#e0c3a6" }}
                      />
                      <span style={{ color: "var(--color-champagne)", minWidth: 76 }}>AS{a.asn}</span>
                      <span style={{ color: "var(--color-text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {a.holder || "—"}
                      </span>
                    </label>
                  );
                })}
              </div>

              <div style={{ display: "flex", gap: 10, marginTop: 12, alignItems: "center", flexWrap: "wrap" }}>
                <button type="button" className="copy-btn" disabled={page <= 0 || loading} onClick={() => load(page - 1)}>← {page}</button>
                <span style={{ fontSize: 12, color: "var(--color-text-muted)", fontFamily: "var(--font-mono)" }}>стр. {page + 1} / {totalPages}</span>
                <button type="button" className="copy-btn" disabled={page + 1 >= totalPages || loading} onClick={() => load(page + 1)}>→</button>
                <button
                  type="button"
                  className="scan-btn"
                  style={{ width: "auto", marginTop: 0, marginLeft: "auto", padding: "0 22px", height: 40 }}
                  onClick={inject}
                  disabled={fetching || selected.size === 0}
                >
                  {fetching ? "Загрузка CIDR…" : `Добавить сети (${selected.size})`}
                </button>
              </div>
            </>
          )}

          {note && (
            <div style={{ marginTop: 12, fontSize: 13, color: "var(--state-ok)", fontFamily: "var(--font-mono)" }}>
              {note}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
