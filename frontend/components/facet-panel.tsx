import Link from "next/link";

export interface FacetBar {
  label: string;
  count: number;
}

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

/** Compact bar-chart panel used for Top Ports / Top Technologies breakdowns. */
export default function FacetPanel({
  title,
  rows,
  statsHref,
  hrefFor,
}: {
  title: string;
  rows: FacetBar[];
  statsHref?: string;
  hrefFor?: (label: string) => string;
}) {
  const max = rows.reduce((m, r) => Math.max(m, r.count), 0) || 1;
  return (
    <div className="panel">
      <div className="pt">
        {title}
        {statsHref && <Link href={statsHref}>stats →</Link>}
      </div>
      {rows.length === 0 ? (
        <div className="facet-empty">no data yet</div>
      ) : (
        rows.map((r) => {
          const inner = (
            <>
              <span className="lbl" title={r.label}>{r.label}</span>
              <span className="track"><span className="fill" style={{ width: `${(r.count / max) * 100}%` }} /></span>
              <span className="val">{fmt(r.count)}</span>
            </>
          );
          return hrefFor ? (
            <Link key={r.label} href={hrefFor(r.label)} className="cc-row cc-link">
              {inner}
            </Link>
          ) : (
            <div key={r.label} className="cc-row">{inner}</div>
          );
        })
      )}
    </div>
  );
}
