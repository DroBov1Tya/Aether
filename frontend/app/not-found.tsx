import Link from "next/link";

// 404 in the Solaris Noir key: glass card, honey monogram, radar mark.
export default function NotFound() {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        minHeight: "80vh",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 460,
          padding: 48,
          textAlign: "center",
          background:
            "linear-gradient(180deg, rgba(255,255,255,0.02), transparent 30%), #0c0c0f",
          border: "1px solid rgba(233, 184, 114,0.14)",
          borderRadius: 18,
          boxShadow:
            "inset 0 1px 0 rgba(255,255,255,0.04), 0 30px 70px rgba(0,0,0,0.7)",
        }}
      >
        <svg
          viewBox="0 0 96 96"
          width="88"
          height="88"
          fill="none"
          aria-hidden="true"
          style={{ margin: "0 auto 24px", display: "block", opacity: 0.6 }}
        >
          <defs>
            <linearGradient id="nf-amber" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor="#f5efe4" />
              <stop offset="55%" stopColor="#e9b872" />
              <stop offset="100%" stopColor="#c2884a" />
            </linearGradient>
          </defs>
          <circle cx="48" cy="48" r="40" stroke="url(#nf-amber)" strokeOpacity="0.18" strokeWidth="1" />
          <circle cx="48" cy="48" r="27" stroke="url(#nf-amber)" strokeOpacity="0.28" strokeWidth="1" />
          <circle cx="48" cy="48" r="14" stroke="url(#nf-amber)" strokeOpacity="0.4" strokeWidth="1" />
          <path d="M48 48 L48 10" stroke="url(#nf-amber)" strokeOpacity="0.5" strokeWidth="1.5" strokeLinecap="round" />
          <circle cx="48" cy="48" r="2.4" fill="#e9b872" />
        </svg>

        <div
          style={{
            fontSize: 34,
            fontWeight: 800,
            fontFamily: "JetBrains Mono, monospace",
            background: "linear-gradient(140deg, #f5efe4 0%, #e9b872 60%, #d9bda0 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            letterSpacing: "0.08em",
            marginBottom: 12,
          }}
        >
          404
        </div>
        <div
          style={{
            color: "#89806f",
            fontSize: 12,
            fontFamily: "JetBrains Mono, monospace",
            textTransform: "uppercase",
            letterSpacing: "0.15em",
            marginBottom: 20,
          }}
        >
          Signal Lost
        </div>
        <p
          style={{
            color: "#cabca6",
            fontSize: 14,
            lineHeight: 1.6,
            marginBottom: 32,
          }}
        >
          Запрошенный маршрут вне зоны покрытия — страница не существует либо
          цель ещё не просканирована.
        </p>

        <Link
          href="/"
          style={{
            display: "inline-block",
            padding: "14px 28px",
            background:
              "linear-gradient(140deg, #f6d9a6 0%, #e0a35a 52%, #d4b294 100%)",
            border: "1px solid rgba(246, 217, 166,0.28)",
            borderRadius: 11,
            color: "#1a1510",
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 13,
            fontWeight: 700,
            letterSpacing: "0.1em",
            textTransform: "uppercase",
            textDecoration: "none",
          }}
        >
          ← На главную
        </Link>
      </div>
    </div>
  );
}
