"use client";

import { Suspense, useState, useEffect, FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";

function AuthFormInner() {
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const searchParams = useSearchParams();
  const redirectTo = searchParams.get("redirect") || "/";

  useEffect(() => {
    fetch("/api/auth/verify", { method: "HEAD" })
      .then((res) => {
        if (res.ok) router.replace(redirectTo);
      })
      .catch(() => {});
  }, [router, redirectTo]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!code.trim()) return;

    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });

      if (res.ok) {
        router.replace(redirectTo);
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.error || "Invalid access code");
        setCode("");
      }
    } catch {
      setError("Connection failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        width: "100%",
        maxWidth: 420,
        padding: 48,
        background:
          "linear-gradient(180deg, rgba(255,255,255,0.02), transparent 30%), #0c0c0f",
        border: "1px solid rgba(233, 184, 114,0.14)",
        borderRadius: 18,
        boxShadow:
          "inset 0 1px 0 rgba(255,255,255,0.04), 0 30px 70px rgba(0,0,0,0.7)",
      }}
    >
      <div style={{ textAlign: "center", marginBottom: 36 }}>
        <div
          style={{
            fontSize: 36,
            fontWeight: 800,
            fontFamily: "JetBrains Mono, monospace",
            background: "linear-gradient(140deg, #f5efe4 0%, #e9b872 60%, #d9bda0 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            marginBottom: 12,
            letterSpacing: "0.1em",
          }}
        >
          AETHER
        </div>
        <div
          style={{
            color: "#89806f",
            fontSize: 12,
            fontFamily: "JetBrains Mono, monospace",
            textTransform: "uppercase",
            letterSpacing: "0.15em",
          }}
        >
          Restricted Access
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 24 }}>
          <label
            style={{
              display: "block",
              fontSize: 11,
              color: "#89806f",
              textTransform: "uppercase",
              letterSpacing: "0.1em",
              marginBottom: 10,
              fontWeight: 700,
              fontFamily: "JetBrains Mono, monospace",
            }}
          >
            Access Code
          </label>
          <input
            type="password"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="••••••••••••"
            autoComplete="off"
            disabled={loading}
            style={{
              width: "100%",
              padding: "14px 18px",
              background: "#050506",
              border: `1px solid ${error ? "rgba(221, 156, 143,0.5)" : "rgba(233, 184, 114,0.25)"}`,
              borderRadius: 11,
              color: "#f5efe4",
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 14,
              letterSpacing: "0.2em",
              outline: "none",
              boxShadow: "inset 0 1px 4px rgba(0,0,0,0.5)",
              transition: "all 0.2s",
            }}
            autoFocus
          />
        </div>

        {error && (
          <div
            style={{
              padding: "12px 16px",
              background: "rgba(221, 156, 143,0.1)",
              border: "1px solid rgba(221, 156, 143,0.3)",
              borderRadius: 8,
              color: "#dd9c8f",
              fontSize: 12,
              marginBottom: 20,
              fontFamily: "JetBrains Mono, monospace",
            }}
          >
            ⚠ {error}
          </div>
        )}

        <button
          type="submit"
          disabled={loading || !code.trim()}
          style={{
            width: "100%",
            padding: "16px",
            background:
              loading || !code.trim()
                ? "rgba(233, 184, 114,0.16)"
                : "linear-gradient(140deg, #f6d9a6 0%, #e0a35a 52%, #d4b294 100%)",
            border: "1px solid rgba(246, 217, 166,0.28)",
            borderRadius: 11,
            color: loading || !code.trim() ? "#7c746a" : "#1a1510",
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 13,
            fontWeight: 700,
            letterSpacing: "0.1em",
            textTransform: "uppercase",
            cursor: loading || !code.trim() ? "not-allowed" : "pointer",
            transition: "all 0.2s",
          }}
        >
          {loading ? "Authenticating..." : "Access Platform"}
        </button>
      </form>

      <div
        style={{
          marginTop: 28,
          paddingTop: 20,
          borderTop: "1px solid rgba(233, 184, 114,0.1)",
          textAlign: "center",
          fontSize: 10,
          color: "#89806f",
          fontFamily: "JetBrains Mono, monospace",
          letterSpacing: "0.05em",
        }}
      >
        🔒 Secure authentication · All access is logged
      </div>
    </div>
  );
}

export default function AuthPage() {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        minHeight: "80vh",
      }}
    >
      <Suspense
        fallback={
          <div style={{ color: "#89806f", fontFamily: "JetBrains Mono" }}>
            Loading...
          </div>
        }
      >
        <AuthFormInner />
      </Suspense>
    </div>
  );
}
