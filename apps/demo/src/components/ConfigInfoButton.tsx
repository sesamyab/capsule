"use client";

import { useState, useEffect } from "react";

interface Config {
  keyExchange: {
    method: string;
    bucketPeriodSeconds: number;
    description: string;
  };
  currentBucket: {
    id: string;
    expiresAt: string;
    expiresIn: string;
  };
  nextBucket: {
    id: string;
    expiresAt: string;
  };
  environment: {
    hasCustomSecret: boolean;
  };
}

export function ConfigInfoButton() {
  const [isOpen, setIsOpen] = useState(false);
  const [config, setConfig] = useState<Config | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchConfig = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/config");
      const data = await res.json();
      setConfig(data);
    } catch (e) {
      console.error("Failed to fetch config:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && !config) {
      fetchConfig();
    }
    
    // Auto-refresh while open
    if (isOpen) {
      const interval = setInterval(fetchConfig, 5000);
      return () => clearInterval(interval);
    }
  }, [isOpen]);

  return (
    <>
      {/* Floating info button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        style={{
          position: "fixed",
          bottom: "1.5rem",
          right: "1.5rem",
          width: "48px",
          height: "48px",
          borderRadius: "50%",
          border: "none",
          background: isOpen ? "var(--accent)" : "var(--code-bg)",
          color: isOpen ? "white" : "var(--text)",
          fontSize: "1.25rem",
          cursor: "pointer",
          boxShadow: "0 4px 12px rgba(0, 0, 0, 0.15)",
          transition: "all 0.2s",
          zIndex: 1000,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
        title="Server Configuration"
      >
        ⚙️
      </button>

      {/* Info panel */}
      {isOpen && (
        <div
          style={{
            position: "fixed",
            bottom: "5rem",
            right: "1.5rem",
            width: "340px",
            maxHeight: "70vh",
            overflowY: "auto",
            background: "var(--code-bg, #1e1e1e)",
            border: "1px solid var(--border)",
            borderRadius: "12px",
            boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
            zIndex: 999,
            padding: "1rem",
            backdropFilter: "blur(8px)",
          }}
        >
          <div style={{ 
            display: "flex", 
            justifyContent: "space-between", 
            alignItems: "center",
            marginBottom: "1rem"
          }}>
            <h4 style={{ margin: 0 }}>🔧 Server Config</h4>
            <button
              onClick={() => setIsOpen(false)}
              style={{
                background: "none",
                border: "none",
                fontSize: "1.25rem",
                cursor: "pointer",
                opacity: 0.6,
              }}
            >
              ×
            </button>
          </div>

          {loading && !config ? (
            <p style={{ color: "var(--muted)" }}>Loading...</p>
          ) : config ? (
            <div style={{ fontSize: "0.85rem" }}>
              {/* Method badge */}
              <div style={{ marginBottom: "1rem" }}>
                <span
                  style={{
                    display: "inline-block",
                    padding: "4px 12px",
                    borderRadius: "20px",
                    fontWeight: 600,
                    fontSize: "0.75rem",
                    textTransform: "uppercase",
                    background: config.keyExchange.method === "totp" ? "#22c55e22" : "#3b82f622",
                    color: config.keyExchange.method === "totp" ? "#16a34a" : "#2563eb",
                    border: `1px solid ${config.keyExchange.method === "totp" ? "#22c55e" : "#3b82f6"}`,
                  }}
                >
                  {config.keyExchange.method === "totp" ? "🔄 TOTP Mode" : "📡 API Mode"}
                </span>
              </div>

              {/* Config details */}
              <table style={{ width: "100%", fontSize: "0.8rem" }}>
                <tbody>
                  <tr>
                    <td style={{ padding: "4px 0", color: "var(--muted)" }}>Bucket Period:</td>
                    <td style={{ padding: "4px 0", textAlign: "right" }}>
                      <strong>{config.keyExchange.bucketPeriodSeconds}s</strong>
                    </td>
                  </tr>
                  <tr>
                    <td style={{ padding: "4px 0", color: "var(--muted)" }}>TOTP Counter:</td>
                    <td style={{ padding: "4px 0", textAlign: "right" }}>
                      <code style={{ fontSize: "0.75rem" }} title="floor(Unix time / period) - used as HKDF input">{config.currentBucket.id}</code>
                    </td>
                  </tr>
                  <tr>
                    <td style={{ padding: "4px 0", color: "var(--muted)" }}>Expires In:</td>
                    <td style={{ padding: "4px 0", textAlign: "right" }}>
                      <strong style={{ color: "var(--accent)" }}>{config.currentBucket.expiresIn}</strong>
                    </td>
                  </tr>
                  <tr>
                    <td style={{ padding: "4px 0", color: "var(--muted)" }}>Next Counter:</td>
                    <td style={{ padding: "4px 0", textAlign: "right" }}>
                      <code style={{ fontSize: "0.75rem" }}>{config.nextBucket.id}</code>
                    </td>
                  </tr>
                  <tr>
                    <td style={{ padding: "4px 0", color: "var(--muted)" }}>Secret:</td>
                    <td style={{ padding: "4px 0", textAlign: "right" }}>
                      {config.environment.hasCustomSecret ? (
                        <span style={{ color: "#16a34a" }}>✅ Custom</span>
                      ) : (
                        <span style={{ color: "#f59e0b" }}>⚠️ Demo</span>
                      )}
                    </td>
                  </tr>
                </tbody>
              </table>

              {/* Key derivation explanation */}
              <div
                style={{
                  marginTop: "0.75rem",
                  padding: "0.5rem",
                  background: "rgba(59, 130, 246, 0.1)",
                  borderRadius: "6px",
                  fontSize: "0.65rem",
                  fontFamily: "monospace",
                  color: "var(--muted)",
                }}
              >
                Key = HKDF(secret, "{config.currentBucket.id}:tier:premium")
              </div>

              {/* Description */}
              <div
                style={{
                  marginTop: "1rem",
                  padding: "0.75rem",
                  background: "var(--code-bg)",
                  borderRadius: "8px",
                  fontSize: "0.75rem",
                  lineHeight: 1.5,
                  color: "var(--muted)",
                }}
              >
                {config.keyExchange.method === "totp" ? (
                  <>
                    <strong>TOTP Mode:</strong> CMS derives bucket keys locally using shared 
                    secret. No API calls to subscription server for key exchange.
                  </>
                ) : (
                  <>
                    <strong>API Mode:</strong> CMS fetches bucket keys from subscription server. 
                    Server controls rotation period dynamically.
                  </>
                )}
              </div>

              {/* Refresh indicator */}
              <div style={{ 
                marginTop: "0.75rem", 
                fontSize: "0.7rem", 
                color: "var(--muted)",
                textAlign: "center"
              }}>
                {loading ? "Refreshing..." : "Auto-refreshes every 5s"}
              </div>
            </div>
          ) : (
            <p style={{ color: "#ef4444" }}>Failed to load config</p>
          )}
        </div>
      )}
    </>
  );
}
