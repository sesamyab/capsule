"use client";

import { useState, useEffect } from "react";
import { CodeBlock } from "@/components/CodeBlock";

interface Config {
  keyExchange: {
    method: string;
    periodDurationSeconds: number;
    description: string;
  };
  currentPeriod: {
    id: string;
    expiresAt: string;
    expiresIn: string;
  };
  nextPeriod: {
    id: string;
    expiresAt: string;
  };
  environment: {
    hasCustomSecret: boolean;
  };
}

export default function CmsTestPage() {
  const [apiKey, setApiKey] = useState("demo-cms-api-key-change-in-production");
  const [contentId, setContentId] = useState("premium");
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [config, setConfig] = useState<Config | null>(null);

  // Fetch config on mount and refresh periodically
  useEffect(() => {
    const fetchConfig = async () => {
      try {
        const res = await fetch("/api/config");
        const data = await res.json();
        setConfig(data);
      } catch (e) {
        console.error("Failed to fetch config:", e);
      }
    };

    fetchConfig();
    const interval = setInterval(fetchConfig, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const testApiKey = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch("/api/cms/period-keys", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ contentId }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(`Error ${response.status}: ${data.error || "Unknown error"}`);
      } else {
        setResult(data);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  const listRegisteredCms = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch("/api/cms/register");
      const data = await response.json();

      if (!response.ok) {
        setError(`Error ${response.status}: ${data.error || "Unknown error"}`);
      } else {
        setResult(data);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="content-page">
      <h1>CMS API Testing</h1>
      <p>
        Test the CMS-to-Subscription Server API endpoints. The demo server implements both
        roles for testing purposes.
      </p>

      {config && (
        <div style={{
          background: "var(--code-bg)",
          padding: "1rem",
          borderRadius: "8px",
          marginBottom: "1.5rem"
        }}>
          <h3 style={{ marginTop: 0 }}>Current Configuration</h3>
          <table style={{ width: "100%" }}>
            <tbody>
              <tr>
                <td><strong>Key Exchange Method:</strong></td>
                <td>
                  <code style={{
                    background: config.keyExchange.method === "period" ? "#22c55e33" : "#3b82f633",
                    padding: "2px 8px",
                    borderRadius: "4px"
                  }}>
                    {config.keyExchange.method.toUpperCase()}
                  </code>
                </td>
              </tr>
              <tr>
                <td><strong>Period Duration:</strong></td>
                <td>{config.keyExchange.periodDurationSeconds} seconds</td>
              </tr>
              <tr>
                <td><strong>Current Period:</strong></td>
                <td>
                  <code>{config.currentPeriod.id}</code>
                  {" "}(expires in {config.currentPeriod.expiresIn})
                </td>
              </tr>
              <tr>
                <td><strong>Shared Secret:</strong></td>
                <td>{config.environment.hasCustomSecret ? "✅ Custom (from env)" : "⚠️ Auto-generated (demo only)"}</td>
              </tr>
            </tbody>
          </table>
          <p style={{ fontSize: "0.85rem", marginBottom: 0, opacity: 0.8 }}>
            {config.keyExchange.description}
          </p>
        </div>
      )}

      <h2>Key Exchange Methods</h2>
      <p>Configure via environment variables:</p>
      <CodeBlock language="bash">{`# period mode (default) - 30 second periods
CAPSULE_KEY_METHOD=period
CAPSULE_BUCKET_PERIOD=30
PERIOD_SECRET=<base64-shared-secret>

# API mode - server controls rotation
CAPSULE_KEY_METHOD=api
CAPSULE_BUCKET_PERIOD=900  # 15 minutes`}</CodeBlock>

      <h2>Test API Key Authentication</h2>

      <div style={{ marginBottom: "1rem" }}>
        <label style={{ display: "block", marginBottom: "0.5rem" }}>
          <strong>API Key:</strong>
        </label>
        <input
          type="text"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          style={{
            width: "100%",
            padding: "0.5rem",
            border: "1px solid #ccc",
            borderRadius: "4px",
            fontFamily: "monospace",
          }}
        />
      </div>

      <div style={{ marginBottom: "1rem" }}>
        <label style={{ display: "block", marginBottom: "0.5rem" }}>
          <strong>Content ID:</strong>
        </label>
        <input
          type="text"
          value={contentId}
          onChange={(e) => setContentId(e.target.value)}
          style={{
            width: "100%",
            padding: "0.5rem",
            border: "1px solid #ccc",
            borderRadius: "4px",
          }}
        />
      </div>

      <button
        onClick={testApiKey}
        disabled={loading}
        style={{
          padding: "0.75rem 1.5rem",
          backgroundColor: "#0070f3",
          color: "white",
          border: "none",
          borderRadius: "4px",
          cursor: loading ? "not-allowed" : "pointer",
          opacity: loading ? 0.6 : 1,
        }}
      >
        {loading ? "Testing..." : "Request Period Keys"}
      </button>

      <button
        onClick={listRegisteredCms}
        disabled={loading}
        style={{
          padding: "0.75rem 1.5rem",
          backgroundColor: "#666",
          color: "white",
          border: "none",
          borderRadius: "4px",
          cursor: loading ? "not-allowed" : "pointer",
          opacity: loading ? 0.6 : 1,
          marginLeft: "1rem",
        }}
      >
        {loading ? "Loading..." : "List Registered CMS"}
      </button>

      {error && (
        <div
          style={{
            marginTop: "1rem",
            padding: "1rem",
            backgroundColor: "#fee",
            border: "1px solid #fcc",
            borderRadius: "4px",
            color: "#c00",
          }}
        >
          <strong>Error:</strong> {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: "1rem" }}>
          <h3>Response:</h3>
          <CodeBlock language="json">{JSON.stringify(result, null, 2)}</CodeBlock>
        </div>
      )}

      <h2>API Documentation</h2>

      <h3>POST /api/cms/period-keys</h3>
      <p>Request time-period keys for encrypting content.</p>
      <CodeBlock>{`curl -X POST http://localhost:3000/api/cms/period-keys \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"contentId":"premium"}'`}</CodeBlock>

      <h4>Response Format</h4>
      <CodeBlock language="json">{`{
  "contentId": "premium",
  "method": "period",
  "periodDurationSeconds": 30,
  "current": {
    "periodId": "123456",
    "key": "base64-encoded-256-bit-aes-key",
    "expiresAt": "2026-01-16T15:00:00.000Z"
  },
  "next": {
    "periodId": "123457",
    "key": "base64-encoded-256-bit-aes-key",
    "expiresAt": "2026-01-16T15:00:30.000Z"
  },
  "authenticatedWith": "api-key",
  "cmsId": "api-key-cms"
}`}</CodeBlock>

      <h3>POST /api/cms/register</h3>
      <p>Register a CMS public key for JWT authentication.</p>
      <CodeBlock>{`curl -X POST http://localhost:3000/api/cms/register \\
  -H "Content-Type: application/json" \\
  -d '{
    "cmsId": "production-cms",
    "publicKey": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----"
  }'`}</CodeBlock>

      <h3>GET /api/cms/register</h3>
      <p>List all registered CMS instances.</p>
      <CodeBlock>{`curl http://localhost:3000/api/cms/register`}</CodeBlock>

      <h2>Time-Period Keys</h2>
      <p>
        Keys rotate every <strong>{config ? config.keyExchange.periodDurationSeconds : 30} seconds</strong> (configurable via <code>CAPSULE_BUCKET_PERIOD</code>). The server always returns both:
      </p>
      <ul>
        <li><strong>Current period:</strong> Valid now</li>
        <li><strong>Next period:</strong> Valid in the next period window</li>
      </ul>

      <p>
        CMS should wrap content keys with <strong>both</strong> period keys. This ensures
        content remains decryptable during period transitions.
      </p>

      <h2>Security Notes</h2>
      <ul>
        <li>🔒 API key should be stored in environment variables, never in code</li>
        <li>🔒 In production, use HTTPS for all requests</li>
        <li>🔒 Period keys should be cached for the duration of the period ({config ? config.keyExchange.periodDurationSeconds : 30}s)</li>
        <li>🔒 Period secret never leaves the Subscription Server</li>
        <li>🔒 CMS can only decrypt content it encrypted (has period keys for one period)</li>
      </ul>
    </main>
  );
}
