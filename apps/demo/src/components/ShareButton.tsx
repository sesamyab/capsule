"use client";

import { useState } from "react";

interface ShareButtonProps {
  /** Content ID to share (required) */
  contentId: string;
  /** Tier for the share token */
  tier?: string;
}

interface ShareResult {
  token: string;
  tokenId: string;
  issuer: string;
  keyId: string;
  contentId: string;
  expiresAt: string;
  shareUrl: string;
}

/**
 * ShareButton component for generating shareable unlock links.
 *
 * Publishers can use this to create pre-signed links that allow
 * readers to unlock content without authentication.
 */
export function ShareButton({ contentId, tier = "premium" }: ShareButtonProps) {
  const [isGenerating, setIsGenerating] = useState(false);
  const [shareResult, setShareResult] = useState<ShareResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [expiresIn, setExpiresIn] = useState("24h");
  const [maxUses, setMaxUses] = useState<string>("");

  const generateShareLink = async () => {
    setIsGenerating(true);
    setError(null);
    setShareResult(null);

    try {
      const response = await fetch("/api/share", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tier,
          contentId,
          expiresIn,
          maxUses: maxUses ? parseInt(maxUses, 10) : undefined,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Failed to generate share link");
      }

      const result = await response.json();
      setShareResult(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to generate share link",
      );
    } finally {
      setIsGenerating(false);
    }
  };

  const copyToClipboard = async () => {
    if (!shareResult) return;

    try {
      await navigator.clipboard.writeText(shareResult.shareUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const textArea = document.createElement("textarea");
      textArea.value = shareResult.shareUrl;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="share-button-container" style={{ marginTop: "1rem" }}>
      {!shareResult ? (
        <div>
          <div
            style={{
              display: "flex",
              gap: "0.5rem",
              marginBottom: "0.75rem",
              flexWrap: "wrap",
              alignItems: "center",
            }}
          >
            <label style={{ fontSize: "0.85rem", color: "var(--muted)" }}>
              Expires in:
              <select
                value={expiresIn}
                onChange={(e) => setExpiresIn(e.target.value)}
                style={{
                  marginLeft: "0.5rem",
                  padding: "0.25rem 0.5rem",
                  borderRadius: "4px",
                  border: "1px solid var(--border)",
                  background: "var(--background)",
                  color: "var(--foreground)",
                }}
              >
                <option value="1h">1 hour</option>
                <option value="24h">24 hours</option>
                <option value="7d">7 days</option>
                <option value="30d">30 days</option>
              </select>
            </label>

            <label style={{ fontSize: "0.85rem", color: "var(--muted)" }}>
              Max uses:
              <input
                type="number"
                value={maxUses}
                onChange={(e) => setMaxUses(e.target.value)}
                placeholder="unlimited"
                min="1"
                style={{
                  marginLeft: "0.5rem",
                  padding: "0.25rem 0.5rem",
                  borderRadius: "4px",
                  border: "1px solid var(--border)",
                  background: "var(--background)",
                  color: "var(--foreground)",
                  width: "100px",
                }}
              />
            </label>
          </div>

          <button
            onClick={generateShareLink}
            disabled={isGenerating}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              padding: "0.5rem 1rem",
              background: "linear-gradient(135deg, #3b82f6, #8b5cf6)",
              color: "white",
              border: "none",
              borderRadius: "6px",
              cursor: isGenerating ? "wait" : "pointer",
              fontSize: "0.9rem",
              fontWeight: "500",
              opacity: isGenerating ? 0.7 : 1,
            }}
          >
            {isGenerating ? (
              <>
                <span className="spinner" /> Generating...
              </>
            ) : (
              <>🔗 Generate Share Link</>
            )}
          </button>
        </div>
      ) : (
        <div
          style={{
            background: "rgba(59, 130, 246, 0.1)",
            border: "1px solid rgba(59, 130, 246, 0.3)",
            borderRadius: "8px",
            padding: "1rem",
          }}
        >
          <div style={{ marginBottom: "0.75rem" }}>
            <strong style={{ color: "var(--accent)" }}>
              ✅ Share Link Generated!
            </strong>
          </div>

          <div
            style={{
              display: "flex",
              gap: "0.5rem",
              alignItems: "center",
              marginBottom: "0.75rem",
            }}
          >
            <input
              type="text"
              value={shareResult.shareUrl}
              readOnly
              style={{
                flex: 1,
                padding: "0.5rem",
                borderRadius: "4px",
                border: "1px solid var(--border)",
                background: "var(--background)",
                color: "var(--foreground)",
                fontSize: "0.8rem",
              }}
            />
            <button
              onClick={copyToClipboard}
              style={{
                padding: "0.5rem 1rem",
                background: copied ? "#10b981" : "var(--accent)",
                color: "white",
                border: "none",
                borderRadius: "4px",
                cursor: "pointer",
                fontSize: "0.85rem",
                minWidth: "80px",
              }}
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>

          <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
            <div>
              <strong>Token ID:</strong> {shareResult.tokenId}
            </div>
            <div>
              <strong>Expires:</strong>{" "}
              {new Date(shareResult.expiresAt).toLocaleString()}
            </div>
            {maxUses && (
              <div>
                <strong>Max uses:</strong> {maxUses}
              </div>
            )}
          </div>

          <button
            onClick={() => {
              setShareResult(null);
              setCopied(false);
            }}
            style={{
              marginTop: "0.75rem",
              padding: "0.25rem 0.75rem",
              background: "transparent",
              color: "var(--muted)",
              border: "1px solid var(--border)",
              borderRadius: "4px",
              cursor: "pointer",
              fontSize: "0.8rem",
            }}
          >
            Generate Another
          </button>
        </div>
      )}

      {error && (
        <div
          style={{
            marginTop: "0.75rem",
            padding: "0.75rem",
            background: "rgba(239, 68, 68, 0.1)",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            borderRadius: "6px",
            color: "#ef4444",
            fontSize: "0.85rem",
          }}
        >
          ❌ {error}
        </div>
      )}

      <style jsx>{`
        .spinner {
          display: inline-block;
          width: 14px;
          height: 14px;
          border: 2px solid rgba(255, 255, 255, 0.3);
          border-radius: 50%;
          border-top-color: white;
          animation: spin 0.8s linear infinite;
        }
        @keyframes spin {
          to {
            transform: rotate(360deg);
          }
        }
      `}</style>
    </div>
  );
}
