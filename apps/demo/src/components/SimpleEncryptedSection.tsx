"use client";

/**
 * SimpleEncryptedSection - Demonstrates the high-level @sesamy/capsule API
 *
 * This is a simplified example showing how easy it is to use the Capsule client.
 * For the full-featured demo with DEK caching visualization, see EncryptedSection.tsx
 */

import { useState, useEffect, useRef } from "react";
import type {
  CapsuleClient as CapsuleClientType,
  EncryptedArticle,
  UnlockFunction,
} from "@sesamy/capsule";

interface SimpleEncryptedSectionProps {
  articleId: string;
  encryptedData: EncryptedArticle | null;
}

type State = "loading" | "locked" | "unlocking" | "unlocked" | "error";

// Simple markdown-to-HTML converter
function formatMarkdown(content: string): string {
  return content
    .replace(/^### (.*$)/gim, "<h3>$1</h3>")
    .replace(/^## (.*$)/gim, "<h2>$1</h2>")
    .replace(/^# (.*$)/gim, "<h1>$1</h1>")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.*?)\*/g, "<em>$1</em>")
    .replace(/`(.*?)`/g, "<code>$1</code>")
    .replace(/^- (.*$)/gim, "<li>$1</li>")
    .replace(/^\d+\. (.*$)/gim, "<li>$1</li>")
    .replace(/^---$/gim, "<hr />")
    .replace(/\n\n/g, "</p><p>");
}

export function SimpleEncryptedSection({
  articleId: _articleId,
  encryptedData,
}: SimpleEncryptedSectionProps) {
  const [state, setState] = useState<State>("loading");
  const [content, setContent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [keyId, setKeyId] = useState<string | null>(null);
  const clientRef = useRef<CapsuleClientType | null>(null);

  // Initialize the Capsule client
  useEffect(() => {
    let mounted = true;

    async function init() {
      try {
        // Dynamic import for client-side only
        const { CapsuleClient } = await import("@sesamy/capsule");

        // Define the unlock function - this is how we fetch DEKs from the server
        const unlock: UnlockFunction = async ({
          keyId,
          wrappedDek,
          publicKey,
          articleId: _articleId,
        }) => {
          const response = await fetch("/api/unlock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ keyId, wrappedDek, publicKey }),
          });

          if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || `Server returned ${response.status}`);
          }

          return response.json();
        };

        // Create the client with minimal config
        const client = new CapsuleClient({
          unlock,
          executeScripts: true,
          dekStorage: "persist",
          renewBuffer: 5000,
        });

        if (mounted) {
          clientRef.current = client;
          setState("locked");
        }
      } catch (err) {
        console.error("Failed to initialize Capsule client:", err);
        if (mounted) {
          setError(err instanceof Error ? err.message : "Failed to initialize");
          setState("error");
        }
      }
    }

    init();
    return () => {
      mounted = false;
    };
  }, []);

  // Handle unlock
  const handleUnlock = async () => {
    if (!clientRef.current || !encryptedData) return;

    setState("unlocking");
    setError(null);

    try {
      // This single call handles everything:
      // 1. Gets public key (creates if needed)
      // 2. Calls unlock function to fetch DEK
      // 3. Caches the DEK
      // 4. Decrypts the content
      const decrypted = await clientRef.current.unlock(encryptedData, "tier");

      // Get which key was used (first tier key in this case)
      const usedKey = encryptedData.wrappedKeys.find(
        (k) => !k.keyId.startsWith("article:")
      );

      setContent(decrypted);
      setKeyId(usedKey?.keyId || "unknown");
      setState("unlocked");
    } catch (err) {
      console.error("Unlock failed:", err);
      setError(err instanceof Error ? err.message : "Unlock failed");
      setState("error");
    }
  };

  // Render based on state
  if (!encryptedData) {
    return (
      <div className="locked-section">
        <div className="locked-overlay error">
          <div className="lock-icon">⚠️</div>
          <p>No encrypted content available</p>
        </div>
      </div>
    );
  }

  if (state === "loading") {
    return (
      <div className="locked-section">
        <div className="locked-overlay">
          <div className="lock-icon">🔐</div>
          <p>Initializing Capsule client...</p>
          <div className="loading-spinner" />
        </div>
      </div>
    );
  }

  if (state === "unlocked" && content) {
    return (
      <div className="unlocked-section">
        <div className="unlock-banner">
          <span>🔓</span>
          <span>Content decrypted using high-level API (key: {keyId})</span>
        </div>
        <div
          className="premium-content"
          dangerouslySetInnerHTML={{ __html: formatMarkdown(content) }}
        />
      </div>
    );
  }

  return (
    <div className="locked-section">
      <div className="locked-overlay">
        {state === "error" ? (
          <>
            <div className="lock-icon">⚠️</div>
            <p className="error-message">{error}</p>
            <button onClick={handleUnlock}>Retry</button>
          </>
        ) : state === "unlocking" ? (
          <>
            <div className="lock-icon">🔐</div>
            <p>Unlocking content...</p>
            <div className="loading-spinner" />
            <p className="status-detail">
              Using @sesamy/capsule high-level API
            </p>
          </>
        ) : (
          <>
            <div className="lock-icon">🔒</div>
            <h3>Premium Content</h3>
            <p>Click to unlock using the @sesamy/capsule client.</p>
            <button onClick={handleUnlock} className="primary">
              <span className="button-icon">🔓</span>
              <span className="button-text">
                <strong>Unlock Content</strong>
                <small>One-click unlock with high-level API</small>
              </span>
            </button>
            <p
              className="hint"
              style={{ marginTop: "1rem", fontSize: "0.85rem", opacity: 0.7 }}
            >
              This uses <code>capsule.unlock()</code> which handles key
              generation, DEK fetching, caching, and decryption automatically.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
