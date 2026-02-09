"use client";

/**
 * EncryptedSection - Demo component showing Capsule client-side decryption.
 *
 * Uses the @sesamy/capsule client library for all cryptographic operations.
 * This version provides verbose logging for demonstration purposes.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { useConsole } from "./ConsoleContext";
import type {
  CapsuleClient as CapsuleClientType,
  EncryptedArticle,
  UnlockFunction,
  WrappedKey,
  DekStorageMode,
} from "@sesamy/capsule";

interface EncryptedSectionProps {
  articleId: string;
  encryptedData: EncryptedArticle | null;
  securityMode?: DekStorageMode;
  /** Optional: pre-signed token for share link unlock */
  token?: string;
}

type UnlockState = "locked" | "unlocking" | "decrypting" | "unlocked" | "error";

export function EncryptedSection({
  articleId,
  encryptedData,
  securityMode = "persist",
  token: propToken,
}: EncryptedSectionProps) {
  const [state, setState] = useState<UnlockState>("locked");
  const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [usedKeyId, setUsedKeyId] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<Date | null>(null);
  const [tokenId, setTokenId] = useState<string | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const clientRef = useRef<CapsuleClientType | null>(null);
  const { log } = useConsole();

  // Parse keyId to get type and base info
  const parseKeyId = (
    keyId: string
  ): { type: "tier" | "article"; baseId: string; bucketId?: string } => {
    const [first, second] = keyId.split(":", 2);
    if (first === "article") {
      return { type: "article", baseId: second ?? "" };
    }
    // tier:bucketId format
    return { type: "tier", baseId: first ?? "", bucketId: second };
  };

  // Get available key options from wrapped keys
  const getKeyOptions = useCallback(() => {
    if (!encryptedData) return { tierKeys: [], articleKeys: [] };

    const tierKeys: WrappedKey[] = [];
    const articleKeys: WrappedKey[] = [];

    for (const wk of encryptedData.wrappedKeys) {
      const parsed = parseKeyId(wk.keyId);
      if (parsed.type === "article") {
        articleKeys.push(wk);
      } else {
        tierKeys.push(wk);
      }
    }

    return { tierKeys, articleKeys };
  }, [encryptedData]);

  // Execute scripts and dispatch event after content is decrypted
  useEffect(() => {
    if (state === "unlocked" && contentRef.current) {
      const contentElement = contentRef.current;

      // Execute any scripts in the decrypted content
      const scripts = contentElement.querySelectorAll("script");
      scripts.forEach((oldScript) => {
        const newScript = document.createElement("script");
        Array.from(oldScript.attributes).forEach((attr) => {
          newScript.setAttribute(attr.name, attr.value);
        });
        newScript.textContent = oldScript.textContent;
        oldScript.parentNode?.replaceChild(newScript, oldScript);
      });
      if (scripts.length > 0) {
        log(`Executed ${scripts.length} embedded script(s)`, "info");
      }

      // Dispatch custom event for external scripts to react to unlocked content
      const event = new CustomEvent("capsule:unlocked", {
        bubbles: true,
        detail: {
          articleId,
          element: contentElement,
          keyId: usedKeyId,
        },
      });
      contentElement.dispatchEvent(event);
      log(
        `Dispatched 'capsule:unlocked' event for article "${articleId}"`,
        "info"
      );
    }
  }, [state, decryptedContent, log, articleId, usedKeyId]);

  // Initialize the Capsule client
  useEffect(() => {
    let mounted = true;

    async function init() {
      try {
        log(`Loading article "${articleId}"...`, "info");
        log("Initializing @sesamy/capsule client...", "key");

        // Dynamic import for client-side only
        const { CapsuleClient } = await import("@sesamy/capsule");

        // Create unlock function with verbose logging
        const unlock: UnlockFunction = async ({
          keyId,
          wrappedDek,
          publicKey,
          token,
        }) => {
          const parsed = parseKeyId(keyId);
          const isTierKey = parsed.type === "tier";

          // Token-based unlock
          if (token) {
            log(
              `POST /api/unlock { token: "...", wrappedDek: "...", publicKey: "..." } (share link mode)`,
              "network"
            );

            const response = await fetch("/api/unlock", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                token,
                wrappedDek,
                publicKey,
                articleId,
              }),
            });

            if (!response.ok) {
              const data = await response.json();
              log(`Server error: ${data.error}`, "error");
              throw new Error(data.error || `Server returned ${response.status}`);
            }

            const result = await response.json();
            log(
              `Share link unlocked! Token ID: ${result.tokenId || "unknown"}`,
              "success"
            );
            log(
              `Received encrypted DEK (${result.encryptedDek.length} chars)`,
              "success"
            );

            if (mounted) {
              setExpiresAt(new Date(result.expiresAt));
              setTokenId(result.tokenId || null);
            }

            return result;
          }

          // Regular unlock (tier or article key)
          if (isTierKey) {
            log(
              `POST /api/unlock { keyId: "${keyId}", publicKey: "..." } (tier mode - getting KEK)`,
              "network"
            );
          } else {
            log(
              `POST /api/unlock { keyId: "${keyId}", wrappedDek: "...", publicKey: "..." }`,
              "network"
            );
          }

          const response = await fetch("/api/unlock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              keyId,
              wrappedDek,
              publicKey,
              mode: isTierKey ? "tier" : undefined,
            }),
          });

          if (!response.ok) {
            const data = await response.json();
            log(`Server error: ${data.error}`, "error");
            throw new Error(data.error || `Server returned ${response.status}`);
          }

          const result = await response.json();
          log(
            `Received encrypted ${
              result.keyType?.toUpperCase() || "DEK"
            } (${result.encryptedDek.length} chars)`,
            "success"
          );
          log(
            `Key valid until: ${new Date(
              result.expiresAt
            ).toLocaleTimeString()} (bucket ${
              result.bucketId || "static"
            }, ${result.bucketPeriodSeconds}s period)`,
            "info"
          );

          // Store expiry for display
          if (mounted) {
            setExpiresAt(new Date(result.expiresAt));
          }

          return result;
        };

        // Create client with logging
        const client = new CapsuleClient({
          unlock,
          dekStorage: securityMode,
          renewBuffer: 5000,
          executeScripts: true,
          logger: (message, level) => {
            // Map client log levels to console log types
            const typeMap: Record<string, "info" | "success" | "error" | "crypto" | "key"> = {
              info: "info",
              debug: "crypto",
              error: "error",
            };
            log(message, typeMap[level] || "info");
          },
        });

        // Initialize keys
        log("Checking for existing RSA key pair...", "key");
        const hasKeys = await client.hasKeyPair();

        if (hasKeys) {
          log("Found existing RSA key pair in IndexedDB", "success");
          const keyInfo = await client.getKeyInfo();
          if (keyInfo) {
            log(
              `Key size: RSA-${keyInfo.keySize}, created: ${new Date(
                keyInfo.createdAt
              ).toLocaleDateString()}`,
              "info"
            );
          }
        } else {
          log(
            "No existing keys found. Generating new RSA-2048 key pair...",
            "key"
          );
        }

        // Get public key (creates if needed)
        const publicKey = await client.getPublicKey();
        log(`Public key ready (${publicKey.length} chars, Base64 SPKI)`, "success");

        if (!hasKeys) {
          log("RSA key pair generated and stored securely", "success");
          log("Private key is non-extractable (cannot be exported)", "crypto");
        }

        if (mounted) {
          clientRef.current = client;
          setIsInitializing(false);

          if (encryptedData) {
            // Check for token in URL or props
            const urlParams = new URLSearchParams(window.location.search);
            const token = propToken || urlParams.get("token");

            if (token) {
              // Auto-unlock with share token
              log("🔗 Share link token detected! Auto-unlocking...", "info");
              setState("unlocking");

              try {
                const content = await client.unlockWithToken(encryptedData, token);

                const tierKey = encryptedData.wrappedKeys.find(
                  (k) => !k.keyId.startsWith("article:")
                );

                setDecryptedContent(content);
                setUsedKeyId(tierKey?.keyId || "token");
                setState("unlocked");
                log("✨ Article unlocked via share link!", "success");

                // Clean up token from URL (optional, prevents re-use on refresh)
                if (urlParams.has("token")) {
                  const newUrl = new URL(window.location.href);
                  newUrl.searchParams.delete("token");
                  window.history.replaceState({}, "", newUrl.toString());
                  log("Token removed from URL for security", "info");
                }
                return;
              } catch (err) {
                log(
                  `Share link unlock failed: ${
                    err instanceof Error ? err.message : "Unknown error"
                  }`,
                  "error"
                );
                // Fall through to regular unlock flow
              }
            }

            // Try auto-decryption with cached keys
            log("Checking for cached decryption keys...", "info");

            try {
              // Attempt to unlock using cached DEK
              setState("decrypting");
              const content = await client.unlock(encryptedData, "tier");

              // Find which key was used
              const tierKey = encryptedData.wrappedKeys.find(
                (k) => !k.keyId.startsWith("article:")
              );

              setDecryptedContent(content);
              setUsedKeyId(tierKey?.keyId || "unknown");
              setState("unlocked");
              log("✨ Article unlocked using cached key!", "success");
            } catch {
              // No cached key or decryption failed
              const { tierKeys, articleKeys } = getKeyOptions();
              log(`Encrypted content ready (${securityMode} mode)`, "info");
              log(
                `Available keys: ${tierKeys.length} tier, ${articleKeys.length} article`,
                "info"
              );
              log("Click 'Unlock' to request decryption key", "info");
              setState("locked");
            }
          }
        }
      } catch (err) {
        console.error("Failed to initialize Capsule client:", err);
        log(
          `Error: ${
            err instanceof Error ? err.message : "Failed to initialize"
          }`,
          "error"
        );
        if (mounted) {
          setError(err instanceof Error ? err.message : "Failed to initialize");
          setState("error");
          setIsInitializing(false);
        }
      }
    }

    init();
    return () => {
      mounted = false;
    };
  }, [articleId, encryptedData, getKeyOptions, log, securityMode]);

  // Handle unlock button click
  const handleUnlock = async (keyType: "tier" | "article") => {
    if (!clientRef.current || !encryptedData) {
      setError("Not ready");
      return;
    }

    const { tierKeys, articleKeys } = getKeyOptions();
    const keys = keyType === "tier" ? tierKeys : articleKeys;

    if (keys.length === 0) {
      setError(`No ${keyType} keys available`);
      return;
    }

    setError(null);
    setState("unlocking");

    try {
      log(`Trying to unlock with ${keyType} key...`, "info");
      log("Exporting public key as SPKI format...", "key");

      const content = await clientRef.current.unlock(encryptedData, keyType);

      // Find which key was used
      const usedKey =
        keyType === "tier"
          ? encryptedData.wrappedKeys.find(
              (k) => !k.keyId.startsWith("article:")
            )
          : encryptedData.wrappedKeys.find((k) =>
              k.keyId.startsWith("article:")
            );

      log("DEK unwrapped successfully (AES-256-GCM, non-extractable)", "success");
      log("Decrypting content with AES-256-GCM...", "crypto");

      setDecryptedContent(content);
      setUsedKeyId(usedKey?.keyId || "unknown");
      setState("unlocked");
      log(`Content decrypted successfully (${content.length} chars)`, "success");
      log("✨ Article unlocked!", "success");
    } catch (err) {
      console.error("Unlock failed:", err);
      log(
        `Unlock failed: ${
          err instanceof Error ? err.message : "Unknown error"
        }`,
        "error"
      );
      setError(err instanceof Error ? err.message : "Unlock failed");
      setState("error");
    }
  };

  // Get time until expiry display
  const getExpiryDisplay = () => {
    if (!expiresAt) return null;
    const ms = expiresAt.getTime() - Date.now();
    if (ms <= 0) return "expired";
    const seconds = Math.floor(ms / 1000);
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    return `${minutes}m ${seconds % 60}s`;
  };

  // Render states
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

  if (isInitializing) {
    return (
      <div className="locked-section">
        <div className="locked-overlay">
          <div className="lock-icon">🔐</div>
          <p>Initializing secure keys...</p>
          <div className="loading-spinner" />
        </div>
      </div>
    );
  }

  if (state === "unlocked" && decryptedContent && usedKeyId) {
    const parsed = parseKeyId(usedKeyId);
    const keyLabel = tokenId
      ? `share link`
      : parsed.type === "tier"
        ? `tier "${parsed.baseId}"`
        : `article "${parsed.baseId}"`;
    const expiryDisplay = getExpiryDisplay();

    return (
      <div className="unlocked-section">
        <div className="unlock-banner">
          <span>{tokenId ? "🔗" : "🔓"}</span>
          <span>Content decrypted locally (using {keyLabel}{tokenId ? ` • token: ${tokenId.slice(0, 8)}...` : ""} key)</span>
          {expiryDisplay && (
            <span
              className="key-expiry-badge"
              title="DEK auto-renews before expiry"
              suppressHydrationWarning
            >
              ⏱️ {expiryDisplay}
            </span>
          )}
        </div>
        <div
          ref={contentRef}
          className="premium-content"
          dangerouslySetInnerHTML={{
            __html: formatMarkdown(decryptedContent),
          }}
        />
      </div>
    );
  }

  const { tierKeys, articleKeys } = getKeyOptions();

  return (
    <div className="locked-section">
      <template
        id={`encrypted-${articleId}`}
        data-encrypted-article={JSON.stringify(encryptedData)}
      />

      <div className="locked-overlay">
        {state === "error" ? (
          <>
            <div className="lock-icon">⚠️</div>
            <p className="error-message">{error}</p>
            <div className="unlock-buttons">
              {tierKeys.length > 0 && (
                <button onClick={() => handleUnlock("tier")}>
                  Try Tier Key
                </button>
              )}
              {articleKeys.length > 0 && (
                <button
                  onClick={() => handleUnlock("article")}
                  className="secondary"
                >
                  Try Article Key
                </button>
              )}
            </div>
          </>
        ) : state === "unlocking" ? (
          <>
            <div className="lock-icon">��</div>
            <p>Getting decryption key...</p>
            <div className="loading-spinner" />
            <p className="status-detail">
              Sending public key to server for key exchange
            </p>
          </>
        ) : state === "decrypting" ? (
          <>
            <div className="lock-icon">🔓</div>
            <p>Decrypting content...</p>
            <div className="loading-spinner" />
            <p className="status-detail">
              Using @sesamy/capsule for AES-256-GCM decryption
            </p>
          </>
        ) : (
          <>
            <div className="lock-icon">🔒</div>
            <h3>Premium Content</h3>
            <p>Choose how to unlock this encrypted content:</p>
            <div className="unlock-buttons">
              {tierKeys.length > 0 && (
                <button onClick={() => handleUnlock("tier")} className="primary">
                  <span className="button-icon">🎫</span>
                  <span className="button-text">
                    <strong>Premium Tier</strong>
                    <small>
                      Unlocks all premium articles ({tierKeys.length} keys)
                    </small>
                  </span>
                </button>
              )}
              {articleKeys.length > 0 && (
                <button
                  onClick={() => handleUnlock("article")}
                  className="secondary"
                >
                  <span className="button-icon">📄</span>
                  <span className="button-text">
                    <strong>Article Only</strong>
                    <small>Unlocks just this article</small>
                  </span>
                </button>
              )}
            </div>
            <p className="hint">
              <strong>Tier keys</strong> unlock all articles in the subscription
              tier. <strong>Article keys</strong> are specific to this article
              only.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

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
