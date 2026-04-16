"use client";

/**
 * EncryptedSection - Demo component showing DCA client-side decryption.
 *
 * Uses the @sesamy/capsule DcaClient for all cryptographic operations.
 * This version provides verbose logging for demonstration purposes.
 */

import { useState, useEffect, useRef } from "react";
import { useConsole } from "./ConsoleContext";
import { KeyManager } from "./KeyManager";

interface EncryptedSectionProps {
  resourceId: string;
  /** The DCA content name (e.g. "bodytext") */
  contentName: string;
  /** Whether the page has DCA-encrypted content embedded */
  hasEncryptedContent: boolean;
  /** Issuer name to unlock with */
  issuerName?: string;
}

type UnlockState = "locked" | "unlocking" | "decrypting" | "unlocked" | "error";
type AccessType = "article" | "tier";

export function EncryptedSection({
  resourceId,
  contentName,
  hasEncryptedContent,
  issuerName = "sesamy-demo",
}: EncryptedSectionProps) {
  const [state, setState] = useState<UnlockState>("locked");
  const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [shareUrl, setShareUrl] = useState<string | null>(null);
  const [isSharing, setIsSharing] = useState(false);
  const contentRef = useRef<HTMLDivElement>(null);
  const clientRef = useRef<InstanceType<typeof import("@sesamy/capsule").DcaClient> | null>(null);
  const pageRef = useRef<import("@sesamy/capsule").DcaParsedPage | null>(null);
  const scopeRef = useRef<string>(contentName);
  const initRanRef = useRef(false);
  const { log } = useConsole();

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

      // Dispatch custom event for external scripts
      const event = new CustomEvent("dca:unlocked", {
        bubbles: true,
        detail: { resourceId, element: contentElement },
      });
      contentElement.dispatchEvent(event);
      log(`Dispatched 'dca:unlocked' event for "${resourceId}"`, "info");
    }
  }, [state, decryptedContent, log, resourceId]);

  // Initialize the DCA client (guarded against React Strict Mode double-mount)
  useEffect(() => {
    // Prevent duplicate initialization from React Strict Mode double-mount
    if (initRanRef.current) return;
    initRanRef.current = true;

    async function init() {
      try {
        log(`Loading article "${resourceId}"...`, "info");
        log("Initializing DCA client (@sesamy/capsule)...", "key");

        const { DcaClient } = await import("@sesamy/capsule");

        const wrapKeyCache = createIdbWrapKeyCache();

        const client = new DcaClient({ clientBound: true, wrapKeyCache });
        clientRef.current = client;

        // Eagerly generate the RSA key pair so it shows immediately in KeyManager
        // (getPublicKey() calls ensureKeyPair() internally)
        await client.getPublicKey();
        log("Client-bound transport enabled (RSA-OAEP key pair)", "crypto");

        // Try to parse the manifest from the page
        try {
          const page = client.parsePage();
          pageRef.current = page;

          // Resolve scope from the current issuer's entries (falls back to contentName)
          const issuerRecord = page.manifest.issuers[issuerName];
          const issuerKeys = issuerRecord?.keys ?? [];
          const resolvedScope = issuerKeys.find(e => (e.contentName ?? "default") === contentName)?.scope ?? contentName;
          scopeRef.current = resolvedScope;

          const contentNames = Object.keys(page.manifest.content);
          const issuerNames = Object.keys(page.manifest.issuers);
          log(`Manifest parsed: ${contentNames.length} content item(s), ${issuerNames.length} issuer(s)`, "info");
          log(`Content items: ${contentNames.join(", ")}`, "info");
          log(`Issuers: ${issuerNames.join(", ")}`, "info");

          // Check for share link token in URL
          const shareToken = DcaClient.getShareTokenFromUrl();
          if (shareToken) {
            log("Share link token detected in URL!", "key");
            log("Auto-unlocking with share token...", "network");

            setIsInitializing(false);
            setState("unlocking");

            const keys = await client.unlockWithShareToken(page, issuerName, shareToken);
            const keyMode = keys.keys.some((k) => k.contentKey)
              ? "contentKey (direct)"
              : "wrapKeys (cacheable)";
            log(`Share link unlock successful! Key mode: ${keyMode}`, "success");

            setState("decrypting");
            log("Decrypting content with AES-256-GCM + AAD...", "crypto");

            const html = await client.decrypt(page, contentName, keys);

            await storeContentKeyRecord(resourceId);
            await storeSubscriptionRecord(resolvedScope);

            setDecryptedContent(html);
            setState("unlocked");
            log(`Content decrypted successfully (${html.length} chars)`, "success");
            log("✨ Article unlocked via share link!", "success");

            try {
              const url = new URL(window.location.href);
              url.searchParams.delete("share");
              window.history.replaceState({}, "", url.toString());
            } catch {
              // Ignore URL cleanup errors
            }
            return;
          }

          // Try auto-unlock from cached wrap keys.
          // WrapKeys are shared across all articles in the same scope (keyed by scope + kid),
          // so any previously cached subscription key can unlock any article in the same scope.
          const hasSubscription = await hasActiveSubscription(resolvedScope);

          if (!hasSubscription) {
            log("No active subscription — skipping cached key auto-unlock", "info");
          }

          if (hasSubscription) try {
            const wrappedContentKey = page.manifest.content[contentName]?.wrappedContentKey ?? [];
            const kids = wrappedContentKey.map((e) => e.kid);
            log(`Checking for cached wrap keys (kids: ${kids.join(", ") || "none"})...`, "crypto");

            if (wrappedContentKey.length === 0) {
              throw new Error(`No wrappedContentKey for ${contentName}`);
            }

            // Verify cache has at least one matching key (keyed by scope)
            let cacheHit = false;
            for (const entry of wrappedContentKey) {
              const cached = await wrapKeyCache.get(`dca:wk:${resolvedScope}:${entry.kid}`);
              if (cached) {
                log(`Cache hit for wrap kid "${entry.kid}" (scope: ${resolvedScope})`, "crypto");
                cacheHit = true;
                break;
              }
            }

            if (!cacheHit) {
              throw new Error("No cached wrap keys found for any kid");
            }

            // Build a synthetic unlock response with empty keys to trigger
            // the cached-wrapKey fallback path inside DcaClient.decrypt()
            const emptyKeys: import("@sesamy/capsule").DcaUnlockResponse = {
              keys: contentNames.map((name) => ({ contentName: name, wrapKeys: [] })),
            };

            const html = await client.decrypt(page, contentName, emptyKeys);

            log("Cached wrap key found — decrypting automatically!", "success");

            await storeSubscriptionRecord(resolvedScope);

            setDecryptedContent(html);
            setState("unlocked");
            setIsInitializing(false);
            log(`Content decrypted successfully (${html.length} chars)`, "success");
            log("✨ Article auto-unlocked from cached subscription key!", "success");
            return;
          } catch (cacheErr) {
            const msg = cacheErr instanceof Error ? cacheErr.message : String(cacheErr);
            log(`Wrap key cache: ${msg}`, "info");
          }

          // Fallback: if we have an active subscription, re-call the issuer
          try {
            if (hasSubscription) {
              log("Active subscription — re-requesting keys from issuer...", "network");

              setIsInitializing(false);
              setState("unlocking");

              const keys = await client.unlock(page, issuerName, { accessType: "tier" });

              setState("decrypting");
              log("Decrypting content with AES-256-GCM + AAD...", "crypto");

              const html = await client.decrypt(page, contentName, keys);
              await storeSubscriptionRecord(resolvedScope);

              setDecryptedContent(html);
              setState("unlocked");
              setIsInitializing(false);
              log(`Content decrypted successfully (${html.length} chars)`, "success");
              log("✨ Article auto-unlocked (re-authenticated)!", "success");
              return;
            }
          } catch (reAuthErr) {
            const msg = reAuthErr instanceof Error ? reAuthErr.message : String(reAuthErr);
            log(`Auto re-auth failed: ${msg}`, "info");
          }

          // Fallback: if we previously unlocked this specific article, re-request a contentKey
          const hasArticle = await hasActiveArticleRecord(resourceId);
          if (hasArticle) {
            try {
              log("Active article record — re-requesting content key from issuer...", "network");

              setIsInitializing(false);
              setState("unlocking");

              const keys = await client.unlock(page, issuerName, { accessType: "article" });

              setState("decrypting");
              log("Decrypting content with AES-256-GCM + AAD...", "crypto");

              const html = await client.decrypt(page, contentName, keys);
              await storeContentKeyRecord(resourceId);

              setDecryptedContent(html);
              setState("unlocked");
              setIsInitializing(false);
              log(`Content decrypted successfully (${html.length} chars)`, "success");
              log("✨ Article auto-unlocked (content key re-requested)!", "success");
              return;
            } catch (articleErr) {
              const msg = articleErr instanceof Error ? articleErr.message : String(articleErr);
              log(`Article re-auth failed: ${msg}`, "info");
            }
          }

          log("Click 'Unlock' to request decryption keys from the issuer", "info");
        } catch {
          log("No DCA manifest found on page", "info");
        }

        setIsInitializing(false);
        setState("locked");
      } catch (err) {
        console.error("Failed to initialize DCA client:", err);
        log(`Error: ${err instanceof Error ? err.message : "Failed to initialize"}`, "error");
        setError(err instanceof Error ? err.message : "Failed to initialize");
        setState("error");
        setIsInitializing(false);
      }
    }

    init();
  }, [resourceId, contentName, issuerName, log]);

  // Handle unlock button click
  const handleUnlock = async (accessType: AccessType) => {
    const client = clientRef.current;
    const page = pageRef.current;
    const scope = scopeRef.current;

    if (!client || !page) {
      setError("Not ready");
      return;
    }

    setError(null);
    setState("unlocking");

    const accessLabels: Record<AccessType, string> = {
      article: "Single Article (direct contentKey — one-time, non-cacheable)",
      tier: `Tier Subscription: ${scope} (wrapKey — cacheable across scope)`,
    };

    try {
      log(`Access type: ${accessLabels[accessType]}`, "info");
      log(`Calling issuer "${issuerName}" unlock endpoint...`, "network");
      log(`POST ${page.manifest.issuers[issuerName]?.unlockUrl ?? "/api/unlock"}`, "network");

      let currentPage = page;
      let keys: import("@sesamy/capsule").DcaUnlockResponse;

      try {
        keys = await client.unlock(currentPage, issuerName, { accessType });
      } catch (unlockErr) {
        // If 403 (e.g. stale JWTs after dev server restart), re-fetch page for fresh manifest
        if (unlockErr instanceof Error && unlockErr.message.includes("403")) {
          log("Stale manifest detected — refreshing page data...", "network");
          const freshPage = await refreshManifest(client);
          if (freshPage) {
            pageRef.current = freshPage;
            currentPage = freshPage;
            log("Manifest refreshed, retrying unlock...", "network");
            keys = await client.unlock(currentPage, issuerName, { accessType });
          } else {
            throw unlockErr;
          }
        } else {
          throw unlockErr;
        }
      }

      const keyMode = keys.keys.some((k) => k.contentKey)
        ? "contentKey (direct)"
        : "wrapKeys (cacheable)";
      log(`Unlock successful! Key mode: ${keyMode}`, "success");

      if (keys.transport === "client-bound") {
        log("Transport: client-bound (RSA-OAEP wrapped)", "crypto");
      } else {
        log("Transport: direct", "info");
      }

      setState("decrypting");
      log("Decrypting content with AES-256-GCM + AAD...", "crypto");

      const html = await client.decrypt(currentPage, contentName, keys);

      if (accessType === "article") {
        await storeContentKeyRecord(resourceId);
      } else {
        await storeSubscriptionRecord(scope);
      }

      setDecryptedContent(html);
      setState("unlocked");
      log(`Content decrypted successfully (${html.length} chars)`, "success");
      log(`✨ Article unlocked via ${accessType}!`, "success");
    } catch (err) {
      console.error("DCA unlock failed:", err);
      log(`Unlock failed: ${err instanceof Error ? err.message : "Unknown error"}`, "error");
      setError(err instanceof Error ? err.message : "Unlock failed");
      setState("error");
    }
  };

  // Handle share link generation
  const handleShare = async () => {
    const scope = scopeRef.current;
    setIsSharing(true);
    try {
      log("Generating share link token...", "network");
      const response = await fetch("/api/share", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          resourceId,
          scopes: [scope],
          expiresIn: 7 * 24 * 3600, // 7 days
        }),
      });

      if (!response.ok) {
        throw new Error(`Failed to create share link: ${response.status}`);
      }

      const data = await response.json();
      setShareUrl(data.shareUrl);
      log(`Share link created (expires in 7 days)`, "success");
      log(`Share URL: ${data.shareUrl}`, "info");

      // Copy to clipboard
      try {
        await navigator.clipboard.writeText(data.shareUrl);
        log("Share link copied to clipboard!", "success");
      } catch {
        log("Share link generated (copy manually from the URL below)", "info");
      }
    } catch (err) {
      log(`Share link error: ${err instanceof Error ? err.message : "Unknown error"}`, "error");
    } finally {
      setIsSharing(false);
    }
  };

  // Render states
  if (!hasEncryptedContent) {
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
          <p>Initializing DCA client...</p>
          <div className="loading-spinner" />
        </div>
      </div>
    );
  }

  if (state === "unlocked" && decryptedContent) {
    return (
      <div className="unlocked-section">
        <div className="unlock-banner">
          <span>🔓</span>
          <span>Content decrypted locally via DCA (issuer: {issuerName})</span>
        </div>
        <div className="unlock-key-manager" style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", alignItems: "center" }}>
          <KeyManager />
          <button
            onClick={handleShare}
            disabled={isSharing}
            style={{
              padding: "0.4rem 0.8rem",
              fontSize: "0.85rem",
              cursor: isSharing ? "wait" : "pointer",
              opacity: isSharing ? 0.6 : 1,
            }}
          >
            {isSharing ? "Creating..." : "🔗 Share Link"}
          </button>
        </div>
        {shareUrl && (
          <div style={{
            margin: "0.5rem 0",
            padding: "0.5rem",
            background: "var(--color-surface, #f0f0f0)",
            borderRadius: "4px",
            fontSize: "0.8rem",
            wordBreak: "break-all",
          }}>
            <strong>Share URL:</strong>{" "}
            <a href={shareUrl} style={{ color: "var(--color-link, #0070f3)" }}>
              {shareUrl}
            </a>
          </div>
        )}
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

  return (
    <div className="locked-section">
      <div className="locked-overlay">
        {state === "error" ? (
          <>
            <div className="lock-icon">⚠️</div>
            <p className="error-message">{error}</p>
            <div className="unlock-buttons">
              <button onClick={() => handleUnlock("article")}>Try Again</button>
            </div>
          </>
        ) : state === "unlocking" || state === "decrypting" ? (
          <>
            <div className="lock-icon">🔑</div>
            <p>{state === "unlocking" ? "Requesting keys from issuer..." : "Decrypting content..."}</p>
            <div className="loading-spinner" />
          </>
        ) : (
          <>
            <div className="lock-icon">🔒</div>
            <h3>Premium Content</h3>
            <p>This content is encrypted with DCA (Delegated Content Access).</p>
            <div className="unlock-buttons">
              <button onClick={() => handleUnlock("article")} className="primary">
                <span className="button-icon">📄</span>
                <span className="button-text">
                  <strong>Unlock Article</strong>
                  <small>Single article — contentKey (one-time)</small>
                </span>
              </button>
              <button onClick={() => handleUnlock("tier")} className="secondary">
                <span className="button-icon">🔑</span>
                <span className="button-text">
                  <strong>Unlock {scopeRef.current}</strong>
                  <small>wrapKey — cacheable across {scopeRef.current} articles</small>
                </span>
              </button>
            </div>
            <p className="hint">
              <strong>Article:</strong> returns a direct contentKey (non-cacheable).<br />
              <strong>{scopeRef.current}:</strong> returns wrapKeys (cacheable per rotation, reusable across {scopeRef.current} articles).
            </p>
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Re-fetch the current page HTML and re-parse the DCA manifest.
// Used when the embedded JWTs are stale (e.g., after server key rotation / HMR).
// ---------------------------------------------------------------------------

async function refreshManifest(
  client: InstanceType<typeof import("@sesamy/capsule").DcaClient>,
): Promise<import("@sesamy/capsule").DcaParsedPage | null> {
  try {
    const resp = await fetch(window.location.href, {
      headers: { Accept: "text/html" },
    });
    if (!resp.ok) return null;
    const html = await resp.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, "text/html");
    return client.parsePage(doc);
  } catch {
    return null;
  }
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

// ---------------------------------------------------------------------------
// Store a content key record in IndexedDB so KeyManager can display it.
// This mirrors the StoredContentKey shape that KeyManager reads.
// ---------------------------------------------------------------------------

const CONTENT_KEY_DB_NAME = "capsule-content-keys";
const CONTENT_KEY_STORE_NAME = "content-keys";
/** Default TTL for a stored content key record (1 hour) */
const CONTENT_KEY_TTL_MS = 60 * 60 * 1000;

async function storeContentKeyRecord(
  resourceId: string,
): Promise<void> {
  try {
    const db = await openContentKeyDb();
    const storeKey = `article:${resourceId}`;
    const record = {
      type: "article" as const,
      baseId: resourceId,
      encryptedContentKey: "(decrypted in memory)",
      expiresAt: Date.now() + CONTENT_KEY_TTL_MS,
    };

    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(CONTENT_KEY_STORE_NAME, "readwrite");
      const store = tx.objectStore(CONTENT_KEY_STORE_NAME);
      store.put(record, storeKey);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  } catch {
    // IndexedDB may not be available; ignore
  }
}

/**
 * Store a tier-scoped subscription record.
 * Each tier (contentName) has its own subscription lifecycle.
 */
async function storeSubscriptionRecord(contentName: string): Promise<void> {
  try {
    const db = await openContentKeyDb();
    const storeKey = `subscription:${contentName}`;
    const record = {
      type: "subscription" as const,
      baseId: contentName,
      encryptedContentKey: "(wrap keys in cache)",
      expiresAt: Date.now() + CONTENT_KEY_TTL_MS,
    };

    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(CONTENT_KEY_STORE_NAME, "readwrite");
      const store = tx.objectStore(CONTENT_KEY_STORE_NAME);
      store.put(record, storeKey);
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  } catch {
    // IndexedDB may not be available; ignore
  }
}

/**
 * Check if there is an active (non-expired) subscription for a specific tier.
 */
async function hasActiveSubscription(contentName: string): Promise<boolean> {
  try {
    const db = await openContentKeyDb();
    return new Promise((resolve) => {
      const tx = db.transaction(CONTENT_KEY_STORE_NAME, "readonly");
      const store = tx.objectStore(CONTENT_KEY_STORE_NAME);
      const req = store.get(`subscription:${contentName}`);

      req.onsuccess = () => {
        const rec = req.result;
        db.close();
        resolve(!!rec && rec.expiresAt > Date.now());
      };
      req.onerror = () => { db.close(); resolve(false); };
    });
  } catch {
    return false;
  }
}

/**
 * Check if there is an active (non-expired) article record for a specific resourceId.
 */
async function hasActiveArticleRecord(resourceId: string): Promise<boolean> {
  try {
    const db = await openContentKeyDb();
    return new Promise((resolve) => {
      const tx = db.transaction(CONTENT_KEY_STORE_NAME, "readonly");
      const store = tx.objectStore(CONTENT_KEY_STORE_NAME);
      const req = store.get(`article:${resourceId}`);

      req.onsuccess = () => {
        const rec = req.result;
        db.close();
        resolve(!!rec && rec.expiresAt > Date.now());
      };
      req.onerror = () => { db.close(); resolve(false); };
    });
  } catch {
    return false;
  }
}

function openContentKeyDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(CONTENT_KEY_DB_NAME, 1);
    request.onerror = () => reject(request.error);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(CONTENT_KEY_STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
  });
}

// ---------------------------------------------------------------------------
// IndexedDB-backed wrap key cache for DcaClient.
//
// WrapKeys are stored as simple key→value pairs so the DcaClient can
// reuse subscription keys across page navigations without a new unlock call.
// ---------------------------------------------------------------------------

const WRAP_KEY_DB_NAME = "capsule-wrap-keys";
const WRAP_KEY_STORE_NAME = "wrap-keys";

function createIdbWrapKeyCache(): import("@sesamy/capsule").DcaWrapKeyCache {
  let dbPromise: Promise<IDBDatabase> | null = null;

  function openDb(): Promise<IDBDatabase> {
    if (!dbPromise) {
      dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open(WRAP_KEY_DB_NAME, 1);
        request.onerror = () => reject(request.error);
        request.onupgradeneeded = () => {
          request.result.createObjectStore(WRAP_KEY_STORE_NAME);
        };
        request.onsuccess = () => resolve(request.result);
      });
    }
    return dbPromise;
  }

  return {
    async get(key: string): Promise<string | null> {
      try {
        const db = await openDb();
        return new Promise((resolve) => {
          const tx = db.transaction(WRAP_KEY_STORE_NAME, "readonly");
          const store = tx.objectStore(WRAP_KEY_STORE_NAME);
          const req = store.get(key);
          req.onsuccess = () => resolve((req.result as string) ?? null);
          req.onerror = () => resolve(null);
        });
      } catch {
        return null;
      }
    },
    async set(key: string, value: string): Promise<void> {
      try {
        const db = await openDb();
        await new Promise<void>((resolve, reject) => {
          const tx = db.transaction(WRAP_KEY_STORE_NAME, "readwrite");
          const store = tx.objectStore(WRAP_KEY_STORE_NAME);
          store.put(value, key);
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        });
      } catch {
        // ignore
      }
    },
  };
}
