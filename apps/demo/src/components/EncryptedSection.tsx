"use client";

import { useState, useEffect, useCallback } from "react";
import { useConsole } from "./ConsoleContext";
import { 
  getStoredDek, 
  getCachedDek, 
  cacheDek,
  storeDek, 
  getTimeUntilExpiry, 
  type StoredDek, 
  type SecurityMode 
} from "@/lib/dek-storage";

interface EncryptedArticleData {
  encryptedContent: string;
  iv: string;
  keyType: "tier" | "article";
  keyId: string;
  /** Bucket ID for time-based keys (undefined for static article keys) */
  bucketId?: string;
}

interface MultiEncryptedArticle {
  /** Tier-based encryption for current bucket */
  tier: EncryptedArticleData;
  /** Tier-based encryption for next bucket (handles clock drift) */
  tierNext: EncryptedArticleData;
  /** Article-specific encryption (static key) */
  article: EncryptedArticleData | null;
}

interface EncryptedSectionProps {
  articleId: string;
  encryptedData: MultiEncryptedArticle | null;
  /**
   * Security mode for DEK storage:
   * - "persist" (default): Store encrypted DEK in IndexedDB, unwrap with RSA key on page load.
   * - "session": Keep DEK in memory only. Requires network request each page load.
   */
  securityMode?: SecurityMode;
}

type UnlockState = "locked" | "unlocking" | "decrypting" | "unlocked" | "error";

// RSA public exponent (65537)
const RSA_PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01]);

export function EncryptedSection({ articleId, encryptedData, securityMode = "persist" }: EncryptedSectionProps) {
  const [state, setState] = useState<UnlockState>("locked");
  const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [usedKey, setUsedKey] = useState<{ type: "tier" | "article"; id: string } | null>(null);
  const [cachedDekInfo, setCachedDekInfo] = useState<{ tier: StoredDek | null; article: StoredDek | null }>({ tier: null, article: null });
  const { log } = useConsole();

  // Decrypt content with a DEK
  const decryptContent = useCallback(async (
    encrypted: EncryptedArticleData,
    dek: CryptoKey,
    keyType: "tier" | "article",
    keyId: string
  ) => {
    try {
      setState("decrypting");
      log("Decoding Base64 IV and ciphertext...", "crypto");
      const iv = base64ToArrayBuffer(encrypted.iv);
      const ciphertext = base64ToArrayBuffer(encrypted.encryptedContent);
      log(`Ciphertext: ${ciphertext.byteLength} bytes, IV: ${iv.byteLength} bytes`, "info");

      log("Decrypting content with AES-256-GCM...", "crypto");
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        dek,
        ciphertext
      );

      const content = new TextDecoder().decode(decrypted);
      log(`Content decrypted successfully (${content.length} chars)`, "success");
      log("✨ Article unlocked!", "success");
      setDecryptedContent(content);
      setUsedKey({ type: keyType, id: keyId });
      setState("unlocked");
      return true;
    } catch (err) {
      console.error("Decryption failed:", err);
      log(`Decryption failed: ${err instanceof Error ? err.message : "Unknown error"}`, "error");
      return false;
    }
  }, [log]);

  // Try to decrypt, falling back to next bucket if current fails
  const tryDecryptWithFallback = useCallback(async (
    current: EncryptedArticleData,
    next: EncryptedArticleData,
    dek: CryptoKey,
    keyType: "tier" | "article",
    keyId: string
  ): Promise<boolean> => {
    // Try current bucket first
    log(`Trying decryption with current bucket (${current.bucketId})...`, "crypto");
    const success = await decryptContent(current, dek, keyType, keyId);
    if (success) {
      log(`Decrypted with current bucket ${current.bucketId}`, "success");
      return true;
    }
    
    // Try next bucket (clock drift)
    log(`Current bucket failed, trying next bucket (${next.bucketId})...`, "crypto");
    const successNext = await decryptContent(next, dek, keyType, keyId);
    if (successNext) {
      log(`Decrypted with next bucket ${next.bucketId} (clock drift handled)`, "success");
      return true;
    }
    
    // Both failed - key may have rotated
    log("Both buckets failed - key may have expired/rotated", "error");
    setError("Decryption failed - key may have expired");
    setState("error");
    return false;
  }, [decryptContent, log]);

  // Check for cached DEKs
  const checkCachedDeks = useCallback(async (data: MultiEncryptedArticle) => {
    const tierDek = await getStoredDek("tier", data.tier.keyId);
    const articleDek = data.article ? await getStoredDek("article", data.article.keyId) : null;
    setCachedDekInfo({ tier: tierDek, article: articleDek });
    return { tierDek, articleDek };
  }, []);

  // Unwrap DEK from encrypted bytes using RSA private key
  const unwrapDek = useCallback(async (
    privateKey: CryptoKey,
    encryptedDekB64: string
  ): Promise<CryptoKey> => {
    const encryptedDekBuffer = base64ToArrayBuffer(encryptedDekB64);
    return await crypto.subtle.unwrapKey(
      "raw",
      encryptedDekBuffer,
      privateKey,
      { name: "RSA-OAEP" },
      { name: "AES-GCM", length: 256 },
      false, // non-extractable
      ["decrypt"]
    );
  }, []);

  // Try to auto-decrypt with cached DEK (unwrap from IndexedDB in persist mode)
  const tryAutoDecrypt = useCallback(async (data: MultiEncryptedArticle, keys: CryptoKeyPair) => {
    // Check for cached tier DEK first (more valuable - unlocks all tier content)
    let cachedDek = getCachedDek("tier", data.tier.keyId);
    let storedDek = await getStoredDek("tier", data.tier.keyId);
    
    if (cachedDek && storedDek) {
      // Have unwrapped DEK in memory - try current bucket first
      log(`Using in-memory DEK for tier "${data.tier.keyId}" (${getTimeUntilExpiry(storedDek)})`, "crypto");
      setState("decrypting");
      
      // Try current bucket first
      const success = await tryDecryptWithFallback(data.tier, data.tierNext, cachedDek, "tier", data.tier.keyId);
      if (success) return true;
    }
    
    if (storedDek) {
      // Have encrypted DEK in IndexedDB - unwrap locally
      log(`Found stored DEK for tier "${data.tier.keyId}" (valid for ${getTimeUntilExpiry(storedDek)})`, "info");
      log("Unwrapping DEK locally with RSA key (no network!)...", "crypto");
      setState("decrypting");
      
      try {
        const dek = await unwrapDek(keys.privateKey, storedDek.encryptedDek);
        cacheDek("tier", data.tier.keyId, dek, storedDek);
        log("DEK unwrapped successfully", "success");
        
        // Try current bucket first, fall back to next bucket
        const success = await tryDecryptWithFallback(data.tier, data.tierNext, dek, "tier", data.tier.keyId);
        if (success) return true;
      } catch (err) {
        log(`Failed to unwrap stored DEK: ${err}`, "error");
      }
    }
    
    // Check for cached article DEK
    if (data.article) {
      cachedDek = getCachedDek("article", data.article.keyId);
      storedDek = await getStoredDek("article", data.article.keyId);
      
      if (cachedDek && storedDek) {
        log(`Using in-memory DEK for article "${data.article.keyId}" (${getTimeUntilExpiry(storedDek)})`, "crypto");
        setState("decrypting");
        await decryptContent(data.article, cachedDek, "article", data.article.keyId);
        return true;
      }
      
      if (storedDek) {
        log(`Found stored DEK for article "${data.article.keyId}" (valid for ${getTimeUntilExpiry(storedDek)})`, "info");
        log("Unwrapping DEK locally with RSA key (no network!)...", "crypto");
        setState("decrypting");
        
        try {
          const dek = await unwrapDek(keys.privateKey, storedDek.encryptedDek);
          cacheDek("article", data.article.keyId, dek, storedDek);
          log("DEK unwrapped successfully", "success");
          await decryptContent(data.article, dek, "article", data.article.keyId);
          return true;
        } catch (err) {
          log(`Failed to unwrap stored DEK: ${err}`, "error");
        }
      }
    }
    
    return false;
  }, [log, decryptContent, unwrapDek, tryDecryptWithFallback]);

  // Fetch and unwrap DEK from server
  const fetchAndUnwrapDek = useCallback(async (
    keys: CryptoKeyPair,
    keyType: "tier" | "article",
    keyId: string
  ): Promise<{ dek: CryptoKey; encryptedDek: string; expiresAt: string; bucketId: string } | null> => {
    try {
      // Export public key as SPKI
      log("Exporting public key as SPKI format...", "key");
      const publicKeySpki = await crypto.subtle.exportKey("spki", keys.publicKey);
      const publicKeyB64 = arrayBufferToBase64(publicKeySpki);
      log(`Public key exported (${publicKeyB64.length} chars, Base64)`, "success");

      // Request wrapped DEK from server
      log(`POST /api/unlock { keyType: "${keyType}", keyId: "${keyId}", publicKey: "..." }`, "network");
      const response = await fetch("/api/unlock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          keyType,
          keyId,
          publicKey: publicKeyB64,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        log(`Server error: ${errorData.error}`, "error");
        return null;
      }

      const { encryptedDek, expiresAt, bucketId } = await response.json();
      log(`Received encrypted DEK (${encryptedDek.length} chars)`, "success");

      // Unwrap the DEK using our private key (non-extractable)
      log("Unwrapping DEK using RSA-OAEP with private key...", "crypto");
      const dek = await unwrapDek(keys.privateKey, encryptedDek);
      log("DEK unwrapped successfully (AES-256-GCM, non-extractable)", "success");
      
      return { dek, encryptedDek, expiresAt, bucketId };
    } catch (err) {
      console.error("Failed to fetch DEK:", err);
      log(`Failed to fetch DEK: ${err instanceof Error ? err.message : "Unknown error"}`, "error");
      return null;
    }
  }, [log, unwrapDek]);

  // Initialize key pair on mount
  useEffect(() => {
    let mounted = true;

    async function initKeys() {
      try {
        log(`Loading article "${articleId}"...`, "info");
        
        // Try to load existing keys from IndexedDB
        log("Checking IndexedDB for existing RSA key pair...", "key");
        let keys = await loadKeysFromStorage();
        
        if (!keys) {
          log("No existing keys found. Generating new RSA-2048 key pair...", "key");
          // Generate new key pair
          keys = await crypto.subtle.generateKey(
            {
              name: "RSA-OAEP",
              modulusLength: 2048,
              publicExponent: RSA_PUBLIC_EXPONENT,
              hash: "SHA-256",
            },
            true, // extractable for public key export
            ["wrapKey", "unwrapKey"]
          );
          
          log("RSA key pair generated successfully", "success");
          log("Storing keys in IndexedDB with extractable: false...", "key");
          // Store the keys
          await saveKeysToStorage(keys);
          log("Keys stored securely in IndexedDB", "success");
        } else {
          log("Found existing RSA key pair in IndexedDB", "success");
        }

        if (mounted) {
          setKeyPair(keys);
          setIsInitializing(false);
          
          // Check if we already have a cached DEK for auto-unlock (persist mode only)
          if (encryptedData) {
            // Update cached DEK info for UI
            await checkCachedDeks(encryptedData);
            
            // Try to auto-decrypt with stored CryptoKey (no network needed!)
            const autoDecrypted = await tryAutoDecrypt(encryptedData, keys);
            if (!autoDecrypted) {
              log(`Encrypted content ready (${securityMode} mode)`, "info");
              if (encryptedData.article) {
                log(`Available keys: tier "${encryptedData.tier.keyId}" or article "${encryptedData.article.keyId}"`, "info");
              } else {
                log(`Available key: tier "${encryptedData.tier.keyId}"`, "info");
              }
              log("Click 'Unlock' to request decryption key", "info");
            }
          }
        }
      } catch (err) {
        console.error("Failed to initialize keys:", err);
        log(`Error: ${err instanceof Error ? err.message : "Failed to initialize"}`, "error");
        if (mounted) {
          setError(err instanceof Error ? err.message : "Failed to initialize");
          setIsInitializing(false);
        }
      }
    }

    initKeys();
    return () => { mounted = false; };
  }, [encryptedData, articleId, log, tryAutoDecrypt, checkCachedDeks, securityMode]);

  // Auto-renew DEK before it expires (when content is unlocked)
  useEffect(() => {
    if (state !== "unlocked" || !keyPair || !usedKey || !encryptedData) {
      return;
    }

    const RENEW_BUFFER_MS = 5000; // Renew 5 seconds before expiry
    let lastKnownExpiresAt: number | null = null;
    
    const checkAndRenew = async () => {
      const stored = await getStoredDek(usedKey.type, usedKey.id);
      
      if (!stored) {
        // DEK is gone - check if it naturally expired vs manually deleted
        if (lastKnownExpiresAt !== null && Date.now() >= lastKnownExpiresAt) {
          // Key expired naturally - renew it
          log(`DEK for ${usedKey.type} "${usedKey.id}" expired, auto-renewing...`, "info");
          await renewDek();
        }
        // If lastKnownExpiresAt is null or in the future, it was manually deleted - don't renew
        return;
      }
      
      // Track the expiry time so we can detect natural expiration
      lastKnownExpiresAt = stored.expiresAt;
      
      const timeUntilExpiry = stored.expiresAt - Date.now();
      
      if (timeUntilExpiry <= RENEW_BUFFER_MS) {
        // About to expire - renew proactively
        log(`DEK expires in ${Math.round(timeUntilExpiry / 1000)}s, auto-renewing...`, "info");
        await renewDek();
      }
    };
    
    const renewDek = async () => {
      const result = await fetchAndUnwrapDek(keyPair, usedKey.type, usedKey.id);
      if (result) {
        await storeDek(usedKey.type, usedKey.id, result.encryptedDek, result.dek, new Date(result.expiresAt), result.bucketId, securityMode);
        log(`DEK renewed successfully (new bucket: ${result.bucketId})`, "success");
        lastKnownExpiresAt = new Date(result.expiresAt).getTime();
        
        // Update cached DEK info for UI
        if (encryptedData) {
          await checkCachedDeks(encryptedData);
        }
      } else {
        log("Failed to renew DEK - content may become inaccessible", "error");
      }
    };
    
    // Check immediately and then every second
    checkAndRenew();
    const interval = setInterval(checkAndRenew, 1000);
    
    return () => clearInterval(interval);
  }, [state, keyPair, usedKey, encryptedData, fetchAndUnwrapDek, checkCachedDeks, log, securityMode]);

  const handleUnlock = async (keyType: "tier" | "article") => {
    if (!keyPair || !encryptedData) {
      setError("Not ready");
      return;
    }

    const encrypted = keyType === "tier" ? encryptedData.tier : encryptedData.article;
    if (!encrypted) {
      setError("No article-specific key available");
      return;
    }

    setError(null);
    setState("unlocking");
    log(`Starting unlock with ${keyType} key "${encrypted.keyId}"...`, "info");

    try {
      // Check if we already have the DEK cached in memory
      let dek = getCachedDek(keyType, encrypted.keyId);

      if (!dek) {
        // Export public key as SPKI
        log("Exporting public key as SPKI format...", "key");
        const publicKeySpki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        const publicKeyB64 = arrayBufferToBase64(publicKeySpki);
        log(`Public key exported (${publicKeyB64.length} chars, Base64)`, "success");

        // Request wrapped DEK from server
        log(`POST /api/unlock { keyType: "${keyType}", keyId: "${encrypted.keyId}", publicKey: "..." }`, "network");
        
        let response: Response;
        try {
          response = await fetch("/api/unlock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              keyType,
              keyId: encrypted.keyId,
              publicKey: publicKeyB64,
            }),
          });
        } catch (fetchErr) {
          log(`Network error: ${fetchErr}`, "error");
          throw new Error(`Network error: ${fetchErr}`);
        }

        log(`Response status: ${response.status}`, "info");

        if (!response.ok) {
          const errorData = await response.json();
          log(`Server error: ${errorData.error}`, "error");
          throw new Error(errorData.error || "Failed to get decryption key");
        }

        const data = await response.json();
        const { encryptedDek, expiresAt, bucketId, bucketPeriodSeconds } = data;
        log(`Received encrypted DEK (${encryptedDek?.length || 0} chars)`, "success");
        log(`DEK valid until: ${new Date(expiresAt).toLocaleTimeString()} (bucket ${bucketId}, ${bucketPeriodSeconds}s period)`, "info");

        // Unwrap the DEK using our private key (non-extractable for security)
        log("Unwrapping DEK using RSA-OAEP with private key...", "crypto");
        dek = await unwrapDek(keyPair.privateKey, encryptedDek);
        log("DEK unwrapped successfully (AES-256-GCM, non-extractable)", "success");

        // Store DEK based on security mode
        log(`Storing DEK in ${securityMode} mode...`, "info");
        try {
          await storeDek(keyType, encrypted.keyId, encryptedDek, dek, new Date(expiresAt), bucketId, securityMode);
          log("DEK stored successfully", "success");
        } catch (storeErr) {
          log(`Failed to store DEK: ${storeErr}`, "error");
          // Continue anyway - we have it in memory
        }
        
        if (securityMode === "persist") {
          if (keyType === "tier") {
            log(`DEK persisted for tier "${encrypted.keyId}" (survives page refresh!)`, "crypto");
          } else {
            log(`DEK persisted for article "${encrypted.keyId}"`, "crypto");
          }
        } else {
          log(`DEK cached in memory only (session mode - more secure)`, "crypto");
        }
        
        // Update cached DEK info for UI
        if (encryptedData) {
          await checkCachedDeks(encryptedData);
        }
      } else {
        log(`Using cached DEK for ${keyType} "${encrypted.keyId}"`, "crypto");
      }

      // Decrypt the content - for tier keys, try both current and next bucket
      if (keyType === "tier") {
        const success = await tryDecryptWithFallback(
          encryptedData.tier, 
          encryptedData.tierNext, 
          dek, 
          keyType, 
          encrypted.keyId
        );
        if (!success) {
          throw new Error("Failed to decrypt with tier key");
        }
      } else {
        // Article keys are static, no fallback needed
        const success = await decryptContent(encrypted, dek, keyType, encrypted.keyId);
        if (!success) {
          setError("Decryption failed");
          setState("error");
        }
      }

    } catch (err) {
      console.error("Unlock failed:", err);
      log(`Unlock failed: ${err instanceof Error ? err.message : "Unknown error"}`, "error");
      setError(err instanceof Error ? err.message : "Unlock failed");
      setState("error");
    }
  };

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

  if (state === "unlocked" && decryptedContent && usedKey) {
    const keyLabel = usedKey.type === "tier" 
      ? `tier "${usedKey.id}"` 
      : `article "${usedKey.id}"`;
    const dekInfo = usedKey.type === "tier" ? cachedDekInfo.tier : cachedDekInfo.article;
    const expiryDisplay = dekInfo ? getTimeUntilExpiry(dekInfo) : null;
    
    return (
      <div className="unlocked-section">
        <div className="unlock-banner">
          <span>🔓</span>
          <span>Content decrypted locally (using {keyLabel} key)</span>
          {expiryDisplay && (
            <span className="key-expiry-badge" title="DEK auto-renews before expiry" suppressHydrationWarning>
              ⏱️ {expiryDisplay}
            </span>
          )}
        </div>
        <div
          className="premium-content"
          dangerouslySetInnerHTML={{
            __html: formatMarkdown(decryptedContent),
          }}
        />
      </div>
    );
  }

  const hasTierKey = !!cachedDekInfo.tier;
  const hasArticleKey = !!cachedDekInfo.article;

  return (
    <div className="locked-section">
      {/* Encrypted content embedded in template tag for offline access */}
      <template
        id={`encrypted-${articleId}`}
        data-encrypted-tier={JSON.stringify(encryptedData.tier)}
        data-encrypted-article={encryptedData.article ? JSON.stringify(encryptedData.article) : ""}
      />
      
      <div className="locked-overlay">
        {state === "error" ? (
          <>
            <div className="lock-icon">⚠️</div>
            <p className="error-message">{error}</p>
            <div className="unlock-buttons">
              <button onClick={() => handleUnlock("tier")}>
                Try Tier Key
              </button>
              {encryptedData.article && (
                <button onClick={() => handleUnlock("article")} className="secondary">
                  Try Article Key
                </button>
              )}
            </div>
          </>
        ) : state === "unlocking" ? (
          <>
            <div className="lock-icon">🔐</div>
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
              Using cached DEK (works offline!)
            </p>
          </>
        ) : (
          <>
            <div className="lock-icon">🔒</div>
            <h3>Premium Content</h3>
            <p>Choose how to unlock this encrypted content:</p>
            <div className="unlock-buttons">
              <button onClick={() => handleUnlock("tier")} className="primary">
                <span className="button-icon">🎫</span>
                <span className="button-text">
                  <strong>Premium Tier</strong>
                  <small>{hasTierKey ? "Key cached ✓" : "Unlocks all premium articles"}</small>
                </span>
              </button>
              {encryptedData.article && (
                <button onClick={() => handleUnlock("article")} className="secondary">
                  <span className="button-icon">📄</span>
                  <span className="button-text">
                    <strong>Article Only</strong>
                    <small>{hasArticleKey ? "Key cached ✓" : "Unlocks just this article"}</small>
                  </span>
                </button>
              )}
            </div>
            <p className="hint">
              <strong>Tier keys</strong> unlock all articles in the subscription tier.{" "}
              <strong>Article keys</strong> are specific to this article only.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

// IndexedDB helpers for key storage
const DB_NAME = "capsule-demo-keys";
const STORE_NAME = "keypair";

async function loadKeysFromStorage(): Promise<CryptoKeyPair | null> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    
    request.onerror = () => reject(request.error);
    
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const getRequest = store.get("default");
      
      getRequest.onsuccess = () => {
        resolve(getRequest.result || null);
      };
      getRequest.onerror = () => reject(getRequest.error);
    };
  });
}

async function saveKeysToStorage(keyPair: CryptoKeyPair): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    
    request.onerror = () => reject(request.error);
    
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      store.put(keyPair, "default");
      
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    };
  });
}

// Base64 helpers
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
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
