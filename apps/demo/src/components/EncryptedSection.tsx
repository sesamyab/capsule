"use client";

import { useState, useEffect, useCallback } from "react";
import { useConsole } from "./ConsoleContext";
import { dekCache } from "./KeyManager";

interface EncryptedArticleData {
  encryptedContent: string;
  iv: string;
  keyType: "tier" | "article";
  keyId: string;
}

interface MultiEncryptedArticle {
  tier: EncryptedArticleData;
  article: EncryptedArticleData | null;
}

interface EncryptedSectionProps {
  articleId: string;
  encryptedData: MultiEncryptedArticle | null;
}

type UnlockState = "locked" | "unlocking" | "decrypting" | "unlocked" | "error";

// RSA public exponent (65537)
const RSA_PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01]);

// Build cache key from keyType and keyId
function getCacheKey(keyType: "tier" | "article", keyId: string): string {
  return `${keyType}:${keyId}`;
}

export function EncryptedSection({ articleId, encryptedData }: EncryptedSectionProps) {
  const [state, setState] = useState<UnlockState>("locked");
  const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [usedKey, setUsedKey] = useState<{ type: "tier" | "article"; id: string } | null>(null);
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
    } catch (err) {
      console.error("Decryption failed:", err);
      log(`Decryption failed: ${err instanceof Error ? err.message : "Unknown error"}`, "error");
      setError(err instanceof Error ? err.message : "Decryption failed");
      setState("error");
    }
  }, [log]);

  // Try to auto-decrypt with cached keys
  const tryAutoDecrypt = useCallback(async (data: MultiEncryptedArticle) => {
    // Check for cached tier key first (more valuable)
    const tierCacheKey = getCacheKey("tier", data.tier.keyId);
    if (dekCache.has(tierCacheKey)) {
      log(`Found cached DEK for tier "${data.tier.keyId}"`, "crypto");
      log("Auto-decrypting content using cached tier key...", "crypto");
      const dek = dekCache.get(tierCacheKey)!;
      await decryptContent(data.tier, dek, "tier", data.tier.keyId);
      return true;
    }
    
    // Check for cached article key
    if (data.article) {
      const articleCacheKey = getCacheKey("article", data.article.keyId);
      if (dekCache.has(articleCacheKey)) {
        log(`Found cached DEK for article "${data.article.keyId}"`, "crypto");
        log("Auto-decrypting content using cached article key...", "crypto");
        const dek = dekCache.get(articleCacheKey)!;
        await decryptContent(data.article, dek, "article", data.article.keyId);
        return true;
      }
    }
    
    return false;
  }, [log, decryptContent]);

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
          
          // Check if we already have a cached DEK
          if (encryptedData) {
            const autoDecrypted = await tryAutoDecrypt(encryptedData);
            if (!autoDecrypted) {
              log(`Encrypted content ready`, "info");
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
  }, [encryptedData, articleId, log, tryAutoDecrypt]);

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

    const cacheKey = getCacheKey(keyType, encrypted.keyId);
    
    setError(null);
    setState("unlocking");
    log(`Starting unlock with ${keyType} key "${encrypted.keyId}"...`, "info");

    try {
      // Check if we already have the DEK cached
      let dek = dekCache.get(cacheKey);

      if (!dek) {
        // Export public key as SPKI
        log("Exporting public key as SPKI format...", "key");
        const publicKeySpki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        const publicKeyB64 = arrayBufferToBase64(publicKeySpki);
        log(`Public key exported (${publicKeyB64.length} chars, Base64)`, "success");

        // Request wrapped DEK from server
        log(`POST /api/unlock { keyType: "${keyType}", keyId: "${encrypted.keyId}", publicKey: "..." }`, "network");
        const response = await fetch("/api/unlock", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            keyType,
            keyId: encrypted.keyId,
            publicKey: publicKeyB64,
          }),
        });

        if (!response.ok) {
          const errorData = await response.json();
          log(`Server error: ${errorData.error}`, "error");
          throw new Error(errorData.error || "Failed to get decryption key");
        }

        const { encryptedDek } = await response.json();
        log(`Received encrypted DEK (${encryptedDek.length} chars)`, "success");

        // Unwrap the DEK using our private key
        log("Unwrapping DEK using RSA-OAEP with private key...", "crypto");
        const encryptedDekBuffer = base64ToArrayBuffer(encryptedDek);
        
        dek = await crypto.subtle.unwrapKey(
          "raw",
          encryptedDekBuffer,
          keyPair.privateKey,
          { name: "RSA-OAEP" },
          { name: "AES-GCM", length: 256 },
          false, // non-extractable
          ["decrypt"]
        );
        log("DEK unwrapped successfully (AES-256-GCM)", "success");

        // Cache the DEK
        dekCache.set(cacheKey, dek);
        if (keyType === "tier") {
          log(`DEK cached for tier "${encrypted.keyId}" (future articles decrypt instantly)`, "crypto");
        } else {
          log(`DEK cached for article "${encrypted.keyId}"`, "crypto");
        }
      } else {
        log(`Using cached DEK for ${keyType} "${encrypted.keyId}"`, "crypto");
      }

      // Decrypt the content
      await decryptContent(encrypted, dek, keyType, encrypted.keyId);

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
    return (
      <div className="unlocked-section">
        <div className="unlock-banner">
          <span>🔓</span>
          <span>Content decrypted locally (using {keyLabel} key)</span>
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

  const hasTierKey = dekCache.has(getCacheKey("tier", encryptedData.tier.keyId));
  const hasArticleKey = encryptedData.article && dekCache.has(getCacheKey("article", encryptedData.article.keyId));

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
