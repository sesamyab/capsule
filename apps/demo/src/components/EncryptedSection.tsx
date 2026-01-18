"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useConsole } from "./ConsoleContext";
import {
  getStoredDek,
  getCachedDek,
  cacheDek,
  storeDek,
  getTimeUntilExpiry,
  type StoredDek,
  type SecurityMode,
} from "@/lib/dek-storage";

/** Wrapped key entry */
interface WrappedKey {
  keyId: string;
  wrappedDek: string;
  expiresAt?: string;
}

/** Encrypted article with envelope encryption */
interface EncryptedArticle {
  articleId: string;
  encryptedContent: string;
  iv: string;
  wrappedKeys: WrappedKey[];
}

interface EncryptedSectionProps {
  articleId: string;
  encryptedData: EncryptedArticle | null;
  securityMode?: SecurityMode;
}

type UnlockState = "locked" | "unlocking" | "decrypting" | "unlocked" | "error";

// RSA public exponent (65537)
const RSA_PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01]);

export function EncryptedSection({
  articleId,
  encryptedData,
  securityMode = "persist",
}: EncryptedSectionProps) {
  const [state, setState] = useState<UnlockState>("locked");
  const [decryptedContent, setDecryptedContent] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [usedKeyId, setUsedKeyId] = useState<string | null>(null);
  const [cachedDekInfo, setCachedDekInfo] = useState<StoredDek | null>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const { log } = useConsole();

  // Execute scripts and dispatch event after content is decrypted
  useEffect(() => {
    if (state === "unlocked" && contentRef.current) {
      const contentElement = contentRef.current;

      // Execute any scripts in the decrypted content
      const scripts = contentElement.querySelectorAll("script");
      scripts.forEach((oldScript) => {
        const newScript = document.createElement("script");
        // Copy attributes
        Array.from(oldScript.attributes).forEach((attr) => {
          newScript.setAttribute(attr.name, attr.value);
        });
        // Copy content
        newScript.textContent = oldScript.textContent;
        // Replace old with new to trigger execution
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

  // Parse keyId to get type and base info
  const parseKeyId = (
    keyId: string
  ): { type: "tier" | "article"; baseId: string; bucketId?: string } => {
    const [first, second] = keyId.split(":", 2);
    if (first === "article") {
      return { type: "article", baseId: second };
    }
    // tier:bucketId format
    return { type: "tier", baseId: first, bucketId: second };
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

  // Decrypt content with a DEK
  const decryptContent = useCallback(
    async (dek: CryptoKey, keyId: string) => {
      if (!encryptedData) return false;

      try {
        setState("decrypting");
        log("Decoding Base64 IV and ciphertext...", "crypto");
        const iv = base64ToArrayBuffer(encryptedData.iv);
        const ciphertext = base64ToArrayBuffer(encryptedData.encryptedContent);
        log(
          `Ciphertext: ${ciphertext.byteLength} bytes, IV: ${iv.byteLength} bytes`,
          "info"
        );

        log("Decrypting content with AES-256-GCM...", "crypto");
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          dek,
          ciphertext
        );

        const content = new TextDecoder().decode(decrypted);
        log(
          `Content decrypted successfully (${content.length} chars)`,
          "success"
        );
        log("✨ Article unlocked!", "success");
        setDecryptedContent(content);
        setUsedKeyId(keyId);
        setState("unlocked");
        return true;
      } catch (err) {
        console.error("Decryption failed:", err);
        log(
          `Decryption failed: ${
            err instanceof Error ? err.message : "Unknown error"
          }`,
          "error"
        );
        return false;
      }
    },
    [encryptedData, log]
  );

  // Unwrap a key using RSA private key (works for both DEK and KEK)
  const unwrapKeyWithRsa = useCallback(
    async (
      privateKey: CryptoKey,
      encryptedKeyB64: string,
      keyUsage: "decrypt" | "unwrapKey"
    ): Promise<CryptoKey> => {
      const encryptedKeyBuffer = base64ToArrayBuffer(encryptedKeyB64);
      return await crypto.subtle.unwrapKey(
        "raw",
        encryptedKeyBuffer,
        privateKey,
        { name: "RSA-OAEP" },
        { name: "AES-GCM", length: 256 },
        false, // non-extractable
        [keyUsage]
      );
    },
    []
  );

  // Unwrap DEK using KEK (AES-GCM with prepended IV)
  // Server format: IV (12 bytes) + ciphertext + auth tag (16 bytes)
  const unwrapDekWithKek = useCallback(
    async (kek: CryptoKey, wrappedDekB64: string): Promise<CryptoKey> => {
      const wrappedDekBuffer = base64ToArrayBuffer(wrappedDekB64);

      // Extract IV (first 12 bytes) and encrypted DEK (rest)
      const iv = wrappedDekBuffer.slice(0, 12);
      const encryptedDek = wrappedDekBuffer.slice(12);

      // Decrypt to get raw DEK bytes
      const dekBytes = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(iv) },
        kek,
        encryptedDek
      );

      // Import the raw DEK bytes as a CryptoKey
      return await crypto.subtle.importKey(
        "raw",
        dekBytes,
        { name: "AES-GCM", length: 256 },
        false, // non-extractable
        ["decrypt"]
      );
    },
    []
  );

  // Try to auto-decrypt with cached keys
  const tryAutoDecrypt = useCallback(
    async (data: EncryptedArticle, keys: CryptoKeyPair) => {
      const { tierKeys, articleKeys } = getKeyOptions();

      // Try tier keys first - we cache the KEK (key-wrapping key), not the DEK
      // KEK is cached by tier:bucketId - shared across all articles in that tier/bucket
      for (const wk of tierKeys) {
        const parsed = parseKeyId(wk.keyId);
        if (!parsed.bucketId) continue;

        // Cache key for tier KEK is just "tier:bucketId" - shared across articles!
        const kekCacheId = `${parsed.baseId}:${parsed.bucketId}`;
        const cachedKek = getCachedDek("tier", kekCacheId);
        const storedKek = await getStoredDek("tier", kekCacheId);

        if (cachedKek && storedKek) {
          log(
            `Using cached KEK for tier "${parsed.baseId}" (${getTimeUntilExpiry(
              storedKek
            )})`,
            "crypto"
          );
          log(
            "Unwrapping article DEK locally with KEK (no network!)...",
            "crypto"
          );
          setState("decrypting");

          try {
            const dek = await unwrapDekWithKek(cachedKek, wk.wrappedDek);
            log("DEK unwrapped successfully", "success");
            const success = await decryptContent(dek, wk.keyId);
            if (success) {
              setCachedDekInfo(storedKek);
              return true;
            }
          } catch (err) {
            log(`Failed to unwrap DEK with cached KEK: ${err}`, "error");
          }
        }

        if (storedKek) {
          log(
            `Found stored KEK for tier "${
              parsed.baseId
            }" (valid for ${getTimeUntilExpiry(storedKek)})`,
            "info"
          );
          log("Unwrapping KEK with RSA key...", "crypto");
          setState("decrypting");

          try {
            const kek = await unwrapKeyWithRsa(
              keys.privateKey,
              storedKek.encryptedDek,
              "decrypt"
            );
            cacheDek("tier", kekCacheId, kek, storedKek);
            log("KEK unwrapped successfully", "success");

            log("Unwrapping article DEK with KEK (no network!)...", "crypto");
            const dek = await unwrapDekWithKek(kek, wk.wrappedDek);
            log("DEK unwrapped successfully", "success");

            const success = await decryptContent(dek, wk.keyId);
            if (success) {
              setCachedDekInfo(storedKek);
              return true;
            }
          } catch (err) {
            log(`Failed to unwrap with stored KEK: ${err}`, "error");
          }
        }
      }

      // Try article keys - these are DEKs cached per-article
      for (const wk of articleKeys) {
        const parsed = parseKeyId(wk.keyId);
        const cachedDek = getCachedDek("article", parsed.baseId);
        const storedDek = await getStoredDek("article", parsed.baseId);

        if (cachedDek && storedDek) {
          log(
            `Using in-memory DEK for article "${
              parsed.baseId
            }" (${getTimeUntilExpiry(storedDek)})`,
            "crypto"
          );
          setState("decrypting");
          const success = await decryptContent(cachedDek, wk.keyId);
          if (success) {
            setCachedDekInfo(storedDek);
            return true;
          }
        }

        if (storedDek) {
          log(`Found stored DEK for article "${parsed.baseId}"`, "info");
          log("Unwrapping DEK locally with RSA key (no network!)...", "crypto");
          setState("decrypting");

          try {
            const dek = await unwrapKeyWithRsa(
              keys.privateKey,
              storedDek.encryptedDek,
              "decrypt"
            );
            cacheDek("article", parsed.baseId, dek, storedDek);
            log("DEK unwrapped successfully", "success");

            const success = await decryptContent(dek, wk.keyId);
            if (success) {
              setCachedDekInfo(storedDek);
              return true;
            }
          } catch (err) {
            log(`Failed to unwrap stored DEK: ${err}`, "error");
          }
        }
      }

      return false;
    },
    [getKeyOptions, decryptContent, unwrapKeyWithRsa, unwrapDekWithKek, log]
  );

  // Fetch and unwrap key from server
  // For tier keys: gets KEK (key-wrapping key) and uses it to unwrap DEK locally
  // For article keys: gets DEK directly
  const fetchAndUnwrapKey = useCallback(
    async (wrappedKey: WrappedKey): Promise<boolean> => {
      if (!keyPair) return false;

      try {
        const parsed = parseKeyId(wrappedKey.keyId);
        const isTierKey = parsed.type === "tier";

        log("Exporting public key as SPKI format...", "key");
        const publicKeySpki = await crypto.subtle.exportKey(
          "spki",
          keyPair.publicKey
        );
        const publicKeyB64 = arrayBufferToBase64(publicKeySpki);
        log(
          `Public key exported (${publicKeyB64.length} chars, Base64)`,
          "success"
        );

        if (isTierKey) {
          // TIER KEY: Request KEK (key-wrapping key), then unwrap DEK locally
          log(
            `POST /api/unlock { keyId: "${wrappedKey.keyId}", publicKey: "..." } (tier mode - getting KEK)`,
            "network"
          );
          const response = await fetch("/api/unlock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              keyId: wrappedKey.keyId,
              publicKey: publicKeyB64,
              mode: "tier", // Request KEK, not DEK
            }),
          });

          if (!response.ok) {
            const errorData = await response.json();
            log(`Server error: ${errorData.error}`, "error");
            return false;
          }

          const {
            encryptedDek: encryptedKek,
            expiresAt,
            bucketId,
            bucketPeriodSeconds,
            keyType,
          } = await response.json();
          log(
            `Received encrypted ${keyType?.toUpperCase() || "KEK"} (${
              encryptedKek.length
            } chars)`,
            "success"
          );
          log(
            `KEK valid until: ${new Date(
              expiresAt
            ).toLocaleTimeString()} (bucket ${bucketId}, ${bucketPeriodSeconds}s period)`,
            "info"
          );

          log("Unwrapping KEK using RSA-OAEP with private key...", "crypto");
          const kek = await unwrapKeyWithRsa(
            keyPair.privateKey,
            encryptedKek,
            "decrypt"
          );
          log(
            "KEK unwrapped successfully (AES-256-GCM key for DEK unwrapping)",
            "success"
          );

          // Cache KEK by tier:bucketId - shared across all articles!
          const kekCacheId = `${parsed.baseId}:${bucketId}`;
          await storeDek(
            "tier",
            kekCacheId,
            encryptedKek,
            kek,
            new Date(expiresAt),
            bucketId,
            securityMode
          );
          const storedKek = await getStoredDek("tier", kekCacheId);
          setCachedDekInfo(storedKek);
          log(
            `KEK stored in ${securityMode} mode (shared for all ${parsed.baseId} content!)`,
            "success"
          );

          // Now unwrap the article's DEK locally using the KEK
          log(
            "Unwrapping article DEK locally with KEK (no additional network!)...",
            "crypto"
          );
          const dek = await unwrapDekWithKek(kek, wrappedKey.wrappedDek);
          log(
            "DEK unwrapped successfully (AES-256-GCM, non-extractable)",
            "success"
          );

          // Decrypt content
          const success = await decryptContent(dek, wrappedKey.keyId);
          return success;
        } else {
          // ARTICLE KEY: Request DEK directly
          log(
            `POST /api/unlock { keyId: "${wrappedKey.keyId}", wrappedDek: "...", publicKey: "..." }`,
            "network"
          );
          const response = await fetch("/api/unlock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              keyId: wrappedKey.keyId,
              wrappedDek: wrappedKey.wrappedDek,
              publicKey: publicKeyB64,
            }),
          });

          if (!response.ok) {
            const errorData = await response.json();
            log(`Server error: ${errorData.error}`, "error");
            return false;
          }

          const { encryptedDek, expiresAt, bucketId, bucketPeriodSeconds } =
            await response.json();
          log(
            `Received encrypted DEK (${encryptedDek.length} chars)`,
            "success"
          );
          log(
            `DEK valid until: ${new Date(
              expiresAt
            ).toLocaleTimeString()} (bucket ${
              bucketId || "static"
            }, ${bucketPeriodSeconds}s period)`,
            "info"
          );

          log("Unwrapping DEK using RSA-OAEP with private key...", "crypto");
          const dek = await unwrapKeyWithRsa(
            keyPair.privateKey,
            encryptedDek,
            "decrypt"
          );
          log(
            "DEK unwrapped successfully (AES-256-GCM, non-extractable)",
            "success"
          );

          // Store DEK by article ID
          await storeDek(
            "article",
            parsed.baseId,
            encryptedDek,
            dek,
            new Date(expiresAt),
            bucketId || "static",
            securityMode
          );
          const storedDek = await getStoredDek("article", parsed.baseId);
          setCachedDekInfo(storedDek);
          log(`DEK stored in ${securityMode} mode`, "success");

          // Decrypt content
          const success = await decryptContent(dek, wrappedKey.keyId);
          return success;
        }
      } catch (err) {
        console.error("Failed to fetch key:", err);
        log(
          `Failed to fetch key: ${
            err instanceof Error ? err.message : "Unknown error"
          }`,
          "error"
        );
        return false;
      }
    },
    [
      keyPair,
      unwrapKeyWithRsa,
      unwrapDekWithKek,
      decryptContent,
      log,
      securityMode,
    ]
  );

  // Initialize key pair on mount
  useEffect(() => {
    let mounted = true;

    async function initKeys() {
      try {
        log(`Loading article "${articleId}"...`, "info");

        log("Checking IndexedDB for existing RSA key pair...", "key");
        let keys = await loadKeysFromStorage();

        if (!keys) {
          log(
            "No existing keys found. Generating new RSA-2048 key pair...",
            "key"
          );
          keys = await crypto.subtle.generateKey(
            {
              name: "RSA-OAEP",
              modulusLength: 2048,
              publicExponent: RSA_PUBLIC_EXPONENT,
              hash: "SHA-256",
            },
            true,
            ["wrapKey", "unwrapKey"]
          );

          log("RSA key pair generated successfully", "success");
          log("Storing keys in IndexedDB...", "key");
          await saveKeysToStorage(keys);
          log("Keys stored securely in IndexedDB", "success");
        } else {
          log("Found existing RSA key pair in IndexedDB", "success");
        }

        if (mounted) {
          setKeyPair(keys);
          setIsInitializing(false);

          if (encryptedData) {
            const autoDecrypted = await tryAutoDecrypt(encryptedData, keys);
            if (!autoDecrypted) {
              const { tierKeys, articleKeys } = getKeyOptions();
              log(`Encrypted content ready (${securityMode} mode)`, "info");
              log(
                `Available keys: ${tierKeys.length} tier, ${articleKeys.length} article`,
                "info"
              );
              log("Click 'Unlock' to request decryption key", "info");
            }
          }
        }
      } catch (err) {
        console.error("Failed to initialize keys:", err);
        log(
          `Error: ${
            err instanceof Error ? err.message : "Failed to initialize"
          }`,
          "error"
        );
        if (mounted) {
          setError(err instanceof Error ? err.message : "Failed to initialize");
          setIsInitializing(false);
        }
      }
    }

    initKeys();
    return () => {
      mounted = false;
    };
  }, [
    encryptedData,
    articleId,
    log,
    tryAutoDecrypt,
    getKeyOptions,
    securityMode,
  ]);

  // Auto-renew KEK/DEK before it expires
  useEffect(() => {
    if (state !== "unlocked" || !keyPair || !usedKeyId || !encryptedData) {
      return;
    }

    const parsed = parseKeyId(usedKeyId);
    const RENEW_BUFFER_MS = 5000;
    // For tier keys, cache is by tier:bucketId (KEK)
    // For article keys, cache is by articleId (DEK)
    const cacheId =
      parsed.type === "tier" && parsed.bucketId
        ? `${parsed.baseId}:${parsed.bucketId}`
        : parsed.baseId;

    const checkAndRenew = async () => {
      const stored = await getStoredDek(parsed.type, cacheId);
      if (!stored) return;

      const timeUntilExpiry = stored.expiresAt - Date.now();

      if (timeUntilExpiry <= RENEW_BUFFER_MS) {
        log(
          `Key expires in ${Math.round(
            timeUntilExpiry / 1000
          )}s, auto-renewing...`,
          "info"
        );

        // Find the wrapped key for this keyId
        const wrappedKey = encryptedData.wrappedKeys.find(
          (wk) => wk.keyId === usedKeyId
        );
        if (!wrappedKey) {
          log("Cannot renew - wrapped key not found", "error");
          return;
        }

        await fetchAndUnwrapKey(wrappedKey);
      }
    };

    checkAndRenew();
    const interval = setInterval(checkAndRenew, 1000);
    return () => clearInterval(interval);
  }, [state, keyPair, usedKeyId, encryptedData, log, fetchAndUnwrapKey]);

  // Handle unlock button click
  const handleUnlock = async (keyType: "tier" | "article") => {
    if (!keyPair || !encryptedData) {
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

    // Try each key in order (for tier keys, try current bucket first)
    for (const wrappedKey of keys) {
      log(`Trying to unlock with ${wrappedKey.keyId}...`, "info");
      const success = await fetchAndUnwrapKey(wrappedKey);
      if (success) return;
    }

    setError("All unlock attempts failed");
    setState("error");
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
    const keyLabel =
      parsed.type === "tier"
        ? `tier "${parsed.baseId}"`
        : `article "${parsed.baseId}"`;
    const expiryDisplay = cachedDekInfo
      ? getTimeUntilExpiry(cachedDekInfo)
      : null;

    return (
      <div className="unlocked-section">
        <div className="unlock-banner">
          <span>🔓</span>
          <span>Content decrypted locally (using {keyLabel} key)</span>
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
            <p className="status-detail">Using cached DEK (works offline!)</p>
          </>
        ) : (
          <>
            <div className="lock-icon">🔒</div>
            <h3>Premium Content</h3>
            <p>Choose how to unlock this encrypted content:</p>
            <div className="unlock-buttons">
              {tierKeys.length > 0 && (
                <button
                  onClick={() => handleUnlock("tier")}
                  className="primary"
                >
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

// IndexedDB helpers
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
