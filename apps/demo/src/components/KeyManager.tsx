"use client";

import { useState, useEffect, useCallback } from "react";
import { useConsole } from "./ConsoleContext";

/**
 * Database names and stores used by the @sesamy/capsule client library.
 * These must match the constants in packages/capsule-client/src/dca-client.ts.
 */
const RSA_DB_NAME = "dca-keys";
const RSA_STORE_NAME = "keypair";
const CONTENT_KEY_DB_NAME = "capsule-content-keys";
const CONTENT_KEY_STORE_NAME = "content-keys";
const WRAP_KEY_DB_NAME = "capsule-wrap-keys";
const WRAP_KEY_STORE_NAME = "wrap-keys";

/** Matches StoredContentKey from @sesamy/capsule client */
interface StoredContentKey {
  type: "shared" | "article" | "subscription";
  baseId: string;
  encryptedContentKey: string;
  expiresAt: number;
  kid?: string;
}

interface KeyStatus {
  hasRsaKeys: boolean;
  contentKeys: Array<{ key: string; value: StoredContentKey }>;
  wrapKeyCount: number;
}

export function KeyManager() {
  const { log } = useConsole();
  const [keyStatus, setKeyStatus] = useState<KeyStatus>({
    hasRsaKeys: false,
    contentKeys: [],
    wrapKeyCount: 0,
  });
  const [isLoading, setIsLoading] = useState(true);
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  const checkKeyStatus = useCallback(async () => {
    try {
      const hasRsa = await checkRsaKeys();
      const contentKeys = await getAllContentKeys();
      const wrapKeyCount = await getWrapKeyCount();

      setKeyStatus({
        hasRsaKeys: hasRsa,
        contentKeys,
        wrapKeyCount,
      });
    } catch (err) {
      console.error("Failed to check key status:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkKeyStatus();
    const interval = setInterval(checkKeyStatus, 1000);
    return () => clearInterval(interval);
  }, [checkKeyStatus]);

  const handleRemoveRsaKeys = async () => {
    log("Removing RSA key pair from IndexedDB...", "key");
    try {
      await clearRsaKeys();
      log("RSA key pair removed successfully", "success");
      log("⚠️ New keys will be generated on next page load", "info");
      await checkKeyStatus();
    } catch (err) {
      log(`Failed to remove RSA keys: ${err}`, "error");
    }
  };

  const handleRemoveContentKey = async (storeKey: string, stored: StoredContentKey) => {
    const isSubscription = stored.type === "subscription" || stored.type === "shared";
    const label = isSubscription ? `${stored.baseId} subscription` : `article "${stored.baseId}"`;
    log(`Removing content key for ${label}...`, "crypto");
    await deleteContentKey(storeKey);

    // Removing a scope subscription also clears that scope's cached wrap keys
    if (isSubscription) {
      try {
        await clearWrapKeyCacheForScope(stored.baseId);
        log(`Wrap key cache cleared for ${stored.baseId}`, "crypto");
      } catch {
        // ignore
      }
    }

    log(`Content key for ${label} removed`, "success");
    log("⚠️ You'll need to request a new key to decrypt", "info");
    await checkKeyStatus();
  };

  const handleClearAll = async () => {
    log("Clearing all keys...", "key");

    await clearAllContentKeys();
    log("All content keys removed", "crypto");

    try {
      await clearRsaKeys();
      log("RSA key pair removed", "key");
    } catch (err) {
      log(`Failed to remove RSA keys: ${err}`, "error");
    }

    // Also clear cached wrap keys
    try {
      await clearWrapKeyCache();
      log("Wrap key cache cleared", "crypto");
    } catch {
      // ignore
    }

    // Clean up legacy DB from older code
    try {
      indexedDB.deleteDatabase("capsule-keys");
    } catch {
      // ignore
    }

    log("✨ All keys cleared", "success");
    await checkKeyStatus();
  };

  if (isLoading || !isMounted) {
    return null;
  }

  const hasAnyKeys = keyStatus.hasRsaKeys || keyStatus.contentKeys.length > 0 || keyStatus.wrapKeyCount > 0;

  if (!hasAnyKeys) {
    return (
      <div className="key-manager">
        <div className="key-manager-empty">
          <span className="key-icon">🔑</span>
          <span>No keys stored</span>
        </div>
      </div>
    );
  }

  return (
    <div className="key-manager">
      <div className="key-manager-label">Stored Keys:</div>
      <div className="key-tags">
        {keyStatus.hasRsaKeys && (
          <div className="key-tag rsa">
            <span className="key-tag-icon">🔐</span>
            <span className="key-tag-label">RSA-2048</span>
            <button
              className="key-tag-remove"
              onClick={handleRemoveRsaKeys}
              title="Remove RSA key pair"
            >
              ×
            </button>
          </div>
        )}
        {keyStatus.contentKeys.map(({ key, value: stored }) => {
          const isExpired = stored.expiresAt <= Date.now();
          const isSubscription = stored.type === "subscription" || stored.type === "shared";
          // For subscription: show time until next time bucket (hourly rotation)
          // For article: show time until the record expires
          const timeLeft = isSubscription
            ? getTimeUntilNextBucket()
            : getTimeUntilExpiry(stored.expiresAt);
          return (
            <div key={key} className={`key-tag ${isSubscription ? "dek-shared" : "dek-article"}`}>
              <span className="key-tag-icon">{isSubscription ? "🔑" : "📄"}</span>
              <span className="key-tag-label">
                {isSubscription ? stored.baseId : `Article: ${stored.baseId}`}
              </span>
              <span
                className="key-tag-expiry"
                title={isSubscription
                  ? `Wrap key rotates at ${getNextBucketTime().toLocaleTimeString()}`
                  : `Expires at ${new Date(stored.expiresAt).toLocaleTimeString()}`
                }
                suppressHydrationWarning
              >
                {isExpired && !isSubscription ? "expired" : `renews ${timeLeft}`}
              </span>
              <button
                className="key-tag-remove"
                onClick={() => handleRemoveContentKey(key, stored)}
                title={`Remove ${stored.type} key`}
              >
                ×
              </button>
            </div>
          );
        })}
      </div>
      {hasAnyKeys && (
        <button className="key-clear-all" onClick={handleClearAll}>
          Clear All
        </button>
      )}
    </div>
  );
}

// ============================================================================
// IndexedDB helpers — read from the @sesamy/capsule client's databases
// ============================================================================

function getTimeUntilExpiry(expiresAt: number): string {
  const ms = expiresAt - Date.now();
  if (ms <= 0) return "expired";
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
}

/**
 * Get the Date of the next hourly rotation boundary.
 * Wrap keys rotate at the top of each UTC hour.
 */
function getNextBucketTime(): Date {
  const now = new Date();
  const next = new Date(now);
  next.setUTCMinutes(0, 0, 0);
  next.setUTCHours(next.getUTCHours() + 1);
  return next;
}

/**
 * Human-readable time until the next hourly rotation.
 */
function getTimeUntilNextBucket(): string {
  const ms = getNextBucketTime().getTime() - Date.now();
  if (ms <= 0) return "now";
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `in ${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `in ${minutes}m ${seconds % 60}s`;
}

async function checkRsaKeys(): Promise<boolean> {
  return new Promise((resolve) => {
    const request = indexedDB.open(RSA_DB_NAME, 1);

    request.onerror = () => resolve(false);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(RSA_STORE_NAME)) {
        db.createObjectStore(RSA_STORE_NAME, { keyPath: "id" });
      }
    };

    request.onsuccess = () => {
      const db = request.result;
      try {
        const tx = db.transaction(RSA_STORE_NAME, "readonly");
        const store = tx.objectStore(RSA_STORE_NAME);
        const getRequest = store.get("default");

        getRequest.onsuccess = () => {
          db.close();
          resolve(!!getRequest.result);
        };
        getRequest.onerror = () => {
          db.close();
          resolve(false);
        };
      } catch {
        db.close();
        resolve(false);
      }
    };
  });
}

async function clearRsaKeys(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(RSA_DB_NAME, 1);

    request.onerror = () => reject(request.error);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(RSA_STORE_NAME)) {
        db.createObjectStore(RSA_STORE_NAME, { keyPath: "id" });
      }
    };

    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(RSA_STORE_NAME, "readwrite");
      const store = tx.objectStore(RSA_STORE_NAME);
      store.delete("default");

      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
  });
}

async function openContentKeyDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(CONTENT_KEY_DB_NAME, 1);
    request.onerror = () => reject(request.error);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(CONTENT_KEY_STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
  });
}

async function getAllContentKeys(): Promise<Array<{ key: string; value: StoredContentKey }>> {
  try {
    const db = await openContentKeyDb();
    return new Promise((resolve) => {
      const tx = db.transaction(CONTENT_KEY_STORE_NAME, "readonly");
      const store = tx.objectStore(CONTENT_KEY_STORE_NAME);
      const keys: Array<{ key: string; value: StoredContentKey }> = [];

      const cursorRequest = store.openCursor();
      cursorRequest.onsuccess = () => {
        const cursor = cursorRequest.result;
        if (cursor) {
          keys.push({ key: cursor.key as string, value: cursor.value });
          cursor.continue();
        } else {
          db.close();
          resolve(keys);
        }
      };
      cursorRequest.onerror = () => { db.close(); resolve([]); };
    });
  } catch {
    return [];
  }
}

async function deleteContentKey(storeKey: string): Promise<void> {
  const db = await openContentKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(CONTENT_KEY_STORE_NAME, "readwrite");
    const store = tx.objectStore(CONTENT_KEY_STORE_NAME);
    store.delete(storeKey);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

async function clearAllContentKeys(): Promise<void> {
  try {
    const db = await openContentKeyDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONTENT_KEY_STORE_NAME, "readwrite");
      const store = tx.objectStore(CONTENT_KEY_STORE_NAME);
      store.clear();
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    });
  } catch {
    // DB may not exist yet
  }
}

// ============================================================================
// Wrap key cache helpers
// ============================================================================

async function getWrapKeyCount(): Promise<number> {
  try {
    return new Promise((resolve) => {
      const request = indexedDB.open(WRAP_KEY_DB_NAME, 1);
      request.onerror = () => resolve(0);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(WRAP_KEY_STORE_NAME);
      };
      request.onsuccess = () => {
        const db = request.result;
        try {
          const tx = db.transaction(WRAP_KEY_STORE_NAME, "readonly");
          const store = tx.objectStore(WRAP_KEY_STORE_NAME);
          const countReq = store.count();
          countReq.onsuccess = () => { db.close(); resolve(countReq.result); };
          countReq.onerror = () => { db.close(); resolve(0); };
        } catch {
          db.close();
          resolve(0);
        }
      };
    });
  } catch {
    return 0;
  }
}

async function clearWrapKeyCache(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(WRAP_KEY_DB_NAME, 1);
    request.onerror = () => reject(request.error);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(WRAP_KEY_STORE_NAME);
    };
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(WRAP_KEY_STORE_NAME, "readwrite");
      const store = tx.objectStore(WRAP_KEY_STORE_NAME);
      store.clear();
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
  });
}

/**
 * Clear cached wrap keys for a specific scope.
 * Keys are stored as `dca:wk:${scope}:${kid}`.
 */
async function clearWrapKeyCacheForScope(scope: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(WRAP_KEY_DB_NAME, 1);
    request.onerror = () => reject(request.error);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(WRAP_KEY_STORE_NAME);
    };
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(WRAP_KEY_STORE_NAME, "readwrite");
      const store = tx.objectStore(WRAP_KEY_STORE_NAME);
      const prefix = `dca:wk:${scope}:`;
      const cursorReq = store.openCursor();
      cursorReq.onsuccess = () => {
        const cursor = cursorReq.result;
        if (cursor) {
          if (typeof cursor.key === "string" && cursor.key.startsWith(prefix)) {
            cursor.delete();
          }
          cursor.continue();
        }
      };
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
  });
}
