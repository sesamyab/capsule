"use client";

import { useState, useEffect, useCallback } from "react";
import { useConsole } from "./ConsoleContext";

/**
 * Database names and stores used by the @sesamy/capsule client library.
 * These must match the constants in packages/capsule-client/src/client.ts
 * and packages/capsule-client/src/storage.ts.
 */
const RSA_DB_NAME = "capsule-keys";
const RSA_STORE_NAME = "keypair";
const CONTENT_KEY_DB_NAME = "capsule-content-keys";
const CONTENT_KEY_STORE_NAME = "content-keys";

/** Matches StoredContentKey from @sesamy/capsule client */
interface StoredContentKey {
  type: "shared" | "article";
  baseId: string;
  encryptedContentKey: string;
  expiresAt: number;
  periodId?: string;
}

interface KeyStatus {
  hasRsaKeys: boolean;
  contentKeys: Array<{ key: string; value: StoredContentKey }>;
}

export function KeyManager() {
  const { log } = useConsole();
  const [keyStatus, setKeyStatus] = useState<KeyStatus>({
    hasRsaKeys: false,
    contentKeys: [],
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

      setKeyStatus({
        hasRsaKeys: hasRsa,
        contentKeys,
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
    const label = stored.type === "shared" ? `shared "${stored.baseId}"` : `article "${stored.baseId}"`;
    log(`Removing content key for ${label}...`, "crypto");
    await deleteContentKey(storeKey);
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

    log("✨ All keys cleared", "success");
    await checkKeyStatus();
  };

  if (isLoading || !isMounted) {
    return null;
  }

  const hasAnyKeys = keyStatus.hasRsaKeys || keyStatus.contentKeys.length > 0;

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
          const timeLeft = getTimeUntilExpiry(stored.expiresAt);
          return (
            <div key={key} className={`key-tag ${stored.type === "shared" ? "dek-shared" : "dek-article"}`}>
              <span className="key-tag-icon">{stored.type === "shared" ? "🎫" : "📄"}</span>
              <span className="key-tag-label">
                {stored.type === "shared" ? `Shared: ${stored.baseId}` : `Article: ${stored.baseId}`}
              </span>
              <span
                className="key-tag-expiry"
                title={`Expires at ${new Date(stored.expiresAt).toLocaleTimeString()}`}
                suppressHydrationWarning
              >
                {isExpired ? "expired" : timeLeft}
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

async function checkRsaKeys(): Promise<boolean> {
  return new Promise((resolve) => {
    const request = indexedDB.open(RSA_DB_NAME, 1);

    request.onerror = () => resolve(false);

    request.onupgradeneeded = () => {
      request.result.createObjectStore(RSA_STORE_NAME, { keyPath: "id" });
    };

    request.onsuccess = () => {
      const db = request.result;
      try {
        const tx = db.transaction(RSA_STORE_NAME, "readonly");
        const store = tx.objectStore(RSA_STORE_NAME);
        const getRequest = store.get("default");

        getRequest.onsuccess = () => {
          resolve(!!getRequest.result);
        };
        getRequest.onerror = () => resolve(false);
      } catch {
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
      request.result.createObjectStore(RSA_STORE_NAME, { keyPath: "id" });
    };

    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(RSA_STORE_NAME, "readwrite");
      const store = tx.objectStore(RSA_STORE_NAME);
      store.delete("default");

      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
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
          resolve(keys);
        }
      };
      cursorRequest.onerror = () => resolve([]);
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
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function clearAllContentKeys(): Promise<void> {
  try {
    const db = await openContentKeyDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(CONTENT_KEY_STORE_NAME, "readwrite");
      const store = tx.objectStore(CONTENT_KEY_STORE_NAME);
      store.clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // DB may not exist yet
  }
}
