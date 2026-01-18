/**
 * DEK (Data Encryption Key) storage with expiration support.
 *
 * Stores ENCRYPTED DEK bytes in IndexedDB. On page load, the DEK is unwrapped
 * using the RSA private key (also stored in IndexedDB).
 *
 * SECURITY MODES:
 *
 * 1. "persist" (default) - Stores encrypted DEK in IndexedDB
 *    - ✅ No network request on page refresh (unwrap locally)
 *    - ✅ Encrypted at rest (needs RSA private key to unwrap)
 *    - Best for: typical premium content, performance-critical apps
 *
 * 2. "session" - Keeps DEK in memory only
 *    - ✅ Key vanishes when tab closes
 *    - ⚠️ Requires network request each page load
 *    - Best for: highly sensitive content
 */

const DB_NAME = "capsule-dek-cache";
const STORE_NAME = "deks";
const DB_VERSION = 4; // Store encrypted DEK bytes, not CryptoKey

export type SecurityMode = "persist" | "session";

export interface StoredDek {
  cacheKey: string;
  keyType: "tier" | "article";
  keyId: string;
  encryptedDek: string; // Base64-encoded wrapped DEK bytes
  expiresAt: number; // Unix timestamp in ms
  bucketId: string;
}

// In-memory cache for unwrapped DEKs
const memoryCache = new Map<string, { dek: CryptoKey; stored: StoredDek }>();

/**
 * Open the DEK database with timeout
 */
function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(
        new Error(
          "IndexedDB open timeout - try closing other tabs or clearing the database"
        )
      );
    }, 2000);

    try {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onerror = () => {
        clearTimeout(timeout);
        reject(request.error);
      };

      request.onblocked = () => {
        clearTimeout(timeout);
        console.warn("IndexedDB blocked - close other tabs and refresh");
        reject(new Error("IndexedDB blocked - close other tabs"));
      };

      request.onupgradeneeded = (event) => {
        const db = request.result;
        // Delete old store if upgrading (schema changed)
        if (
          event.oldVersion < DB_VERSION &&
          db.objectStoreNames.contains(STORE_NAME)
        ) {
          db.deleteObjectStore(STORE_NAME);
        }
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, {
            keyPath: "cacheKey",
          });
          store.createIndex("expiresAt", "expiresAt");
        }
      };

      request.onsuccess = () => {
        clearTimeout(timeout);
        resolve(request.result);
      };
    } catch (err) {
      clearTimeout(timeout);
      reject(err);
    }
  });
}

/**
 * Build cache key from keyType and keyId
 */
export function buildCacheKey(
  keyType: "tier" | "article",
  keyId: string
): string {
  return `${keyType}:${keyId}`;
}

/**
 * Store encrypted DEK with expiration.
 */
export async function storeDek(
  keyType: "tier" | "article",
  keyId: string,
  encryptedDek: string,
  dek: CryptoKey,
  expiresAt: Date,
  bucketId: string,
  mode: SecurityMode = "persist"
): Promise<void> {
  const cacheKey = buildCacheKey(keyType, keyId);
  const stored: StoredDek = {
    cacheKey,
    keyType,
    keyId,
    encryptedDek,
    expiresAt: expiresAt.getTime(),
    bucketId,
  };

  // Always update memory cache with unwrapped DEK
  memoryCache.set(cacheKey, { dek, stored });

  // Only persist to IndexedDB in "persist" mode
  if (mode === "persist") {
    try {
      const db = await openDb();
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      store.put(stored);

      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (err) {
      console.error("Failed to persist DEK:", err);
    }
  }
}

/**
 * Get stored DEK metadata (for checking if we have a cached key)
 */
export async function getStoredDek(
  keyType: "tier" | "article",
  keyId: string
): Promise<StoredDek | null> {
  const cacheKey = buildCacheKey(keyType, keyId);
  const now = Date.now();

  // Check memory cache first
  const cached = memoryCache.get(cacheKey);
  if (cached && cached.stored.expiresAt > now) {
    return cached.stored;
  }

  // Try IndexedDB
  try {
    const db = await openDb();
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);

    const stored = await new Promise<StoredDek | undefined>(
      (resolve, reject) => {
        const request = store.get(cacheKey);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      }
    );

    if (stored && stored.expiresAt > now) {
      return stored;
    }

    // Expired or not found
    if (stored) {
      await deleteDek(keyType, keyId);
    }
  } catch (err) {
    console.error("Failed to load DEK:", err);
  }

  return null;
}

/**
 * Get cached (unwrapped) DEK from memory
 */
export function getCachedDek(
  keyType: "tier" | "article",
  keyId: string
): CryptoKey | null {
  const cacheKey = buildCacheKey(keyType, keyId);
  const cached = memoryCache.get(cacheKey);
  if (cached && cached.stored.expiresAt > Date.now()) {
    return cached.dek;
  }
  return null;
}

/**
 * Cache an unwrapped DEK in memory
 */
export function cacheDek(
  keyType: "tier" | "article",
  keyId: string,
  dek: CryptoKey,
  stored: StoredDek
): void {
  const cacheKey = buildCacheKey(keyType, keyId);
  memoryCache.set(cacheKey, { dek, stored });
}

/**
 * Delete a specific DEK
 */
export async function deleteDek(
  keyType: "tier" | "article",
  keyId: string
): Promise<void> {
  const cacheKey = buildCacheKey(keyType, keyId);
  memoryCache.delete(cacheKey);

  try {
    const db = await openDb();
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    store.delete(cacheKey);

    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch (err) {
    console.error("Failed to delete DEK:", err);
  }
}

/**
 * Get all stored DEKs (for display purposes)
 */
export async function getAllStoredDeks(): Promise<StoredDek[]> {
  const now = Date.now();
  const results: StoredDek[] = [];

  try {
    const db = await openDb();
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);

    const all = await new Promise<StoredDek[]>((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });

    for (const stored of all) {
      if (stored.expiresAt > now) {
        results.push(stored);
      }
    }
  } catch (err) {
    console.error("Failed to get all DEKs:", err);
  }

  return results;
}

/**
 * Clear all stored DEKs
 */
export async function clearAllDeks(): Promise<void> {
  memoryCache.clear();

  try {
    const db = await openDb();
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    store.clear();

    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch (err) {
    console.error("Failed to clear DEKs:", err);
  }
}

/**
 * Clean up expired DEKs
 */
export async function purgeExpiredDeks(): Promise<number> {
  const now = Date.now();
  let purged = 0;

  // Clean memory cache
  memoryCache.forEach((cached, key) => {
    if (cached.stored.expiresAt <= now) {
      memoryCache.delete(key);
      purged++;
    }
  });

  // Skip IndexedDB cleanup if database is having issues - it's not critical
  // The expired entries will just be ignored on read
  try {
    const db = await openDb();
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);

    const all = await new Promise<StoredDek[]>((resolve, reject) => {
      const request = store.getAll();
      request.onsuccess = () => resolve(request.result || []);
      request.onerror = () => reject(request.error);
    });

    for (const item of all) {
      if (item.expiresAt <= now) {
        store.delete(item.cacheKey);
        purged++;
      }
    }

    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });

    db.close();
  } catch {
    // Silently ignore - purging is not critical
  }

  return purged;
}

/**
 * Get time until a DEK expires (for display)
 */
export function getTimeUntilExpiry(stored: StoredDek): string {
  const remaining = stored.expiresAt - Date.now();
  if (remaining <= 0) return "expired";

  const seconds = Math.ceil(remaining / 1000);
  if (seconds < 60) return `${seconds}s`;

  const minutes = Math.ceil(seconds / 60);
  return `${minutes}m`;
}
