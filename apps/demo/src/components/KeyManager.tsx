"use client";

import { useState, useEffect, useCallback } from "react";
import { useConsole } from "./ConsoleContext";
import { 
  getAllStoredDeks, 
  deleteDek, 
  clearAllDeks, 
  purgeExpiredDeks,
  getTimeUntilExpiry,
  type StoredDek 
} from "@/lib/dek-storage";

const DB_NAME = "capsule-demo-keys";
const STORE_NAME = "keypair";

interface KeyStatus {
  hasRsaKeys: boolean;
  cachedDeks: StoredDek[];
}

export function KeyManager() {
  const { log } = useConsole();
  const [keyStatus, setKeyStatus] = useState<KeyStatus>({
    hasRsaKeys: false,
    cachedDeks: [],
  });
  const [isLoading, setIsLoading] = useState(true);
  const [isMounted, setIsMounted] = useState(false);

  // Prevent hydration mismatch by only rendering after mount
  useEffect(() => {
    setIsMounted(true);
  }, []);

  const checkKeyStatus = useCallback(async () => {
    try {
      // Purge expired DEKs first (non-critical, may fail silently)
      await purgeExpiredDeks();
      
      // Check IndexedDB for RSA keys
      const hasRsa = await checkRsaKeys();
      
      // Get all valid stored DEKs (may return empty if DB issues)
      const deks = await getAllStoredDeks();
      
      setKeyStatus({
        hasRsaKeys: hasRsa,
        cachedDeks: deks,
      });
    } catch (err) {
      console.error("Failed to check key status:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkKeyStatus();
    
    // Re-check frequently to update expiry countdown and purge expired keys
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

  const handleRemoveDek = async (stored: StoredDek) => {
    const label = stored.keyType === "tier" ? `tier "${stored.keyId}"` : `article "${stored.keyId}"`;
    log(`Removing DEK for ${label}...`, "crypto");
    await deleteDek(stored.keyType, stored.keyId);
    log(`DEK for ${label} removed`, "success");
    log("⚠️ You'll need to request a new key to decrypt", "info");
    await checkKeyStatus();
  };

  const handleClearAll = async () => {
    log("Clearing all keys...", "key");
    
    // Clear all DEKs
    await clearAllDeks();
    log("All DEKs removed", "crypto");
    
    // Clear RSA keys
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

  const hasAnyKeys = keyStatus.hasRsaKeys || keyStatus.cachedDeks.length > 0;

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
        {keyStatus.cachedDeks.map(stored => (
          <div key={stored.cacheKey} className={`key-tag ${stored.keyType === "tier" ? "dek-tier" : "dek-article"}`}>
            <span className="key-tag-icon">{stored.keyType === "tier" ? "🎫" : "📄"}</span>
            <span className="key-tag-label">
              {stored.keyType === "tier" ? `Tier: ${stored.keyId}` : `Article: ${stored.keyId}`}
            </span>
            <span className="key-tag-expiry" title={`Expires at ${new Date(stored.expiresAt).toLocaleTimeString()}`} suppressHydrationWarning>
              {getTimeUntilExpiry(stored)}
            </span>
            <button 
              className="key-tag-remove" 
              onClick={() => handleRemoveDek(stored)}
              title={`Remove ${stored.keyType} key`}
            >
              ×
            </button>
          </div>
        ))}
      </div>
      {hasAnyKeys && (
        <button className="key-clear-all" onClick={handleClearAll}>
          Clear All
        </button>
      )}
    </div>
  );
}

async function checkRsaKeys(): Promise<boolean> {
  return new Promise((resolve) => {
    const request = indexedDB.open(DB_NAME, 1);
    
    request.onerror = () => resolve(false);
    
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    
    request.onsuccess = () => {
      const db = request.result;
      try {
        const tx = db.transaction(STORE_NAME, "readonly");
        const store = tx.objectStore(STORE_NAME);
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
    const request = indexedDB.open(DB_NAME, 1);
    
    request.onerror = () => reject(request.error);
    
    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };
    
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      store.delete("default");
      
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    };
  });
}
