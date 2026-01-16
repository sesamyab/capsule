"use client";

import { useState, useEffect, useCallback } from "react";
import { useConsole } from "./ConsoleContext";

// Reference to the DEK cache from EncryptedSection
// We need to export it so we can clear it
// Keys are stored as "tier:keyId" or "article:keyId"
export const dekCache = new Map<string, CryptoKey>();

const DB_NAME = "capsule-demo-keys";
const STORE_NAME = "keypair";

interface CachedKey {
  cacheKey: string;
  keyType: "tier" | "article";
  keyId: string;
}

interface KeyStatus {
  hasRsaKeys: boolean;
  cachedKeys: CachedKey[];
}

function parseCacheKey(cacheKey: string): CachedKey {
  const [keyType, keyId] = cacheKey.split(":");
  return {
    cacheKey,
    keyType: keyType as "tier" | "article",
    keyId,
  };
}

export function KeyManager() {
  const { log } = useConsole();
  const [keyStatus, setKeyStatus] = useState<KeyStatus>({
    hasRsaKeys: false,
    cachedKeys: [],
  });
  const [isLoading, setIsLoading] = useState(true);

  const checkKeyStatus = useCallback(async () => {
    try {
      // Check IndexedDB for RSA keys
      const hasRsa = await checkRsaKeys();
      
      // Check DEK cache
      const keys = Array.from(dekCache.keys()).map(parseCacheKey);
      
      setKeyStatus({
        hasRsaKeys: hasRsa,
        cachedKeys: keys,
      });
    } catch (err) {
      console.error("Failed to check key status:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkKeyStatus();
    
    // Re-check periodically to catch DEK cache changes
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

  const handleRemoveDek = (key: CachedKey) => {
    const label = key.keyType === "tier" ? `tier "${key.keyId}"` : `article "${key.keyId}"`;
    log(`Removing cached DEK for ${label}...`, "crypto");
    dekCache.delete(key.cacheKey);
    log(`DEK for ${label} removed from cache`, "success");
    log("⚠️ You'll need to request a new key to decrypt", "info");
    checkKeyStatus();
  };

  const handleClearAll = async () => {
    log("Clearing all keys...", "key");
    
    // Clear DEK cache
    const keys = Array.from(dekCache.keys());
    keys.forEach(cacheKey => {
      const parsed = parseCacheKey(cacheKey);
      const label = parsed.keyType === "tier" ? `tier "${parsed.keyId}"` : `article "${parsed.keyId}"`;
      dekCache.delete(cacheKey);
      log(`DEK for ${label} removed`, "crypto");
    });
    
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

  if (isLoading) {
    return null;
  }

  const hasAnyKeys = keyStatus.hasRsaKeys || keyStatus.cachedKeys.length > 0;

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
        {keyStatus.cachedKeys.map(key => (
          <div key={key.cacheKey} className={`key-tag ${key.keyType === "tier" ? "dek-tier" : "dek-article"}`}>
            <span className="key-tag-icon">{key.keyType === "tier" ? "🎫" : "📄"}</span>
            <span className="key-tag-label">
              {key.keyType === "tier" ? `Tier: ${key.keyId}` : `Article: ${key.keyId}`}
            </span>
            <button 
              className="key-tag-remove" 
              onClick={() => handleRemoveDek(key)}
              title={`Remove ${key.keyType} key`}
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
