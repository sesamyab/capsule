/**
 * Capsule Client - High-level API for encrypted content decryption.
 *
 * Uses the Web Crypto API for all cryptographic operations:
 * - RSA-OAEP for key unwrapping (SHA-256)
 * - AES-256-GCM for content decryption
 *
 * @example Minimal setup:
 * ```ts
 * const capsule = new CapsuleClient({
 *   unlock: async ({ keyId, wrappedContentKey, publicKey }) => {
 *     const res = await fetch('/api/unlock', {
 *       method: 'POST',
 *       body: JSON.stringify({ keyId, wrappedContentKey, publicKey }),
 *     });
 *     return res.json();
 *   }
 * });
 *
 * // Keys are auto-created on first use
 * await capsule.unlockElement('article-123');
 * ```
 *
 * @example Auto-process all encrypted elements:
 * ```ts
 * const capsule = new CapsuleClient({
 *   unlock: myUnlockFunction,
 *   autoProcess: true,
 * });
 *
 * // Listen for unlock events
 * document.addEventListener('capsule:unlock', (e) => {
 *   console.log('Unlocked:', e.detail.resourceId);
 * });
 * ```
 *
 * @example Manual low-level control:
 * ```ts
 * const capsule = new CapsuleClient();
 * const publicKey = await capsule.getPublicKey();
 * const encryptedContentKey = await myServerCall(publicKey);
 * const content = await capsule.decrypt(encryptedArticle, encryptedContentKey);
 * ```
 */

import { KeyStorage } from "./storage";
import type {
  EncryptedPayload,
  EncryptedArticle,
  WrappedKey,
  CapsuleClientOptions,
  StoredKeyPair,
  StoredContentKey,
  UnlockFunction,
  UnlockResponse,
  ElementState,
  ContentKeyStorageMode,
  CapsuleUnlockEvent,
  CapsuleErrorEvent,
  CapsuleStateEvent,
} from "./types";

/** Default key identifier for RSA key pair */
const DEFAULT_KEY_ID = "default";

/** Default CSS selector for encrypted elements */
const DEFAULT_SELECTOR = "[data-capsule]";

/** RSA public exponent (65537) */
const RSA_PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01]);

/** DEK storage key prefix */
const CONTENT_KEY_STORAGE_PREFIX = "capsule-key:";

/** AES-GCM initialization vector size in bytes (96 bits per NIST) */
const GCM_IV_BYTES = 12;

/**
 * Main client for Capsule decryption operations.
 *
 * Handles:
 * - RSA key pair generation and storage (auto-creates if needed)
 * - content key caching and auto-renewal
 * - HTML element processing and script execution
 * - Custom event emission
 */
export class CapsuleClient {
  private storage: KeyStorage;
  private keySize: 2048 | 4096;
  private unlockFn?: UnlockFunction;
  private autoProcess: boolean;
  private executeScripts: boolean;
  private selector: string;
  private contentKeyStorage: ContentKeyStorageMode;
  private renewBuffer: number;
  private logger?: (message: string, level: "info" | "error" | "debug") => void;

  // Cached state
  private keyPairPromise: Promise<StoredKeyPair> | null = null;
  private contentKeyCache: Map<string, { contentKey: CryptoKey; info: StoredContentKey }> =
    new Map();
  private renewalTimers: Map<string, number> = new Map();
  private elementStates: Map<string, ElementState> = new Map();

  // Shared key cache: content ID → { AES CryptoKey, periodId, expiresAt }
  private sharedKeyCache: Map<
    string,
    { key: CryptoKey; periodId: string; expiresAt: number }
  > = new Map();
  private sharedRenewalTimers: Map<string, number> = new Map();
  /** Expired key IDs found (and cleaned up) during the last tryUnlockFromCache call */
  private _expiredKeyIds: Set<string> = new Set();
  /** The wrapped key IDs from the last tryUnlockFromCache article */
  private _lastContentKeyIds: Set<string> = new Set();

  /**
   * Create a new CapsuleClient instance.
   *
   * @param options - Configuration options
   *
   * @example
   * ```ts
   * // Minimal - just provide unlock function
   * const capsule = new CapsuleClient({
   *   unlock: async (params) => fetch('/api/unlock', {
   *     method: 'POST',
   *     body: JSON.stringify(params),
   *   }).then(r => r.json())
   * });
   *
   * // Full control
   * const capsule = new CapsuleClient({
   *   keySize: 4096,
   *   autoProcess: true,
   *   executeScripts: false,
   *   contentKeyStorage: 'session',
   *   renewBuffer: 10000,
   * });
   * ```
   */
  constructor(options: CapsuleClientOptions = {}) {
    this.keySize = options.keySize ?? 2048;
    this.unlockFn = options.unlock;
    this.autoProcess = options.autoProcess ?? false;
    this.executeScripts = options.executeScripts ?? true;
    this.selector = options.selector ?? DEFAULT_SELECTOR;
    this.contentKeyStorage = options.contentKeyStorage ?? "persist";
    this.renewBuffer = options.renewBuffer ?? 5000;
    this.logger = options.logger;
    this.storage = new KeyStorage(options.dbName, options.storeName);

    // Auto-process on init if enabled
    if (this.autoProcess && typeof document !== "undefined") {
      // Wait for DOM to be ready
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => this.processAll());
      } else {
        // Use microtask to allow event listeners to be set up
        queueMicrotask(() => this.processAll());
      }
    }
  }

  // =========================================================================
  // Public API - High Level
  // =========================================================================

  /**
   * Get the public key, creating a new key pair if needed.
   * This is the main entry point - keys are auto-created on first call.
   *
   * @returns Base64-encoded SPKI public key
   *
   * @example
   * ```ts
   * const publicKey = await capsule.getPublicKey();
   * // Send to server for key registration
   * ```
   */
  async getPublicKey(): Promise<string> {
    const keyPair = await this.ensureKeyPair();
    const publicKeySpki = await crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey,
    );
    return this.arrayBufferToBase64(publicKeySpki);
  }

  /**
   * Unlock an encrypted element on the page by article ID.
   * Finds the element, fetches the content key (using unlock function), decrypts, and renders.
   *
   * @param resourceId - The resource ID to unlock
   * @returns The decrypted content string
   * @throws Error if element not found, no unlock function, or decryption fails
   *
   * @example
   * ```ts
   * // Element: <div data-capsule='{"resourceId":"abc",...}'></div>
   * const content = await capsule.unlockElement('abc');
   * ```
   */
  async unlockElement(resourceId: string): Promise<string> {
    const element = this.findElement(resourceId);
    if (!element) {
      throw new Error(`No encrypted element found for article "${resourceId}"`);
    }

    return this.processElement(element);
  }

  /**
   * Process all encrypted elements on the page.
   * Elements must have the data-capsule attribute with JSON EncryptedArticle data.
   *
   * @returns Map of resourceId to decrypted content (or error)
   *
   * @example
   * ```ts
   * const results = await capsule.processAll();
   * for (const [id, result] of results) {
   *   if (result instanceof Error) {
   *     console.error(`Failed to unlock ${id}:`, result);
   *   } else {
   *     console.log(`Unlocked ${id}:`, result.substring(0, 50));
   *   }
   * }
   * ```
   */
  async processAll(): Promise<Map<string, string | Error>> {
    const results = new Map<string, string | Error>();
    const elements = document.querySelectorAll<HTMLElement>(this.selector);

    for (let i = 0; i < elements.length; i++) {
      const element = elements[i]!;
      try {
        const data = this.parseElementData(element);
        if (data) {
          const content = await this.processElement(element);
          results.set(data.resourceId, content);
        }
      } catch (err) {
        const resourceId = element.dataset.capsuleId || "unknown";
        results.set(
          resourceId,
          err instanceof Error ? err : new Error(String(err)),
        );
      }
    }

    return results;
  }

  /**
   * Unlock content using a pre-signed share token.
   *
   * This is used for share links (social media, email, etc.) where
   * the user doesn't need to be authenticated. The token proves
   * access was granted by the publisher.
   *
   * @param article - The encrypted article data
   * @param token - Pre-signed share token from the URL
   * @returns Decrypted content string
   *
   * @example
   * ```ts
   * // Get token from URL
   * const params = new URLSearchParams(window.location.search);
   * const token = params.get('token');
   *
   * if (token) {
   *   const content = await capsule.unlockWithToken(article, token);
   * }
   * ```
   */
  async unlockWithToken(
    article: EncryptedArticle,
    token: string,
  ): Promise<string> {
    if (!this.unlockFn) {
      throw new Error(
        "No unlock function provided. Pass an unlock function to the constructor.",
      );
    }

    const keyPair = await this.ensureKeyPair();
    const publicKey = await this.getPublicKey();

    // Use the first shared key's wrappedContentKey (token-based unlock doesn't need keyId)
    const sharedKey = article.wrappedKeys.find(
      (k) => !k.keyId.startsWith("article:"),
    );
    if (!sharedKey) {
      throw new Error("No shared key found in article for token-based unlock");
    }

    const response = await this.unlockFn({
      keyId: sharedKey.keyId,
      wrappedContentKey: sharedKey.wrappedContentKey,
      publicKey,
      resourceId: article.resourceId,
      token,
    });

    const contentKey = await this.unwrapContentKey(keyPair.privateKey, response.encryptedContentKey);

    // Cache the content key for future use
    await this.cacheContentKey(sharedKey.keyId, contentKey, response);

    this.log(
      `Unlocked ${article.resourceId} with token ${response.tokenId || "unknown"
      }`,
      "info",
    );

    return await this.decryptWithContentKey(article, contentKey);
  }

  /**
   * Decrypt content using cached content key or by fetching a new one.
   * This is the main decryption method that handles the full flow.
   *
   * For shared keys, this automatically:
   * 1. Checks for a cached shared key and unwraps content keys locally (zero network)
   * 2. Falls back to fetching a shared key from the server
   * 3. Caches the shared key so subsequent articles decrypt locally
   *
   * @param article - The encrypted article data
   * @param preferredKeyType - Prefer 'shared' or 'article' keys (default: shared)
   * @returns Decrypted content string
   *
   * @example
   * ```ts
   * const article = JSON.parse(element.dataset.capsule);
   * const content = await capsule.unlock(article);
   * ```
   */
  async unlock(
    article: EncryptedArticle,
    preferredKeyType: "shared" | "article" = "shared",
  ): Promise<string> {
    const keyPair = await this.ensureKeyPair();

    // Sort wrapped keys by preference
    const sortedKeys = this.sortKeysByPreference(
      article.wrappedKeys,
      preferredKeyType,
    );

    // 1. Try locally with cached shared keys (fastest: zero network, zero I/O)
    for (const wrappedKey of sortedKeys) {
      const content = await this.tryLocalSharedUnwrap(article, wrappedKey);
      if (content !== null) return content;
    }

    // 2. Try cached content keys (from persistent storage)
    for (const wrappedKey of sortedKeys) {
      const cached = await this.getCachedContentKey(wrappedKey.keyId);
      if (cached) {
        this.log(`Using cached content key for ${wrappedKey.keyId}`, "debug");
        try {
          return await this.decryptWithContentKey(article, cached.contentKey);
        } catch {
          // Cache might be stale, continue
          this.log(
            `Cached content key failed for ${wrappedKey.keyId}, trying next`,
            "debug",
          );
        }
      }
    }

    // 3. Need to fetch from server
    if (!this.unlockFn) {
      throw new Error(
        "No unlock function provided. Either pass an unlock function to the constructor, " +
        "or use decrypt() with a pre-fetched encryptedContentKey.",
      );
    }

    // Try each key until one works
    for (const wrappedKey of sortedKeys) {
      try {
        const publicKey = await this.getPublicKey();
        const parsed = this.parseKeyId(wrappedKey.keyId);

        const response = await this.unlockFn({
          keyId: wrappedKey.keyId,
          wrappedContentKey: wrappedKey.wrappedContentKey,
          publicKey,
          resourceId: article.resourceId,
          // Request shared key when appropriate
          ...(parsed.type === "shared" ? { mode: "shared" as const } : {}),
        });

        if (response.keyType === "kek") {
          // Shared key response: unwrap the KEK, cache it, and locally unwrap the content key
          const sharedKey = await this.unwrapContentKey(
            keyPair.privateKey,
            response.encryptedContentKey,
          );
          this.cacheSharedKey(parsed.baseId, sharedKey, response);

          const contentKey = await this.localUnwrapContentKey(
            wrappedKey.wrappedContentKey,
            sharedKey,
          );
          this.log(
            `Shared key '${parsed.baseId}' cached, article unlocked locally`,
            "info",
          );
          return await this.decryptWithContentKey(article, contentKey);
        }

        // DEK response (standard per-article flow)
        const contentKey = await this.unwrapContentKey(
          keyPair.privateKey,
          response.encryptedContentKey,
        );
        await this.cacheContentKey(wrappedKey.keyId, contentKey, response);

        return await this.decryptWithContentKey(article, contentKey);
      } catch (err) {
        this.log(`Failed to unlock with ${wrappedKey.keyId}: ${err}`, "debug");
        continue;
      }
    }

    throw new Error("Failed to unlock content with any available key");
  }

  /**
   * Try to unlock content using only locally-cached keys (no server call).
   *
   * Returns the decrypted content if a valid cached key is found, or `null`
   * if no cached key is available. This is useful for restoring previously
   * unlocked content on page load without triggering a server round-trip.
   *
   * Checks:
   * 1. In-memory shared key cache (fastest)
   * 2. Persistent content key storage (IndexedDB)
   *
   * @param article - The encrypted article data
   * @param preferredKeyType - Which key type to try first (default: "shared")
   * @returns Decrypted content string, or `null` if no cached key works
   *
   * @example
   * ```ts
   * const cached = await capsule.tryUnlockFromCache(article);
   * if (cached) {
   *   showContent(cached);
   * } else {
   *   showPaywall();
   * }
   * ```
   */
  async tryUnlockFromCache(
    article: EncryptedArticle,
    preferredKeyType: "shared" | "article" = "shared",
  ): Promise<string | null> {
    this._expiredKeyIds = new Set();
    this._lastContentKeyIds = new Set(
      article.wrappedKeys.map((wk) => wk.keyId),
    );
    const keyPair = await this.ensureKeyPair();

    const sortedKeys = this.sortKeysByPreference(
      article.wrappedKeys,
      preferredKeyType,
    );

    // 0. Hydrate in-memory shared key cache from IndexedDB (survives page reload)
    await this.loadPersistedSharedKeys(keyPair.privateKey);

    // 1. Try locally with cached shared keys (in-memory, now hydrated)
    for (const wrappedKey of sortedKeys) {
      const content = await this.tryLocalSharedUnwrap(article, wrappedKey);
      if (content !== null) {
        this.log(`Unlocked from cached shared key for ${wrappedKey.keyId}`, "debug");
        return content;
      }
    }

    // 2. Try cached content keys (from persistent storage)
    for (const wrappedKey of sortedKeys) {
      const cached = await this.getCachedContentKey(wrappedKey.keyId);
      if (cached) {
        try {
          const content = await this.decryptWithContentKey(article, cached.contentKey);
          this.log(`Unlocked from cached content key for ${wrappedKey.keyId}`, "debug");
          return content;
        } catch {
          this.log(
            `Cached content key failed for ${wrappedKey.keyId}, trying next`,
            "debug",
          );
        }
      }
    }

    // No cached keys available — do NOT call the server
    return null;
  }

  /**
   * Returns true if `tryUnlockFromCache` encountered expired keys that belonged
   * to the article it was called with. Use this to distinguish "first visit"
   * (no keys) from "returning user with expired keys" so the UI can auto-renew.
   *
   * Must be called after `tryUnlockFromCache()`.
   */
  get hadExpiredKeys(): boolean {
    // Check if any expired key matches the article's wrapped key IDs.
    // For shared keys, match on content ID (baseId) since the period changes on renewal.
    for (const expiredId of this._expiredKeyIds) {
      // Direct match (same keyId)
      if (this._lastContentKeyIds.has(expiredId)) return true;

      // Shared key: match if same content ID (e.g. expired "premium:111" matches article's "premium:222")
      if (!expiredId.startsWith("article:")) {
        const expiredShared = expiredId.split(":")[0];
        for (const contentKeyId of this._lastContentKeyIds) {
          if (!contentKeyId.startsWith("article:") && contentKeyId.split(":")[0] === expiredShared) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /**
   * Returns the key type ("shared" or "article") of the expired keys found for
   * the last article passed to `tryUnlockFromCache()`. Useful for renewing
   * with the same key type the user originally used.
   *
   * Returns null if no relevant expired keys were found.
   */
  get expiredKeyType(): "shared" | "article" | null {
    for (const expiredId of this._expiredKeyIds) {
      const isShared = !expiredId.startsWith("article:");

      // Direct match
      if (this._lastContentKeyIds.has(expiredId)) {
        return isShared ? "shared" : "article";
      }

      // Shared: match on content ID
      if (isShared) {
        const expiredShared = expiredId.split(":")[0];
        for (const contentKeyId of this._lastContentKeyIds) {
          if (!contentKeyId.startsWith("article:") && contentKeyId.split(":")[0] === expiredShared) {
            return "shared";
          }
        }
      }
    }
    return null;
  }

  /**
   * Pre-fetch and cache a shared key-wrapping key for local DEK unwrapping.
   *
   * After calling this, all articles encrypted for this content ID can be unlocked
   * locally without additional server round-trips (until the period expires).
   *
   * This is optional — `unlock()` automatically requests and caches shared keys.
   * Use this to pre-warm the cache before processing multiple articles.
   *
   * @param keyId - Full key ID including period (e.g., "premium:123456")
   * @returns Expiration info for the cached shared key
   *
   * @example
   * ```ts
   * // Pre-fetch shared key from first article's wrappedKeys
   * const sharedKeyId = articles[0].wrappedKeys.find(k => !k.keyId.startsWith('article:'))?.keyId;
   * if (sharedKeyId) {
   *   await capsule.prefetchSharedKey(sharedKeyId);
   * }
   * // Now all unlocks for this content ID are local
   * for (const article of articles) {
   *   await capsule.unlock(article);
   * }
   * ```
   */
  async prefetchSharedKey(
    keyId: string,
  ): Promise<{ expiresAt: number; periodId: string }> {
    if (!this.unlockFn) {
      throw new Error(
        "No unlock function provided. Pass an unlock function to the constructor.",
      );
    }

    const parsed = this.parseKeyId(keyId);

    // Check if already cached and valid
    const existing = this.sharedKeyCache.get(parsed.baseId);
    if (existing && existing.expiresAt > Date.now()) {
      return { expiresAt: existing.expiresAt, periodId: existing.periodId };
    }

    const keyPair = await this.ensureKeyPair();
    const publicKey = await this.getPublicKey();

    const response = await this.unlockFn({
      keyId,
      wrappedContentKey: "",
      publicKey,
      resourceId: "",
      mode: "shared",
    });

    if (response.keyType !== "kek") {
      throw new Error(
        "Server did not return a shared key (expected keyType 'kek')",
      );
    }

    const sharedKey = await this.unwrapContentKey(
      keyPair.privateKey,
      response.encryptedContentKey,
    );
    this.cacheSharedKey(parsed.baseId, sharedKey, response);

    const expiresAt =
      typeof response.expiresAt === "string"
        ? new Date(response.expiresAt).getTime()
        : response.expiresAt;

    this.log(
      `Pre-fetched shared key '${parsed.baseId}', expires ${new Date(expiresAt).toISOString()}`,
      "info",
    );
    return { expiresAt, periodId: response.periodId || "" };
  }

  // =========================================================================
  // Public API - Low Level
  // =========================================================================

  /**
   * Decrypt content with a pre-fetched encrypted DEK.
   * Use this for full manual control over the unlock flow.
   *
   * @param article - The encrypted article data
   * @param encryptedContentKey - Base64-encoded DEK encrypted with user's public key
   * @returns Decrypted content string
   *
   * @example
   * ```ts
   * // Manual flow
   * const publicKey = await capsule.getPublicKey();
   * const { encryptedContentKey } = await myServerCall(publicKey, article.wrappedKeys[0]);
   * const content = await capsule.decrypt(article, encryptedContentKey);
   * ```
   */
  async decrypt(
    article: EncryptedArticle,
    encryptedContentKey: string,
  ): Promise<string> {
    const keyPair = await this.ensureKeyPair();
    const contentKey = await this.unwrapContentKey(keyPair.privateKey, encryptedContentKey);
    return this.decryptWithContentKey(article, contentKey);
  }

  /**
   * Decrypt a simple encrypted payload (single key, no envelope).
   * For simpler use cases without multi-key support.
   *
   * @param payload - Simple encrypted payload
   * @returns Decrypted content string
   */
  async decryptPayload(payload: EncryptedPayload): Promise<string> {
    const keyPair = await this.ensureKeyPair();
    const contentKey = await this.unwrapContentKey(keyPair.privateKey, payload.encryptedContentKey);

    const iv = this.base64ToArrayBuffer(payload.iv);
    const ciphertext = this.base64ToArrayBuffer(payload.encryptedContent);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      contentKey,
      ciphertext,
    );

    return new TextDecoder().decode(decrypted);
  }

  /**
   * Check if a key pair exists in storage.
   */
  async hasKeyPair(): Promise<boolean> {
    return this.storage.hasKeyPair(DEFAULT_KEY_ID);
  }

  /**
   * Get info about the stored key pair.
   */
  async getKeyInfo(): Promise<{ keySize: number; createdAt: number } | null> {
    const keyPair = await this.storage.getKeyPair(DEFAULT_KEY_ID);
    if (!keyPair) return null;

    return {
      keySize: keyPair.keySize,
      createdAt: keyPair.createdAt,
    };
  }

  /**
   * Generate a new key pair, replacing any existing one.
   * Usually not needed - getPublicKey() auto-creates keys.
   *
   * @returns Base64-encoded SPKI public key
   */
  async regenerateKeyPair(): Promise<string> {
    await this.storage.deleteKeyPair(DEFAULT_KEY_ID);
    this.keyPairPromise = null;
    this.contentKeyCache.clear();
    this.sharedKeyCache.clear();
    return this.getPublicKey();
  }

  /**
   * Clear all stored keys and cached content keys.
   */
  async clearAll(): Promise<void> {
    await this.storage.clearAll();
    this.keyPairPromise = null;
    this.contentKeyCache.clear();
    this.sharedKeyCache.clear();
    this.clearAllRenewalTimers();

    // Clear persisted DEKs
    if (this.contentKeyStorage === "persist") {
      // Clear from IndexedDB
      const db = await this.openContentKeyDb();
      await this.clearContentKeyStore(db);
    } else if (this.contentKeyStorage === "session") {
      // Clear from sessionStorage
      const keys = Object.keys(sessionStorage).filter((k) =>
        k.startsWith(CONTENT_KEY_STORAGE_PREFIX),
      );
      keys.forEach((k) => sessionStorage.removeItem(k));
    }
  }

  /**
   * Get the current state of an element.
   */
  getElementState(resourceId: string): ElementState | undefined {
    return this.elementStates.get(resourceId);
  }

  // =========================================================================
  // Element Processing
  // =========================================================================

  /**
   * Process a single encrypted element.
   */
  private async processElement(element: HTMLElement): Promise<string> {
    const data = this.parseElementData(element);
    if (!data) {
      throw new Error("Element has no valid encrypted data");
    }

    const resourceId = data.resourceId;
    this.setElementState(element, resourceId, "unlocking");

    try {
      // Unlock and get content
      const content = await this.unlock(data);

      // Render content into element
      this.renderContent(element, content, resourceId);
      this.setElementState(element, resourceId, "unlocked");

      // Emit unlock event
      this.emitEvent(element, "capsule:unlock", {
        resourceId,
        element,
        keyId: data.wrappedKeys[0]?.keyId || "unknown",
        content,
      } satisfies CapsuleUnlockEvent);

      return content;
    } catch (err) {
      this.setElementState(element, resourceId, "error");

      // Emit error event
      this.emitEvent(element, "capsule:error", {
        resourceId,
        element,
        error: err instanceof Error ? err : new Error(String(err)),
      } satisfies CapsuleErrorEvent);

      throw err;
    }
  }

  /**
   * Find an encrypted element by article ID.
   */
  private findElement(resourceId: string): HTMLElement | null {
    // Try data-capsule-id first
    let element = document.querySelector<HTMLElement>(
      `[data-capsule-id="${resourceId}"]`,
    );
    if (element) return element;

    // Try id attribute
    element = document.getElementById(resourceId);
    if (element?.hasAttribute("data-capsule")) return element;

    // Search all encrypted elements for matching resourceId
    const elements = document.querySelectorAll<HTMLElement>(this.selector);
    for (let i = 0; i < elements.length; i++) {
      const el = elements[i]!;
      try {
        const data = this.parseElementData(el);
        if (data?.resourceId === resourceId) return el;
      } catch {
        continue;
      }
    }

    return null;
  }

  /**
   * Parse encrypted data from an element.
   */
  private parseElementData(element: HTMLElement): EncryptedArticle | null {
    const json = element.dataset.capsule;
    if (!json) return null;

    try {
      return JSON.parse(json) as EncryptedArticle;
    } catch {
      this.log(`Failed to parse encrypted data from element`, "error");
      return null;
    }
  }

  /**
   * Render decrypted content into an element.
   */
  private renderContent(
    element: HTMLElement,
    content: string,
    resourceId: string,
  ): void {
    // Set the HTML content
    element.innerHTML = content;

    // Mark as unlocked
    element.dataset.capsuleUnlocked = "true";
    delete element.dataset.capsule; // Remove encrypted data

    // Execute scripts if enabled
    if (this.executeScripts) {
      this.executeEmbeddedScripts(element);
    }

    this.log(`Rendered content for ${resourceId}`, "info");
  }

  /**
   * Execute script tags found in decrypted content.
   */
  private executeEmbeddedScripts(container: HTMLElement): void {
    const scripts = container.querySelectorAll("script");

    scripts.forEach((oldScript) => {
      const newScript = document.createElement("script");

      // Copy attributes
      Array.from(oldScript.attributes).forEach((attr) => {
        newScript.setAttribute(attr.name, attr.value);
      });

      // Copy content
      newScript.textContent = oldScript.textContent;

      // Replace old script with new one to execute it
      oldScript.parentNode?.replaceChild(newScript, oldScript);
    });

    this.log(`Executed ${scripts.length} embedded scripts`, "debug");
  }

  /**
   * Set element state and emit state change event.
   */
  private setElementState(
    element: HTMLElement,
    resourceId: string,
    state: ElementState,
  ): void {
    const previousState = this.elementStates.get(resourceId) || "locked";
    this.elementStates.set(resourceId, state);

    // Update element data attribute
    element.dataset.capsuleState = state;

    // Emit state change event
    if (previousState !== state) {
      this.emitEvent(element, "capsule:state", {
        resourceId,
        element,
        previousState,
        state,
      } satisfies CapsuleStateEvent);
    }
  }

  /**
   * Emit a custom event on an element and document.
   */
  private emitEvent<T>(
    element: HTMLElement,
    eventName: string,
    detail: T,
  ): void {
    const event = new CustomEvent(eventName, {
      detail,
      bubbles: true,
      cancelable: true,
    });

    element.dispatchEvent(event);
  }

  // =========================================================================
  // Key Management
  // =========================================================================

  /**
   * Ensure a key pair exists, creating one if needed.
   */
  private async ensureKeyPair(): Promise<StoredKeyPair> {
    if (!this.keyPairPromise) {
      this.keyPairPromise = this.loadOrCreateKeyPair();
    }
    return this.keyPairPromise;
  }

  /**
   * Load existing key pair or create a new one.
   */
  private async loadOrCreateKeyPair(): Promise<StoredKeyPair> {
    const existing = await this.storage.getKeyPair(DEFAULT_KEY_ID);
    if (existing) {
      this.log("Loaded existing key pair from storage", "debug");
      return existing;
    }

    this.log(`Generating new RSA-${this.keySize} key pair`, "info");

    // Generate RSA-OAEP key pair
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: this.keySize,
        publicExponent: RSA_PUBLIC_EXPONENT,
        hash: "SHA-256",
      },
      true, // Need extractable for public key export
      ["wrapKey", "unwrapKey"],
    );

    // Re-import private key as non-extractable
    const privateKeyJwk = await crypto.subtle.exportKey(
      "jwk",
      keyPair.privateKey,
    );
    const nonExtractablePrivateKey = await crypto.subtle.importKey(
      "jwk",
      privateKeyJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false, // NOT extractable
      ["unwrapKey"],
    );

    // Store
    await this.storage.storeKeyPair(
      DEFAULT_KEY_ID,
      keyPair.publicKey,
      nonExtractablePrivateKey,
      this.keySize,
    );

    this.log("Key pair generated and stored", "info");

    return {
      id: DEFAULT_KEY_ID,
      publicKey: keyPair.publicKey,
      privateKey: nonExtractablePrivateKey,
      createdAt: Date.now(),
      keySize: this.keySize,
    };
  }

  // =========================================================================
  // DEK Management
  // =========================================================================

  /**
   * Sort wrapped keys by preference.
   */
  private sortKeysByPreference(
    keys: WrappedKey[],
    preferredType: "shared" | "article",
  ): WrappedKey[] {
    const parseKeyType = (keyId: string): "shared" | "article" => {
      return keyId.startsWith("article:") ? "article" : "shared";
    };

    return [...keys].sort((a, b) => {
      const typeA = parseKeyType(a.keyId);
      const typeB = parseKeyType(b.keyId);

      if (typeA === preferredType && typeB !== preferredType) return -1;
      if (typeA !== preferredType && typeB === preferredType) return 1;
      return 0;
    });
  }

  // =========================================================================
  // Shared Key Management (local DEK unwrapping)
  // =========================================================================

  /**
   * Try to unwrap an article's content key locally using a cached shared key.
   * Returns decrypted content on success, null if not possible.
   */
  private async tryLocalSharedUnwrap(
    article: EncryptedArticle,
    wrappedKey: WrappedKey,
  ): Promise<string | null> {
    const parsed = this.parseKeyId(wrappedKey.keyId);
    if (parsed.type !== "shared") return null;

    const cached = this.sharedKeyCache.get(parsed.baseId);
    if (!cached || cached.expiresAt <= Date.now()) return null;

    // Extract periodId from keyId (e.g., "premium:123456" → "123456")
    const colonIdx = wrappedKey.keyId.lastIndexOf(":");
    const periodId =
      colonIdx > 0 ? wrappedKey.keyId.substring(colonIdx + 1) : null;
    if (!periodId || cached.periodId !== periodId) return null;

    try {
      const contentKey = await this.localUnwrapContentKey(wrappedKey.wrappedContentKey, cached.key);
      this.log(
        `Local shared unwrap for '${parsed.baseId}:${periodId}'`,
        "debug",
      );
      return await this.decryptWithContentKey(article, contentKey);
    } catch {
      this.log(
        `Local shared unwrap failed for '${parsed.baseId}:${periodId}'`,
        "debug",
      );
      return null;
    }
  }

  /**
   * Locally unwrap a content key using a shared key (AES-GCM).
   *
   * The wrappedContentKey format is: IV (12 bytes) + AES-GCM(DEK + auth tag).
   * This mirrors the server-side wrapContentKey/unwrapContentKey from @sesamy/capsule-server.
   */
  private async localUnwrapContentKey(
    wrappedContentKeyB64: string,
    sharedKey: CryptoKey,
  ): Promise<CryptoKey> {
    const wrappedBytes = this.base64ToArrayBuffer(wrappedContentKeyB64) as Uint8Array;

    // Split: first 12 bytes = IV, rest = AES-GCM ciphertext (content key + auth tag)
    const iv = wrappedBytes.slice(0, GCM_IV_BYTES);
    const ciphertext = wrappedBytes.slice(GCM_IV_BYTES);

    // Decrypt the wrapped content key with the shared key
    const contentKeyBytes = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      sharedKey,
      ciphertext,
    );

    // Import the raw content key as a CryptoKey for content decryption
    return crypto.subtle.importKey(
      "raw",
      contentKeyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  }

  /**
   * Cache a shared key in memory and persist to IndexedDB.
   */
  private cacheSharedKey(
    contentId: string,
    key: CryptoKey,
    response: UnlockResponse,
  ): void {
    const expiresAt =
      typeof response.expiresAt === "string"
        ? new Date(response.expiresAt).getTime()
        : response.expiresAt;
    const periodId = response.periodId || "";

    this.sharedKeyCache.set(contentId, { key, periodId, expiresAt });
    this.scheduleSharedKeyRenewal(contentId, expiresAt);

    // Persist to IndexedDB so the shared key survives page reloads.
    // Stored as a StoredContentKey with an IndexedDB key of "kek:<contentId>:<periodId>".
    const info: StoredContentKey = {
      type: "shared",
      baseId: contentId,
      encryptedContentKey: response.encryptedContentKey,
      expiresAt,
      periodId,
    };
    const storeKey = `kek:${contentId}:${periodId}`;

    // Remove old shared key entries for this content ID, then store the new one
    this.replaceOldSharedKeys(contentId, storeKey, info).catch(() => {
      // Non-critical — worst case the user re-fetches on next page load
    });
  }

  /**
   * Remove old kek entries for a content ID and store the new one.
   */
  private async replaceOldSharedKeys(
    contentId: string,
    newStoreKey: string,
    newInfo: StoredContentKey,
  ): Promise<void> {
    const db = await this.openContentKeyDb();
    const allKeys = await this.getAllContentKeysFromStore(db);
    const prefix = `kek:${contentId}:`;

    for (const { key: storeKey } of allKeys) {
      if (typeof storeKey === "string" && storeKey.startsWith(prefix) && storeKey !== newStoreKey) {
        await this.deleteContentKeyFromStore(db, storeKey);
        this.log(`Removed expired shared key: ${storeKey}`, "debug");
      }
    }

    await this.putContentKeyToStore(db, newStoreKey, newInfo);
  }

  /**
   * Load persisted shared keys from IndexedDB into the in-memory sharedKeyCache.
   * Called by tryUnlockFromCache to restore keys that survived a page reload.
   */
  private async loadPersistedSharedKeys(privateKey: CryptoKey): Promise<void> {
    if (this.contentKeyStorage === "memory") return;

    try {
      const db = await this.openContentKeyDb();
      const allKeys = await this.getAllContentKeysFromStore(db);

      for (const { key: storeKey, value: stored } of allKeys) {
        // Only process shared key entries (stored with "kek:" prefix)
        if (typeof storeKey !== "string" || !storeKey.startsWith("kek:")) continue;
        if (stored.type !== "shared") continue;

        // Clean up expired entries from IndexedDB
        if (stored.expiresAt <= Date.now()) {
          // Record the original keyId (contentId:periodId format) for this expired shared key
          const expiredKeyId = `${stored.baseId}:${stored.periodId || ""}`;
          this._expiredKeyIds.add(expiredKeyId);
          this.deleteContentKeyFromStore(db, storeKey as string).catch(() => { });
          this.log(`Removed expired shared key: ${storeKey}`, "debug");
          continue;
        }

        // Skip if already in memory cache
        if (this.sharedKeyCache.has(stored.baseId)) {
          const existing = this.sharedKeyCache.get(stored.baseId)!;
          if (existing.expiresAt > Date.now()) continue;
        }

        // Unwrap the RSA-encrypted shared key
        try {
          const sharedKey = await this.unwrapContentKey(privateKey, stored.encryptedContentKey);
          this.sharedKeyCache.set(stored.baseId, {
            key: sharedKey,
            periodId: stored.periodId || "",
            expiresAt: stored.expiresAt,
          });
          this.scheduleSharedKeyRenewal(stored.baseId, stored.expiresAt);
          this.log(`Restored shared key '${stored.baseId}' from IndexedDB`, "debug");
        } catch {
          // Key may be stale or for a different RSA key — ignore
        }
      }
    } catch {
      // IndexedDB may not be available — non-critical
    }
  }

  /**
   * Read all entries from the content-keys object store.
   */
  private getAllContentKeysFromStore(
    db: IDBDatabase,
  ): Promise<Array<{ key: IDBValidKey; value: StoredContentKey }>> {
    return new Promise((resolve) => {
      const tx = db.transaction("content-keys", "readonly");
      const store = tx.objectStore("content-keys");
      const results: Array<{ key: IDBValidKey; value: StoredContentKey }> = [];
      const cursorReq = store.openCursor();
      cursorReq.onsuccess = () => {
        const cursor = cursorReq.result;
        if (cursor) {
          results.push({ key: cursor.key, value: cursor.value });
          cursor.continue();
        } else {
          resolve(results);
        }
      };
      cursorReq.onerror = () => resolve([]);
    });
  }

  /**
   * Schedule auto-expiry for a cached shared key.
   */
  private scheduleSharedKeyRenewal(contentId: string, expiresAt: number): void {
    if (this.renewBuffer <= 0) return;

    const existingTimer = this.sharedRenewalTimers.get(contentId);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    const timeUntilExpiry = expiresAt - Date.now() - this.renewBuffer;
    if (timeUntilExpiry <= 0) return;

    const timer = window.setTimeout(() => {
      this.sharedKeyCache.delete(contentId);
      this.sharedRenewalTimers.delete(contentId);
      this.log(`Shared key '${contentId}' expired, cleared from cache`, "debug");
    }, timeUntilExpiry);

    this.sharedRenewalTimers.set(contentId, timer);
  }

  /**
   * Get cached content key for a key ID.
   */
  private async getCachedContentKey(
    keyId: string,
  ): Promise<{ contentKey: CryptoKey; info: StoredContentKey } | null> {
    // Check memory cache first
    const memCached = this.contentKeyCache.get(keyId);
    if (memCached && memCached.info.expiresAt > Date.now()) {
      return memCached;
    }

    // Check persistent storage
    const stored = await this.loadStoredContentKey(keyId);
    if (!stored || stored.expiresAt <= Date.now()) {
      // Remove expired entry from persistent storage
      if (stored && stored.expiresAt <= Date.now()) {
        this._expiredKeyIds.add(keyId);
        this.removeStoredContentKey(keyId).catch(() => { });
      }
      return null;
    }

    // Unwrap and cache in memory
    const keyPair = await this.ensureKeyPair();
    try {
      const contentKey = await this.unwrapContentKey(keyPair.privateKey, stored.encryptedContentKey);
      this.contentKeyCache.set(keyId, { contentKey, info: stored });
      this.scheduleRenewal(keyId, stored);
      return { contentKey, info: stored };
    } catch {
      return null;
    }
  }

  /**
   * Cache a content key after fetching.
   */
  private async cacheContentKey(
    keyId: string,
    contentKey: CryptoKey,
    response: UnlockResponse,
  ): Promise<void> {
    const expiresAt =
      typeof response.expiresAt === "string"
        ? new Date(response.expiresAt).getTime()
        : response.expiresAt;

    const parsed = this.parseKeyId(keyId);
    const info: StoredContentKey = {
      type: parsed.type,
      baseId: parsed.baseId,
      encryptedContentKey: response.encryptedContentKey,
      expiresAt,
      periodId: response.periodId,
    };

    // Memory cache
    this.contentKeyCache.set(keyId, { contentKey, info });

    // Persistent storage
    await this.storeStoredContentKey(keyId, info);

    // Schedule renewal
    this.scheduleRenewal(keyId, info);

    this.log(
      `Cached content key for ${keyId}, expires ${new Date(expiresAt).toISOString()}`,
      "debug",
    );
  }

  /**
   * Parse a key ID into type and base ID.
   */
  private parseKeyId(keyId: string): {
    type: "shared" | "article";
    baseId: string;
  } {
    if (keyId.startsWith("article:")) {
      return { type: "article", baseId: keyId.slice(8) };
    }
    // Shared format: "contentId:periodId" or just "contentId"
    const colonIdx = keyId.indexOf(":");
    if (colonIdx > 0) {
      return { type: "shared", baseId: keyId.slice(0, colonIdx) };
    }
    return { type: "shared", baseId: keyId };
  }

  /**
   * Schedule auto-renewal for a content key.
   */
  private scheduleRenewal(keyId: string, info: StoredContentKey): void {
    if (this.renewBuffer <= 0) return;

    // Clear existing timer
    const existingTimer = this.renewalTimers.get(keyId);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    const timeUntilRenewal = info.expiresAt - Date.now() - this.renewBuffer;
    if (timeUntilRenewal <= 0) return;

    const timer = window.setTimeout(async () => {
      this.log(`Auto-renewing content key for ${keyId}`, "debug");
      // DEK will be refreshed on next decrypt attempt
      this.contentKeyCache.delete(keyId);
      this.renewalTimers.delete(keyId);
    }, timeUntilRenewal);

    this.renewalTimers.set(keyId, timer);
  }

  /**
   * Clear all renewal timers.
   */
  private clearAllRenewalTimers(): void {
    for (const timer of this.renewalTimers.values()) {
      clearTimeout(timer);
    }
    this.renewalTimers.clear();
    for (const timer of this.sharedRenewalTimers.values()) {
      clearTimeout(timer);
    }
    this.sharedRenewalTimers.clear();
  }

  // =========================================================================
  // DEK Persistence
  // =========================================================================

  private async loadStoredContentKey(keyId: string): Promise<StoredContentKey | null> {
    if (this.contentKeyStorage === "memory") {
      return null; // Memory-only, no persistence
    }

    if (this.contentKeyStorage === "session") {
      const json = sessionStorage.getItem(CONTENT_KEY_STORAGE_PREFIX + keyId);
      return json ? JSON.parse(json) : null;
    }

    // persist mode - use IndexedDB
    const db = await this.openContentKeyDb();
    return this.getContentKeyFromStore(db, keyId);
  }

  private async storeStoredContentKey(keyId: string, info: StoredContentKey): Promise<void> {
    if (this.contentKeyStorage === "memory") {
      return; // Memory-only
    }

    if (this.contentKeyStorage === "session") {
      sessionStorage.setItem(CONTENT_KEY_STORAGE_PREFIX + keyId, JSON.stringify(info));
      return;
    }

    // persist mode - use IndexedDB
    const db = await this.openContentKeyDb();
    await this.putContentKeyToStore(db, keyId, info);
  }

  private async removeStoredContentKey(keyId: string): Promise<void> {
    if (this.contentKeyStorage === "memory") return;

    if (this.contentKeyStorage === "session") {
      sessionStorage.removeItem(CONTENT_KEY_STORAGE_PREFIX + keyId);
      return;
    }

    const db = await this.openContentKeyDb();
    await this.deleteContentKeyFromStore(db, keyId);
  }

  private contentKeyDbPromise: Promise<IDBDatabase> | null = null;

  private async openContentKeyDb(): Promise<IDBDatabase> {
    if (this.contentKeyDbPromise) return this.contentKeyDbPromise;

    this.contentKeyDbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open("capsule-content-keys", 1);
      request.onerror = () => reject(request.error);
      request.onupgradeneeded = () => {
        request.result.createObjectStore("content-keys");
      };
      request.onsuccess = () => resolve(request.result);
    });

    return this.contentKeyDbPromise;
  }

  private getContentKeyFromStore(
    db: IDBDatabase,
    keyId: string,
  ): Promise<StoredContentKey | null> {
    return new Promise((resolve, reject) => {
      const tx = db.transaction("content-keys", "readonly");
      const store = tx.objectStore("content-keys");
      const request = store.get(keyId);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  private putContentKeyToStore(
    db: IDBDatabase,
    keyId: string,
    info: StoredContentKey,
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = db.transaction("content-keys", "readwrite");
      const store = tx.objectStore("content-keys");
      const request = store.put(info, keyId);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  private deleteContentKeyFromStore(db: IDBDatabase, keyId: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = db.transaction("content-keys", "readwrite");
      const store = tx.objectStore("content-keys");
      const request = store.delete(keyId);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  private clearContentKeyStore(db: IDBDatabase): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = db.transaction("content-keys", "readwrite");
      const store = tx.objectStore("content-keys");
      const request = store.clear();
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  // =========================================================================
  // Cryptographic Operations
  // =========================================================================

  /**
   * Unwrap a content key using the private key.
   */
  private async unwrapContentKey(
    privateKey: CryptoKey,
    encryptedContentKeyB64: string,
  ): Promise<CryptoKey> {
    const encryptedContentKey = this.base64ToArrayBuffer(encryptedContentKeyB64);

    return crypto.subtle.unwrapKey(
      "raw",
      encryptedContentKey,
      privateKey,
      { name: "RSA-OAEP" },
      { name: "AES-GCM", length: 256 },
      false, // Non-extractable
      ["decrypt"],
    );
  }

  /**
   * Decrypt content with an unwrapped content key.
   */
  private async decryptWithContentKey(
    article: EncryptedArticle,
    contentKey: CryptoKey,
  ): Promise<string> {
    const iv = this.base64ToArrayBuffer(article.iv);
    const ciphertext = this.base64ToArrayBuffer(article.encryptedContent);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      contentKey,
      ciphertext,
    );

    return new TextDecoder().decode(decrypted);
  }

  // =========================================================================
  // Utilities
  // =========================================================================

  private log(message: string, level: "info" | "error" | "debug"): void {
    this.logger?.(message, level);
  }

  private arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]!);
    }
    return btoa(binary);
  }

  private base64ToArrayBuffer(base64: string): BufferSource {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}
