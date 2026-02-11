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
 *   unlock: async ({ keyId, wrappedDek, publicKey }) => {
 *     const res = await fetch('/api/unlock', {
 *       method: 'POST',
 *       body: JSON.stringify({ keyId, wrappedDek, publicKey }),
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
 *   console.log('Unlocked:', e.detail.articleId);
 * });
 * ```
 *
 * @example Manual low-level control:
 * ```ts
 * const capsule = new CapsuleClient();
 * const publicKey = await capsule.getPublicKey();
 * const encryptedDek = await myServerCall(publicKey);
 * const content = await capsule.decrypt(encryptedArticle, encryptedDek);
 * ```
 */

import { KeyStorage } from "./storage";
import type {
  EncryptedPayload,
  EncryptedArticle,
  WrappedKey,
  CapsuleClientOptions,
  StoredKeyPair,
  StoredDek,
  UnlockFunction,
  UnlockResponse,
  ElementState,
  DekStorageMode,
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
const DEK_STORAGE_PREFIX = "capsule-dek:";

/**
 * Main client for Capsule decryption operations.
 *
 * Handles:
 * - RSA key pair generation and storage (auto-creates if needed)
 * - DEK caching and auto-renewal
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
  private dekStorage: DekStorageMode;
  private renewBuffer: number;
  private logger?: (message: string, level: "info" | "error" | "debug") => void;

  // Cached state
  private keyPairPromise: Promise<StoredKeyPair> | null = null;
  private dekCache: Map<string, { dek: CryptoKey; info: StoredDek }> =
    new Map();
  private renewalTimers: Map<string, number> = new Map();
  private elementStates: Map<string, ElementState> = new Map();

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
   *   dekStorage: 'session',
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
    this.dekStorage = options.dekStorage ?? "persist";
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
   * Finds the element, fetches the DEK (using unlock function), decrypts, and renders.
   *
   * @param articleId - The article ID to unlock
   * @returns The decrypted content string
   * @throws Error if element not found, no unlock function, or decryption fails
   *
   * @example
   * ```ts
   * // Element: <div data-capsule='{"articleId":"abc",...}'></div>
   * const content = await capsule.unlockElement('abc');
   * ```
   */
  async unlockElement(articleId: string): Promise<string> {
    const element = this.findElement(articleId);
    if (!element) {
      throw new Error(`No encrypted element found for article "${articleId}"`);
    }

    return this.processElement(element);
  }

  /**
   * Process all encrypted elements on the page.
   * Elements must have the data-capsule attribute with JSON EncryptedArticle data.
   *
   * @returns Map of articleId to decrypted content (or error)
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
          results.set(data.articleId, content);
        }
      } catch (err) {
        const articleId = element.dataset.capsuleId || "unknown";
        results.set(
          articleId,
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

    // Use the first tier key's wrappedDek (token-based unlock doesn't need keyId)
    const tierKey = article.wrappedKeys.find(
      (k) => !k.keyId.startsWith("article:"),
    );
    if (!tierKey) {
      throw new Error("No tier key found in article for token-based unlock");
    }

    const response = await this.unlockFn({
      keyId: tierKey.keyId,
      wrappedDek: tierKey.wrappedDek,
      publicKey,
      articleId: article.articleId,
      token,
    });

    const dek = await this.unwrapDek(keyPair.privateKey, response.encryptedDek);

    // Cache the DEK for future use
    await this.cacheDek(tierKey.keyId, dek, response);

    this.log(
      `Unlocked ${article.articleId} with token ${
        response.tokenId || "unknown"
      }`,
      "info",
    );

    return await this.decryptWithDek(article, dek);
  }

  /**
   * Decrypt content using cached DEK or by fetching a new one.
   * This is the main decryption method that handles the full flow.
   *
   * @param article - The encrypted article data
   * @param preferredKeyType - Prefer 'tier' or 'article' keys (default: tier)
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
    preferredKeyType: "tier" | "article" = "tier",
  ): Promise<string> {
    const keyPair = await this.ensureKeyPair();

    // Sort wrapped keys by preference
    const sortedKeys = this.sortKeysByPreference(
      article.wrappedKeys,
      preferredKeyType,
    );

    // Try cached DEKs first
    for (const wrappedKey of sortedKeys) {
      const cached = await this.getCachedDek(wrappedKey.keyId);
      if (cached) {
        this.log(`Using cached DEK for ${wrappedKey.keyId}`, "debug");
        try {
          return await this.decryptWithDek(article, cached.dek);
        } catch {
          // Cache might be stale, continue
          this.log(
            `Cached DEK failed for ${wrappedKey.keyId}, trying next`,
            "debug",
          );
        }
      }
    }

    // Need to fetch new DEK
    if (!this.unlockFn) {
      throw new Error(
        "No unlock function provided. Either pass an unlock function to the constructor, " +
          "or use decrypt() with a pre-fetched encryptedDek.",
      );
    }

    // Try each key until one works
    for (const wrappedKey of sortedKeys) {
      try {
        const publicKey = await this.getPublicKey();
        const response = await this.unlockFn({
          keyId: wrappedKey.keyId,
          wrappedDek: wrappedKey.wrappedDek,
          publicKey,
          articleId: article.articleId,
        });

        const dek = await this.unwrapDek(
          keyPair.privateKey,
          response.encryptedDek,
        );
        await this.cacheDek(wrappedKey.keyId, dek, response);

        return await this.decryptWithDek(article, dek);
      } catch (err) {
        this.log(`Failed to unlock with ${wrappedKey.keyId}: ${err}`, "debug");
        continue;
      }
    }

    throw new Error("Failed to unlock content with any available key");
  }

  // =========================================================================
  // Public API - Low Level
  // =========================================================================

  /**
   * Decrypt content with a pre-fetched encrypted DEK.
   * Use this for full manual control over the unlock flow.
   *
   * @param article - The encrypted article data
   * @param encryptedDek - Base64-encoded DEK encrypted with user's public key
   * @returns Decrypted content string
   *
   * @example
   * ```ts
   * // Manual flow
   * const publicKey = await capsule.getPublicKey();
   * const { encryptedDek } = await myServerCall(publicKey, article.wrappedKeys[0]);
   * const content = await capsule.decrypt(article, encryptedDek);
   * ```
   */
  async decrypt(
    article: EncryptedArticle,
    encryptedDek: string,
  ): Promise<string> {
    const keyPair = await this.ensureKeyPair();
    const dek = await this.unwrapDek(keyPair.privateKey, encryptedDek);
    return this.decryptWithDek(article, dek);
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
    const dek = await this.unwrapDek(keyPair.privateKey, payload.encryptedDek);

    const iv = this.base64ToArrayBuffer(payload.iv);
    const ciphertext = this.base64ToArrayBuffer(payload.encryptedContent);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      dek,
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
    this.dekCache.clear();
    return this.getPublicKey();
  }

  /**
   * Clear all stored keys and cached DEKs.
   */
  async clearAll(): Promise<void> {
    await this.storage.clearAll();
    this.keyPairPromise = null;
    this.dekCache.clear();
    this.clearAllRenewalTimers();

    // Clear persisted DEKs
    if (this.dekStorage === "persist") {
      // Clear from IndexedDB
      const db = await this.openDekDb();
      await this.clearDekStore(db);
    } else if (this.dekStorage === "session") {
      // Clear from sessionStorage
      const keys = Object.keys(sessionStorage).filter((k) =>
        k.startsWith(DEK_STORAGE_PREFIX),
      );
      keys.forEach((k) => sessionStorage.removeItem(k));
    }
  }

  /**
   * Get the current state of an element.
   */
  getElementState(articleId: string): ElementState | undefined {
    return this.elementStates.get(articleId);
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

    const articleId = data.articleId;
    this.setElementState(element, articleId, "unlocking");

    try {
      // Unlock and get content
      const content = await this.unlock(data);

      // Render content into element
      this.renderContent(element, content, articleId);
      this.setElementState(element, articleId, "unlocked");

      // Emit unlock event
      this.emitEvent(element, "capsule:unlock", {
        articleId,
        element,
        keyId: data.wrappedKeys[0]?.keyId || "unknown",
        content,
      } satisfies CapsuleUnlockEvent);

      return content;
    } catch (err) {
      this.setElementState(element, articleId, "error");

      // Emit error event
      this.emitEvent(element, "capsule:error", {
        articleId,
        element,
        error: err instanceof Error ? err : new Error(String(err)),
      } satisfies CapsuleErrorEvent);

      throw err;
    }
  }

  /**
   * Find an encrypted element by article ID.
   */
  private findElement(articleId: string): HTMLElement | null {
    // Try data-capsule-id first
    let element = document.querySelector<HTMLElement>(
      `[data-capsule-id="${articleId}"]`,
    );
    if (element) return element;

    // Try id attribute
    element = document.getElementById(articleId);
    if (element?.hasAttribute("data-capsule")) return element;

    // Search all encrypted elements for matching articleId
    const elements = document.querySelectorAll<HTMLElement>(this.selector);
    for (let i = 0; i < elements.length; i++) {
      const el = elements[i]!;
      try {
        const data = this.parseElementData(el);
        if (data?.articleId === articleId) return el;
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
    articleId: string,
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

    this.log(`Rendered content for ${articleId}`, "info");
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
    articleId: string,
    state: ElementState,
  ): void {
    const previousState = this.elementStates.get(articleId) || "locked";
    this.elementStates.set(articleId, state);

    // Update element data attribute
    element.dataset.capsuleState = state;

    // Emit state change event
    if (previousState !== state) {
      this.emitEvent(element, "capsule:state", {
        articleId,
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
    preferredType: "tier" | "article",
  ): WrappedKey[] {
    const parseKeyType = (keyId: string): "tier" | "article" => {
      return keyId.startsWith("article:") ? "article" : "tier";
    };

    return [...keys].sort((a, b) => {
      const typeA = parseKeyType(a.keyId);
      const typeB = parseKeyType(b.keyId);

      if (typeA === preferredType && typeB !== preferredType) return -1;
      if (typeA !== preferredType && typeB === preferredType) return 1;
      return 0;
    });
  }

  /**
   * Get cached DEK for a key ID.
   */
  private async getCachedDek(
    keyId: string,
  ): Promise<{ dek: CryptoKey; info: StoredDek } | null> {
    // Check memory cache first
    const memCached = this.dekCache.get(keyId);
    if (memCached && memCached.info.expiresAt > Date.now()) {
      return memCached;
    }

    // Check persistent storage
    const stored = await this.loadStoredDek(keyId);
    if (!stored || stored.expiresAt <= Date.now()) {
      return null;
    }

    // Unwrap and cache in memory
    const keyPair = await this.ensureKeyPair();
    try {
      const dek = await this.unwrapDek(keyPair.privateKey, stored.encryptedDek);
      this.dekCache.set(keyId, { dek, info: stored });
      this.scheduleRenewal(keyId, stored);
      return { dek, info: stored };
    } catch {
      return null;
    }
  }

  /**
   * Cache a DEK after fetching.
   */
  private async cacheDek(
    keyId: string,
    dek: CryptoKey,
    response: UnlockResponse,
  ): Promise<void> {
    const expiresAt =
      typeof response.expiresAt === "string"
        ? new Date(response.expiresAt).getTime()
        : response.expiresAt;

    const parsed = this.parseKeyId(keyId);
    const info: StoredDek = {
      type: parsed.type,
      baseId: parsed.baseId,
      encryptedDek: response.encryptedDek,
      expiresAt,
      bucketId: response.bucketId,
    };

    // Memory cache
    this.dekCache.set(keyId, { dek, info });

    // Persistent storage
    await this.storeStoredDek(keyId, info);

    // Schedule renewal
    this.scheduleRenewal(keyId, info);

    this.log(
      `Cached DEK for ${keyId}, expires ${new Date(expiresAt).toISOString()}`,
      "debug",
    );
  }

  /**
   * Parse a key ID into type and base ID.
   */
  private parseKeyId(keyId: string): {
    type: "tier" | "article";
    baseId: string;
  } {
    if (keyId.startsWith("article:")) {
      return { type: "article", baseId: keyId.slice(8) };
    }
    // Tier format: "tierName:bucketId" or just "tierName"
    const colonIdx = keyId.indexOf(":");
    if (colonIdx > 0) {
      return { type: "tier", baseId: keyId.slice(0, colonIdx) };
    }
    return { type: "tier", baseId: keyId };
  }

  /**
   * Schedule auto-renewal for a DEK.
   */
  private scheduleRenewal(keyId: string, info: StoredDek): void {
    if (this.renewBuffer <= 0) return;

    // Clear existing timer
    const existingTimer = this.renewalTimers.get(keyId);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    const timeUntilRenewal = info.expiresAt - Date.now() - this.renewBuffer;
    if (timeUntilRenewal <= 0) return;

    const timer = window.setTimeout(async () => {
      this.log(`Auto-renewing DEK for ${keyId}`, "debug");
      // DEK will be refreshed on next decrypt attempt
      this.dekCache.delete(keyId);
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
  }

  // =========================================================================
  // DEK Persistence
  // =========================================================================

  private async loadStoredDek(keyId: string): Promise<StoredDek | null> {
    if (this.dekStorage === "memory") {
      return null; // Memory-only, no persistence
    }

    if (this.dekStorage === "session") {
      const json = sessionStorage.getItem(DEK_STORAGE_PREFIX + keyId);
      return json ? JSON.parse(json) : null;
    }

    // persist mode - use IndexedDB
    const db = await this.openDekDb();
    return this.getDekFromStore(db, keyId);
  }

  private async storeStoredDek(keyId: string, info: StoredDek): Promise<void> {
    if (this.dekStorage === "memory") {
      return; // Memory-only
    }

    if (this.dekStorage === "session") {
      sessionStorage.setItem(DEK_STORAGE_PREFIX + keyId, JSON.stringify(info));
      return;
    }

    // persist mode - use IndexedDB
    const db = await this.openDekDb();
    await this.putDekToStore(db, keyId, info);
  }

  private dekDbPromise: Promise<IDBDatabase> | null = null;

  private async openDekDb(): Promise<IDBDatabase> {
    if (this.dekDbPromise) return this.dekDbPromise;

    this.dekDbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open("capsule-deks", 1);
      request.onerror = () => reject(request.error);
      request.onupgradeneeded = () => {
        request.result.createObjectStore("deks");
      };
      request.onsuccess = () => resolve(request.result);
    });

    return this.dekDbPromise;
  }

  private getDekFromStore(
    db: IDBDatabase,
    keyId: string,
  ): Promise<StoredDek | null> {
    return new Promise((resolve, reject) => {
      const tx = db.transaction("deks", "readonly");
      const store = tx.objectStore("deks");
      const request = store.get(keyId);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  private putDekToStore(
    db: IDBDatabase,
    keyId: string,
    info: StoredDek,
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = db.transaction("deks", "readwrite");
      const store = tx.objectStore("deks");
      const request = store.put(info, keyId);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  private clearDekStore(db: IDBDatabase): Promise<void> {
    return new Promise((resolve, reject) => {
      const tx = db.transaction("deks", "readwrite");
      const store = tx.objectStore("deks");
      const request = store.clear();
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  // =========================================================================
  // Cryptographic Operations
  // =========================================================================

  /**
   * Unwrap a DEK using the private key.
   */
  private async unwrapDek(
    privateKey: CryptoKey,
    encryptedDekB64: string,
  ): Promise<CryptoKey> {
    const encryptedDek = this.base64ToArrayBuffer(encryptedDekB64);

    return crypto.subtle.unwrapKey(
      "raw",
      encryptedDek,
      privateKey,
      { name: "RSA-OAEP" },
      { name: "AES-GCM", length: 256 },
      false, // Non-extractable
      ["decrypt"],
    );
  }

  /**
   * Decrypt content with an unwrapped DEK.
   */
  private async decryptWithDek(
    article: EncryptedArticle,
    dek: CryptoKey,
  ): Promise<string> {
    const iv = this.base64ToArrayBuffer(article.iv);
    const ciphertext = this.base64ToArrayBuffer(article.encryptedContent);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      dek,
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
