/**
 * Capsule CMS Server - High-Level API
 *
 * Provides a simple interface for server-side content encryption.
 * The CMS just works with key IDs - it doesn't know or care about
 * tiers, subscriptions, or how keys are derived.
 *
 * Keys are fetched via an async `getKeys` function that you provide.
 * This could:
 * - Fetch from your subscription server
 * - Use period key derivation (see `createPeriodKeyProvider`)
 * - Return hardcoded/cached keys
 *
 * Uses Web Crypto API for cross-platform compatibility (Node.js, Cloudflare Workers, browsers).
 *
 * @example Basic Usage with Custom Key Provider
 * ```typescript
 * import { createCmsServer } from '@sesamy/capsule-server';
 *
 * const cms = createCmsServer({
 *   getKeys: async (keyIds) => {
 *     // Fetch keys from your subscription server
 *     const response = await fetch('/api/keys', {
 *       method: 'POST',
 *       body: JSON.stringify({ keyIds }),
 *     });
 *     return response.json();
 *   },
 * });
 *
 * // Encrypt with specific key IDs
 * const encrypted = await cms.encrypt('article-123', content, {
 *   keyIds: ['premium', 'enterprise'],
 * });
 * ```
 *
 * @example Using Period Key Provider
 * ```typescript
 * import { createCmsServer, createPeriodKeyProvider } from '@sesamy/capsule-server';
 *
 * const keyProvider = createPeriodKeyProvider({
 *   periodSecret: process.env.PERIOD_SECRET,
 *   periodDurationSeconds: 30,
 * });
 *
 * const cms = createCmsServer({
 *   getKeys: (keyIds) => keyProvider.getKeys(keyIds),
 * });
 *
 * const encrypted = await cms.encrypt('article-123', content, {
 *   keyIds: ['premium', 'enterprise'],
 * });
 * ```
 */

import { encryptContent, wrapContentKey, generateContentKey } from "./encryption";
import {
  derivePeriodKey,
  getPeriodKeys,
  DEFAULT_PERIOD_DURATION_SECONDS,
} from "./time-periods";
import { fromBase64, toBase64 } from "./web-crypto";
import type { EncryptedArticle, WrappedKey } from "./types";

/**
 * A key entry returned by the key provider.
 */
export interface KeyEntry {
  /** Unique key identifier */
  keyId: string;
  /** 256-bit AES key (Uint8Array or base64 string) */
  key: Uint8Array | string;
  /** Optional expiration time (for time-period keys) */
  expiresAt?: Date | string;
}

/**
 * Async function to fetch keys for given key IDs.
 *
 * The CMS calls this with the key IDs it needs, and you return
 * the actual keys. This decouples key management from encryption.
 *
 * @param keyIds - Array of key IDs to fetch
 * @returns Array of key entries with the actual keys
 */
export type KeyProvider = (keyIds: string[]) => Promise<KeyEntry[]>;

/**
 * Options for creating a CMS server.
 */
export interface CmsServerOptions {
  /**
   * Async function to fetch keys for given key IDs.
   *
   * @example Fetch from subscription server
   * ```typescript
   * getKeys: async (keyIds) => {
   *   const response = await fetch('/api/keys', {
   *     method: 'POST',
   *     body: JSON.stringify({ keyIds }),
   *   });
   *   return response.json();
   * }
   * ```
   *
   * @example Use period key provider
   * ```typescript
   * const keyProvider = createPeriodKeyProvider({ periodSecret: '...' });
   * getKeys: (keyIds) => keyProvider.getKeys(keyIds)
   * ```
   */
  getKeys: KeyProvider;

  /**
   * Optional logger function for debugging.
   */
  logger?: (message: string, level: "info" | "warn" | "error") => void;
}

/**
 * Options for the encrypt() method.
 */
export interface EncryptOptions {
  /**
   * Key IDs to encrypt with. The content key will be wrapped with each key.
   *
   * @example
   * ```typescript
   * keyIds: ['premium', 'enterprise', 'promo-2024']
   * ```
   */
  keyIds: string[];

  /**
   * Generic content tier identifier (e.g., "premium", "paywall/basic/bodytext").
   * Used for key derivation and caching — multiple resources share the same contentId
   * so browsers can cache one key and unlock many articles.
   *
   * If not provided, defaults to the first entry in keyIds.
   */
  contentId?: string;

  /**
   * Output format:
   * - 'json': Returns EncryptedArticle object (default)
   * - 'html': Returns HTML element with data-capsule attribute
   * - 'html-template': Returns just the JSON for templates
   */
  format?: "json" | "html" | "html-template";

  /** HTML element tag when format is 'html'. Default: 'div' */
  htmlTag?: string;

  /** HTML element class when format is 'html'. */
  htmlClass?: string;

  /** Placeholder content shown before unlock when format is 'html'. */
  placeholder?: string;
}

/** Result type based on format option */
export type EncryptResult<T extends EncryptOptions["format"]> = T extends "html"
  ? string
  : T extends "html-template"
  ? string
  : EncryptedArticle;

/**
 * CMS Server for content encryption.
 *
 * Encrypts content with envelope encryption - the content is encrypted
 * once with a unique content key (content key), then the content key is wrapped
 * with multiple key-wrapping keys so different users can unlock it.
 *
 * @see createCmsServer for the recommended way to create an instance
 */
export class CmsServer {
  private getKeys: KeyProvider;
  private logger: (message: string, level: "info" | "warn" | "error") => void;

  constructor(options: CmsServerOptions) {
    if (!options.getKeys) {
      throw new Error("CmsServer requires a getKeys function");
    }
    this.getKeys = options.getKeys;
    this.logger = options.logger ?? (() => { });
  }

  /**
   * Encrypt content with envelope encryption.
   *
   * The content is encrypted once with a unique content key, then the content key is wrapped
   * with multiple key-wrapping keys (one for each keyId).
   *
   * @param resourceId - Unique resource identifier (specific page/article)
   * @param content - Plaintext content to encrypt
   * @param options - Encryption options (includes contentId for the generic content tier)
   * @returns Encrypted article data
   *
   * @example
   * ```typescript
   * const encrypted = await cms.encrypt('article-123', '<p>Premium content...</p>', {
   *   keyIds: ['premium', 'enterprise'],
   *   contentId: 'premium',
   * });
   * ```
   *
   * Returns (format: 'json'):
   * ```json
   * {
   *   "resourceId": "article-123",
   *   "contentId": "premium",
   *   "encryptedContent": "base64...",  // AES-256-GCM encrypted content
   *   "iv": "base64...",                 // 12-byte initialization vector
   *   "wrappedKeys": [
   *     {
   *       "keyId": "premium:1737158400",
   *       "wrappedContentKey": "base64...",     // content key wrapped with this key
   *       "expiresAt": "2025-01-18T01:00:00.000Z"
   *     },
   *     {
   *       "keyId": "premium:1737158430",
   *       "wrappedContentKey": "base64...",
   *       "expiresAt": "2025-01-18T01:00:30.000Z"
   *     }
   *   ]
   * }
   * ```
   */
  async encrypt<T extends EncryptOptions["format"] = "json">(
    resourceId: string,
    content: string,
    options: EncryptOptions & { format?: T }
  ): Promise<EncryptResult<T>> {
    const {
      keyIds,
      contentId,
      format = "json",
      htmlTag = "div",
      htmlClass,
      placeholder = "Loading encrypted content...",
    } = options;

    // Default contentId to the first non-article keyId if not provided
    const resolvedContentId = contentId ?? keyIds.find(id => !id.startsWith("article:")) ?? keyIds[0];

    if (!keyIds || keyIds.length === 0) {
      throw new Error("At least one keyId is required");
    }

    this.logger(
      `Encrypting resource: ${resourceId} (contentId: ${resolvedContentId}) with keys: ${keyIds.join(", ")}`,
      "info"
    );

    // Fetch keys from the provider
    const keyEntries = await this.getKeys(keyIds);

    if (keyEntries.length === 0) {
      throw new Error(`No keys returned for keyIds: ${keyIds.join(", ")}`);
    }

    // Convert keys to internal format
    const keyConfigs = keyEntries.map((entry) => ({
      keyId: entry.keyId,
      key:
        entry.key instanceof Uint8Array
          ? entry.key
          : fromBase64(entry.key),
      expiresAt: entry.expiresAt
        ? entry.expiresAt instanceof Date
          ? entry.expiresAt
          : new Date(entry.expiresAt)
        : undefined,
    }));

    this.logger(`Got ${keyConfigs.length} keys from provider`, "info");

    // Generate unique content key for this article
    const contentKey = generateContentKey();

    // Encrypt content ONCE with the content key
    const { encryptedContent, iv } = await encryptContent(content, contentKey);

    // Wrap the content key with each key-wrapping key
    const wrappedKeys: WrappedKey[] = await Promise.all(
      keyConfigs.map(async (config) => ({
        keyId: config.keyId,
        wrappedContentKey: toBase64(await wrapContentKey(contentKey, config.key)),
        expiresAt: config.expiresAt?.toISOString(),
      })),
    );

    /**
     * The encrypted article structure sent to the client:
     *
     * {
     *   resourceId: string,          // Specific page/article identifier
     *   contentId: string,           // Generic content tier (e.g., "premium")
     *   encryptedContent: string,    // Base64 AES-256-GCM ciphertext
     *   iv: string,                  // Base64 12-byte IV
     *   wrappedKeys: [               // One entry per key
     *     {
     *       keyId: string,           // Key identifier (e.g., "premium:1234567890")
     *       wrappedContentKey: string,      // Base64 AES-KW wrapped content key
     *       expiresAt?: string,      // ISO 8601 expiration (optional)
     *     }
     *   ]
     * }
     */
    const result: EncryptedArticle = {
      resourceId,
      contentId: resolvedContentId,
      encryptedContent: toBase64(encryptedContent),
      iv: toBase64(iv),
      wrappedKeys,
    };

    this.logger(`Encrypted with ${wrappedKeys.length} wrapped keys`, "info");

    // Format output
    if (format === "html") {
      const json = JSON.stringify(result);
      const classAttr = htmlClass ? ` class="${htmlClass}"` : "";
      return `<${htmlTag}${classAttr} data-capsule='${this.escapeHtml(
        json
      )}' data-capsule-id="${resourceId}">${placeholder}</${htmlTag}>` as EncryptResult<T>;
    }

    if (format === "html-template") {
      return JSON.stringify(result) as EncryptResult<T>;
    }

    return result as EncryptResult<T>;
  }

  /**
   * Encrypt and return data in multiple formats for templates.
   *
   * @returns Object with all template formats:
   * - data: The EncryptedArticle object
   * - json: JSON string
   * - attribute: HTML-escaped JSON for data attributes
   * - html: Complete HTML element
   */
  async encryptForTemplate(
    resourceId: string,
    content: string,
    options: Omit<EncryptOptions, "format"> & {
      htmlTag?: string;
      htmlClass?: string;
      placeholder?: string;
    }
  ): Promise<{
    data: EncryptedArticle;
    json: string;
    attribute: string;
    html: string;
  }> {
    // Encrypt ONCE to get the data
    const data = await this.encrypt(resourceId, content, {
      ...options,
      format: "json",
    });
    const json = JSON.stringify(data);
    const attribute = this.escapeHtml(json);

    // Build HTML from the same encrypted data (not a second encryption!)
    const {
      htmlTag = "div",
      htmlClass,
      placeholder = "Loading encrypted content...",
    } = options;
    const classAttr = htmlClass ? ` class="${htmlClass}"` : "";
    const html = `<${htmlTag}${classAttr} data-capsule='${attribute}' data-capsule-id="${resourceId}">${placeholder}</${htmlTag}>`;

    return {
      data,
      json,
      attribute,
      html,
    };
  }

  /**
   * Escape HTML special characters for safe attribute embedding.
   */
  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, "&amp;")
      .replace(/'/g, "&#39;")
      .replace(/"/g, "&quot;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }
}

/**
 * Create a CMS server for content encryption.
 *
 * @example With subscription server
 * ```typescript
 * const cms = createCmsServer({
 *   getKeys: async (keyIds) => {
 *     const response = await fetch('/api/keys', {
 *       method: 'POST',
 *       body: JSON.stringify({ keyIds }),
 *     });
 *     return response.json();
 *   },
 * });
 * ```
 *
 * @example With period key provider
 * ```typescript
 * const keyProvider = createPeriodKeyProvider({ periodSecret: process.env.PERIOD_SECRET });
 * const cms = createCmsServer({
 *   getKeys: (keyIds) => keyProvider.getKeys(keyIds),
 * });
 * ```
 */
export function createCmsServer(options: CmsServerOptions): CmsServer {
  return new CmsServer(options);
}

// ============================================================================
// Period Key Provider
// ============================================================================

/**
 * Options for the period key provider.
 */
export interface PeriodKeyProviderOptions {
  /**
   * Period secret for key derivation.
   * Can be a Uint8Array or base64-encoded string.
   */
  periodSecret: Uint8Array | string;

  /**
   * Period duration in seconds.
   * Default: 30 seconds.
   */
  periodDurationSeconds?: number;
}

/**
 * Period-based key provider.
 *
 * Derives time-period keys from a period secret using HKDF.
 * For each key ID, returns BOTH current and next period keys
 * to handle clock drift between CMS and subscription server.
 */
export class PeriodKeyProvider {
  private periodSecret: Uint8Array;
  private periodDurationSeconds: number;

  constructor(options: PeriodKeyProviderOptions) {
    this.periodSecret =
      options.periodSecret instanceof Uint8Array
        ? options.periodSecret
        : fromBase64(options.periodSecret);
    const duration =
      options.periodDurationSeconds ?? DEFAULT_PERIOD_DURATION_SECONDS;
    if (!Number.isFinite(duration) || duration <= 0) {
      throw new RangeError(
        `periodDurationSeconds must be a positive number, got ${duration}`,
      );
    }
    this.periodDurationSeconds = duration;
  }

  /**
   * Get keys for the given key IDs.
   *
   * For each keyId, returns two keys:
   * - Current period key (e.g., "premium:1737158400")
   * - Next period key (e.g., "premium:1737158430")
   *
   * This ensures content encrypted near a period boundary
   * can still be decrypted after the period rotates.
   */
  async getKeys(keyIds: string[]): Promise<KeyEntry[]> {
    const entries: KeyEntry[] = [];

    for (const keyId of keyIds) {
      const periodKeys = await getPeriodKeys(
        this.periodSecret,
        keyId,
        this.periodDurationSeconds,
      );

      // Add current period key
      entries.push({
        keyId: `${keyId}:${periodKeys.current.periodId}`,
        key: periodKeys.current.key,
        expiresAt: periodKeys.current.expiresAt,
      });

      // Add next period key
      entries.push({
        keyId: `${keyId}:${periodKeys.next.periodId}`,
        key: periodKeys.next.key,
        expiresAt: periodKeys.next.expiresAt,
      });
    }

    return entries;
  }

  /**
   * Derive a static key for an article (no time period).
   * Useful for per-article purchase access.
   */
  async getArticleKey(resourceId: string): Promise<KeyEntry> {
    const key = await derivePeriodKey(this.periodSecret, "article", resourceId);
    return {
      keyId: `article:${resourceId}`,
      key,
    };
  }
}

/**
 * Create a period key provider for deriving time-period keys.
 *
 * Use this with CmsServer when you want to derive keys locally
 * from a shared period secret (no API calls needed).
 *
 * @example
 * ```typescript
 * const keyProvider = createPeriodKeyProvider({
 *   periodSecret: process.env.PERIOD_SECRET,
 *   periodDurationSeconds: 30,
 * });
 *
 * const cms = createCmsServer({
 *   getKeys: (keyIds) => keyProvider.getKeys(keyIds),
 * });
 *
 * // Or combine with article keys:
 * const cms = createCmsServer({
 *   getKeys: async (keyIds) => {
 *     const keys = await keyProvider.getKeys(keyIds);
 *     // Add article key if requested
 *     if (keyIds.some(id => id.startsWith('article:'))) {
 *       const resourceId = keyIds.find(id => id.startsWith('article:'))!.slice(8);
 *       keys.push(await keyProvider.getArticleKey(resourceId));
 *     }
 *     return keys;
 *   },
 * });
 * ```
 */
export function createPeriodKeyProvider(
  options: PeriodKeyProviderOptions
): PeriodKeyProvider {
  return new PeriodKeyProvider(options);
}

