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
 * - Use TOTP derivation (see `createTotpKeyProvider`)
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
 * @example Using TOTP Key Provider
 * ```typescript
 * import { createCmsServer, createTotpKeyProvider } from '@sesamy/capsule-server';
 *
 * const totp = createTotpKeyProvider({
 *   masterSecret: process.env.MASTER_SECRET,
 *   bucketPeriodSeconds: 30,
 * });
 *
 * const cms = createCmsServer({
 *   getKeys: (keyIds) => totp.getKeys(keyIds),
 * });
 *
 * const encrypted = await cms.encrypt('article-123', content, {
 *   keyIds: ['premium', 'enterprise'],
 * });
 * ```
 */

import { encryptContent, wrapDek, generateDek } from "./encryption";
import {
  deriveBucketKey,
  getBucketKeys,
  DEFAULT_BUCKET_PERIOD_SECONDS,
} from "./time-buckets";
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
  /** Optional expiration time (for time-bucket keys) */
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
   * @example Use TOTP provider
   * ```typescript
   * const totp = createTotpKeyProvider({ masterSecret: '...' });
   * getKeys: (keyIds) => totp.getKeys(keyIds)
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
   * Key IDs to encrypt with. The DEK will be wrapped with each key.
   *
   * @example
   * ```typescript
   * keyIds: ['premium', 'enterprise', 'promo-2024']
   * ```
   */
  keyIds: string[];

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
 * once with a unique DEK (Data Encryption Key), then the DEK is wrapped
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
    this.logger = options.logger ?? (() => {});
  }

  /**
   * Encrypt content with envelope encryption.
   *
   * The content is encrypted once with a unique DEK, then the DEK is wrapped
   * with multiple key-wrapping keys (one for each keyId).
   *
   * @param articleId - Unique article identifier
   * @param content - Plaintext content to encrypt
   * @param options - Encryption options
   * @returns Encrypted article data
   *
   * @example
   * ```typescript
   * const encrypted = await cms.encrypt('article-123', '<p>Premium content...</p>', {
   *   keyIds: ['premium', 'enterprise'],
   * });
   * ```
   *
   * Returns (format: 'json'):
   * ```json
   * {
   *   "articleId": "article-123",
   *   "encryptedContent": "base64...",  // AES-256-GCM encrypted content
   *   "iv": "base64...",                 // 12-byte initialization vector
   *   "wrappedKeys": [
   *     {
   *       "keyId": "premium:1737158400",
   *       "wrappedDek": "base64...",     // DEK wrapped with this key
   *       "expiresAt": "2025-01-18T01:00:00.000Z"
   *     },
   *     {
   *       "keyId": "premium:1737158430",
   *       "wrappedDek": "base64...",
   *       "expiresAt": "2025-01-18T01:00:30.000Z"
   *     }
   *   ]
   * }
   * ```
   */
  async encrypt<T extends EncryptOptions["format"] = "json">(
    articleId: string,
    content: string,
    options: EncryptOptions & { format?: T }
  ): Promise<EncryptResult<T>> {
    const {
      keyIds,
      format = "json",
      htmlTag = "div",
      htmlClass,
      placeholder = "Loading encrypted content...",
    } = options;

    if (!keyIds || keyIds.length === 0) {
      throw new Error("At least one keyId is required");
    }

    this.logger(
      `Encrypting article: ${articleId} with keys: ${keyIds.join(", ")}`,
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

    // Generate unique DEK for this article
    const dek = generateDek();

    // Encrypt content ONCE with the DEK
    const { encryptedContent, iv } = await encryptContent(content, dek);

    // Wrap the DEK with each key-wrapping key
    const wrappedKeys: WrappedKey[] = await Promise.all(
      keyConfigs.map(async (config) => ({
        keyId: config.keyId,
        wrappedDek: toBase64(await wrapDek(dek, config.key)),
        expiresAt: config.expiresAt?.toISOString(),
      })),
    );

    /**
     * The encrypted article structure sent to the client:
     *
     * {
     *   articleId: string,           // Original article ID
     *   encryptedContent: string,    // Base64 AES-256-GCM ciphertext
     *   iv: string,                  // Base64 12-byte IV
     *   wrappedKeys: [               // One entry per key
     *     {
     *       keyId: string,           // Key identifier (e.g., "premium:1234567890")
     *       wrappedDek: string,      // Base64 AES-KW wrapped DEK
     *       expiresAt?: string,      // ISO 8601 expiration (optional)
     *     }
     *   ]
     * }
     */
    const result: EncryptedArticle = {
      articleId,
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
      )}' data-capsule-id="${articleId}">${placeholder}</${htmlTag}>` as EncryptResult<T>;
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
    articleId: string,
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
    const data = await this.encrypt(articleId, content, {
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
    const html = `<${htmlTag}${classAttr} data-capsule='${attribute}' data-capsule-id="${articleId}">${placeholder}</${htmlTag}>`;

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
 * @example With TOTP key provider
 * ```typescript
 * const totp = createTotpKeyProvider({ masterSecret: process.env.MASTER_SECRET });
 * const cms = createCmsServer({
 *   getKeys: (keyIds) => totp.getKeys(keyIds),
 * });
 * ```
 */
export function createCmsServer(options: CmsServerOptions): CmsServer {
  return new CmsServer(options);
}

// ============================================================================
// TOTP Key Provider
// ============================================================================

/**
 * Options for the TOTP key provider.
 */
export interface TotpKeyProviderOptions {
  /**
   * Master secret for key derivation.
   * Can be a Uint8Array or base64-encoded string.
   */
  masterSecret: Uint8Array | string;

  /**
   * Bucket period in seconds.
   * Default: 30 seconds.
   */
  bucketPeriodSeconds?: number;
}

/**
 * TOTP-based key provider.
 *
 * Derives time-bucket keys from a master secret using HKDF.
 * For each key ID, returns BOTH current and next bucket keys
 * to handle clock drift between CMS and subscription server.
 */
export class TotpKeyProvider {
  private masterSecret: Uint8Array;
  private bucketPeriodSeconds: number;

  constructor(options: TotpKeyProviderOptions) {
    this.masterSecret =
      options.masterSecret instanceof Uint8Array
        ? options.masterSecret
        : fromBase64(options.masterSecret);
    this.bucketPeriodSeconds =
      options.bucketPeriodSeconds ?? DEFAULT_BUCKET_PERIOD_SECONDS;
  }

  /**
   * Get keys for the given key IDs.
   *
   * For each keyId, returns two keys:
   * - Current bucket key (e.g., "premium:1737158400")
   * - Next bucket key (e.g., "premium:1737158430")
   *
   * This ensures content encrypted near a bucket boundary
   * can still be decrypted after the bucket rotates.
   */
  async getKeys(keyIds: string[]): Promise<KeyEntry[]> {
    const entries: KeyEntry[] = [];

    for (const keyId of keyIds) {
      const bucketKeys = await getBucketKeys(
        this.masterSecret,
        keyId,
        this.bucketPeriodSeconds,
      );

      // Add current bucket key
      entries.push({
        keyId: `${keyId}:${bucketKeys.current.bucketId}`,
        key: bucketKeys.current.key,
        expiresAt: bucketKeys.current.expiresAt,
      });

      // Add next bucket key
      entries.push({
        keyId: `${keyId}:${bucketKeys.next.bucketId}`,
        key: bucketKeys.next.key,
        expiresAt: bucketKeys.next.expiresAt,
      });
    }

    return entries;
  }

  /**
   * Derive a static key for an article (no time bucket).
   * Useful for per-article purchase access.
   */
  async getArticleKey(articleId: string): Promise<KeyEntry> {
    const key = await deriveBucketKey(this.masterSecret, "article", articleId);
    return {
      keyId: `article:${articleId}`,
      key,
    };
  }
}

/**
 * Create a TOTP key provider for deriving time-bucket keys.
 *
 * Use this with CmsServer when you want to derive keys locally
 * from a shared master secret (no API calls needed).
 *
 * @example
 * ```typescript
 * const totp = createTotpKeyProvider({
 *   masterSecret: process.env.MASTER_SECRET,
 *   bucketPeriodSeconds: 30,
 * });
 *
 * const cms = createCmsServer({
 *   getKeys: (keyIds) => totp.getKeys(keyIds),
 * });
 *
 * // Or combine with article keys:
 * const cms = createCmsServer({
 *   getKeys: async (keyIds) => {
 *     const keys = await totp.getKeys(keyIds);
 *     // Add article key if requested
 *     if (keyIds.some(id => id.startsWith('article:'))) {
 *       const articleId = keyIds.find(id => id.startsWith('article:'))!.slice(8);
 *       keys.push(await totp.getArticleKey(articleId));
 *     }
 *     return keys;
 *   },
 * });
 * ```
 */
export function createTotpKeyProvider(
  options: TotpKeyProviderOptions
): TotpKeyProvider {
  return new TotpKeyProvider(options);
}

// ============================================================================
// Legacy Aliases (Deprecated)
// ============================================================================

/** @deprecated Use CmsServer instead */
export const CapsuleServer = CmsServer;
/** @deprecated Use CmsServerOptions instead */
export type CapsuleServerOptions = CmsServerOptions;
/** @deprecated Use createCmsServer instead */
export const createCapsule = createCmsServer;
