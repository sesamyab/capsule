/**
 * Capsule Server - High-Level API
 * 
 * Provides a simple, high-level interface for server-side content encryption.
 * Similar to CapsuleClient on the browser side, this handles:
 * - Key fetching (TOTP, async function, or direct)
 * - Content encryption with envelope encryption
 * - Output formatting (JSON or HTML)
 * 
 * @example Basic Usage
 * ```typescript
 * import { CapsuleServer } from '@sesamy/capsule-server';
 * 
 * const capsule = new CapsuleServer({
 *   masterSecret: process.env.MASTER_SECRET,
 * });
 * 
 * // Encrypt with tier-based access
 * const encrypted = await capsule.encrypt('article-123', content, {
 *   tiers: ['premium'],
 * });
 * ```
 * 
 * @example With Async Key Provider
 * ```typescript
 * const capsule = new CapsuleServer({
 *   getKeys: async (articleId) => {
 *     // Fetch from CMS, subscription server, or cache
 *     const response = await fetch(`/api/keys?article=${articleId}`);
 *     return response.json(); // [{ keyId, key, expiresAt? }]
 *   },
 * });
 * ```
 */

import { encryptContent, wrapDek, generateDek } from "./encryption";
import { deriveBucketKey, getBucketKeys, DEFAULT_BUCKET_PERIOD_SECONDS } from "./time-buckets";
import type { EncryptedArticle, WrappedKey, BucketKey } from "./types";

/** Key provider result - what keys are available for an article */
export interface KeyEntry {
  /** Key ID (e.g., "premium", "article:abc123") */
  keyId: string;
  /** 256-bit AES key (Buffer or base64 string) */
  key: Buffer | string;
  /** When this key expires (for time-bucket keys) */
  expiresAt?: Date | string;
}

/** Async function to fetch keys for an article */
export type KeyProvider = (articleId: string) => Promise<KeyEntry[]>;

/** Options for CapsuleServer */
export interface CapsuleServerOptions {
  /**
   * Master secret for TOTP-based key derivation.
   * If provided, tier-based keys are derived locally.
   * Can be a Buffer or base64-encoded string.
   */
  masterSecret?: Buffer | string;

  /**
   * Async function to fetch keys for an article.
   * Called when encrypting if tiers aren't using TOTP.
   */
  getKeys?: KeyProvider;

  /**
   * Bucket period in seconds for TOTP keys.
   * Default: 30 seconds.
   */
  bucketPeriodSeconds?: number;

  /**
   * Logger function for debugging.
   */
  logger?: (message: string, level: 'info' | 'warn' | 'error') => void;
}

/** Options for encrypt() method */
export interface EncryptOptions {
  /**
   * Subscription tiers that can unlock this content.
   * Uses TOTP-derived bucket keys if masterSecret is configured.
   * @example ['premium', 'enterprise']
   */
  tiers?: string[];

  /**
   * Include article-specific permanent key.
   * Derived from masterSecret if available.
   */
  includeArticleKey?: boolean;

  /**
   * Additional keys to wrap the DEK with.
   * Use this for custom key sources.
   */
  additionalKeys?: KeyEntry[];

  /**
   * Output format.
   * - 'json': Returns EncryptedArticle object (default)
   * - 'html': Returns HTML string with data-capsule attribute
   * - 'html-template': Returns just the data-capsule JSON for templates
   */
  format?: 'json' | 'html' | 'html-template';

  /**
   * HTML element tag when format is 'html'.
   * Default: 'div'
   */
  htmlTag?: string;

  /**
   * HTML element class when format is 'html'.
   */
  htmlClass?: string;

  /**
   * Placeholder content shown before unlock when format is 'html'.
   */
  placeholder?: string;
}

/** Result type based on format option */
export type EncryptResult<T extends EncryptOptions['format']> = 
  T extends 'html' ? string :
  T extends 'html-template' ? string :
  EncryptedArticle;

/**
 * High-level server for content encryption.
 * 
 * Provides a simple interface for encrypting content with multiple
 * unlock paths (subscription tiers, per-article keys, custom keys).
 */
export class CapsuleServer {
  private masterSecret: Buffer | null;
  private getKeys: KeyProvider | null;
  private bucketPeriodSeconds: number;
  private logger: (message: string, level: 'info' | 'warn' | 'error') => void;

  constructor(options: CapsuleServerOptions = {}) {
    this.masterSecret = options.masterSecret
      ? (Buffer.isBuffer(options.masterSecret) 
          ? options.masterSecret 
          : Buffer.from(options.masterSecret, 'base64'))
      : null;
    this.getKeys = options.getKeys ?? null;
    this.bucketPeriodSeconds = options.bucketPeriodSeconds ?? DEFAULT_BUCKET_PERIOD_SECONDS;
    this.logger = options.logger ?? (() => {});

    // Validate configuration
    if (!this.masterSecret && !this.getKeys) {
      throw new Error(
        'CapsuleServer requires either masterSecret (for TOTP) or getKeys (for async key fetching)'
      );
    }
  }

  /**
   * Encrypt content with envelope encryption.
   * 
   * The content is encrypted once with a unique DEK, then the DEK is wrapped
   * with multiple key-wrapping keys based on the options provided.
   * 
   * @param articleId - Unique article identifier
   * @param content - Plaintext content to encrypt
   * @param options - Encryption options (tiers, format, etc.)
   * @returns Encrypted article (format depends on options.format)
   */
  async encrypt<T extends EncryptOptions['format'] = 'json'>(
    articleId: string,
    content: string,
    options: EncryptOptions & { format?: T } = {}
  ): Promise<EncryptResult<T>> {
    const {
      tiers = [],
      includeArticleKey = false,
      additionalKeys = [],
      format = 'json',
      htmlTag = 'div',
      htmlClass,
      placeholder = 'Loading encrypted content...',
    } = options;

    this.logger(`Encrypting article: ${articleId}`, 'info');

    // Collect all key configurations
    const keyConfigs: Array<{ keyId: string; key: Buffer; expiresAt?: Date }> = [];

    // Add tier-based bucket keys
    for (const tier of tiers) {
      const bucketKeys = await this.getTierBucketKeys(tier);
      keyConfigs.push(
        {
          keyId: `${tier}:${bucketKeys.current.bucketId}`,
          key: bucketKeys.current.key,
          expiresAt: bucketKeys.current.expiresAt,
        },
        {
          keyId: `${tier}:${bucketKeys.next.bucketId}`,
          key: bucketKeys.next.key,
          expiresAt: bucketKeys.next.expiresAt,
        }
      );
      this.logger(`Added bucket keys for tier: ${tier}`, 'info');
    }

    // Add article-specific key
    if (includeArticleKey) {
      const articleKey = await this.getArticleKey(articleId);
      keyConfigs.push({
        keyId: `article:${articleId}`,
        key: articleKey,
      });
      this.logger(`Added article-specific key: article:${articleId}`, 'info');
    }

    // Add custom keys from async provider
    if (this.getKeys && tiers.length === 0 && !includeArticleKey && additionalKeys.length === 0) {
      // If no explicit keys specified, fetch from provider
      const fetchedKeys = await this.getKeys(articleId);
      for (const entry of fetchedKeys) {
        keyConfigs.push({
          keyId: entry.keyId,
          key: Buffer.isBuffer(entry.key) ? entry.key : Buffer.from(entry.key, 'base64'),
          expiresAt: entry.expiresAt 
            ? (entry.expiresAt instanceof Date ? entry.expiresAt : new Date(entry.expiresAt))
            : undefined,
        });
      }
      this.logger(`Fetched ${fetchedKeys.length} keys from provider`, 'info');
    }

    // Add additional custom keys
    for (const entry of additionalKeys) {
      keyConfigs.push({
        keyId: entry.keyId,
        key: Buffer.isBuffer(entry.key) ? entry.key : Buffer.from(entry.key, 'base64'),
        expiresAt: entry.expiresAt 
          ? (entry.expiresAt instanceof Date ? entry.expiresAt : new Date(entry.expiresAt))
          : undefined,
      });
    }

    if (keyConfigs.length === 0) {
      throw new Error('At least one encryption key is required');
    }

    // Generate unique DEK for this article
    const dek = generateDek();

    // Encrypt content ONCE with the DEK
    const { encryptedContent, iv } = encryptContent(content, dek);

    // Wrap the DEK with each key-wrapping key (serialize dates to ISO strings)
    const wrappedKeys: WrappedKey[] = keyConfigs.map(config => ({
      keyId: config.keyId,
      wrappedDek: wrapDek(dek, config.key).toString('base64'),
      expiresAt: config.expiresAt?.toISOString(),
    }));

    const result: EncryptedArticle = {
      articleId,
      encryptedContent: encryptedContent.toString('base64'),
      iv: iv.toString('base64'),
      wrappedKeys,
    };

    this.logger(`Encrypted with ${wrappedKeys.length} wrapped keys`, 'info');

    // Format output
    if (format === 'html') {
      const json = JSON.stringify(result);
      const classAttr = htmlClass ? ` class="${htmlClass}"` : '';
      return `<${htmlTag}${classAttr} data-capsule='${this.escapeHtml(json)}' data-capsule-id="${articleId}">${placeholder}</${htmlTag}>` as EncryptResult<T>;
    }

    if (format === 'html-template') {
      return JSON.stringify(result) as EncryptResult<T>;
    }

    return result as EncryptResult<T>;
  }

  /**
   * Encrypt and return just the data needed for a template.
   * 
   * Convenience method that returns an object with all the template data:
   * - json: The EncryptedArticle as a JSON string
   * - data: The EncryptedArticle object
   * - attribute: The data-capsule attribute value (escaped for HTML)
   * - html: A complete HTML element with the encrypted data
   */
  async encryptForTemplate(
    articleId: string,
    content: string,
    options: Omit<EncryptOptions, 'format'> = {}
  ): Promise<{
    data: EncryptedArticle;
    json: string;
    attribute: string;
    html: string;
  }> {
    const data = await this.encrypt(articleId, content, { ...options, format: 'json' });
    const json = JSON.stringify(data);
    
    return {
      data,
      json,
      attribute: this.escapeHtml(json),
      html: await this.encrypt(articleId, content, { ...options, format: 'html' }) as string,
    };
  }

  /**
   * Get bucket keys for a tier (TOTP mode).
   */
  private async getTierBucketKeys(tier: string): Promise<{ current: BucketKey; next: BucketKey }> {
    if (!this.masterSecret) {
      throw new Error('Master secret required for tier-based encryption');
    }
    return getBucketKeys(this.masterSecret, tier, this.bucketPeriodSeconds);
  }

  /**
   * Get article-specific key (derived from master secret).
   */
  private async getArticleKey(articleId: string): Promise<Buffer> {
    if (!this.masterSecret) {
      throw new Error('Master secret required for article key derivation');
    }
    // Derive a static key for this article using HKDF
    return deriveBucketKey(this.masterSecret, 'article', articleId);
  }

  /**
   * Escape HTML special characters for safe attribute embedding.
   */
  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/'/g, '&#39;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }
}

/**
 * Create a CapsuleServer with TOTP-based key derivation.
 */
export function createCapsule(
  masterSecret: string | Buffer,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): CapsuleServer {
  return new CapsuleServer({
    masterSecret,
    bucketPeriodSeconds,
  });
}

/**
 * Create a CapsuleServer with an async key provider.
 */
export function createCapsuleWithKeyProvider(
  getKeys: KeyProvider,
  options: Omit<CapsuleServerOptions, 'getKeys'> = {}
): CapsuleServer {
  return new CapsuleServer({
    ...options,
    getKeys,
  });
}
