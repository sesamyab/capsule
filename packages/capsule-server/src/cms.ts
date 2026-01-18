/**
 * CMS Content Encryptor
 * 
 * Provides envelope encryption for article content:
 * 1. Content is encrypted ONCE with a unique DEK (AES-256-GCM)
 * 2. The DEK is wrapped with MULTIPLE key-wrapping keys for different unlock paths
 * 
 * Supports two modes for obtaining bucket keys:
 * - TOTP: Derive keys locally from master secret (no network calls)
 * - API: Fetch keys from subscription server
 */

import { encryptContent, wrapDek, generateDek } from "./encryption";
import { getBucketKeys, DEFAULT_BUCKET_PERIOD_SECONDS } from "./time-buckets";
import type { EncryptedArticle, WrappedKey, KeyWrapConfig, CmsEncryptorOptions, BucketKey } from "./types";

/** API response type for bucket keys */
interface BucketKeysApiResponse {
  current: { bucketId: string; key: string; expiresAt: string };
  next: { bucketId: string; key: string; expiresAt: string };
}

/**
 * CMS Content Encryptor for Capsule.
 * 
 * Use this in your CMS to encrypt article content with envelope encryption.
 */
export class CmsEncryptor {
  private masterSecret: Buffer | null;
  private subscriptionServerUrl: string | null;
  private apiKey: string | null;
  private bucketPeriodSeconds: number;

  constructor(options: CmsEncryptorOptions = {}) {
    this.masterSecret = options.masterSecret 
      ? Buffer.from(options.masterSecret, "base64") 
      : null;
    this.subscriptionServerUrl = options.subscriptionServerUrl ?? null;
    this.apiKey = options.apiKey ?? null;
    this.bucketPeriodSeconds = options.bucketPeriodSeconds ?? DEFAULT_BUCKET_PERIOD_SECONDS;

    // Validate configuration
    if (!this.masterSecret && !this.subscriptionServerUrl) {
      throw new Error(
        "CmsEncryptor requires either masterSecret (TOTP mode) or subscriptionServerUrl (API mode)"
      );
    }
  }

  /**
   * Get bucket keys for a key ID.
   * 
   * In TOTP mode: derives from master secret locally.
   * In API mode: fetches from subscription server.
   */
  async getBucketKeys(keyId: string): Promise<{ current: BucketKey; next: BucketKey }> {
    if (this.masterSecret) {
      // TOTP mode - derive locally
      return getBucketKeys(this.masterSecret, keyId, this.bucketPeriodSeconds);
    }

    // API mode - fetch from subscription server
    if (!this.subscriptionServerUrl || !this.apiKey) {
      throw new Error("API mode requires subscriptionServerUrl and apiKey");
    }

    const response = await fetch(`${this.subscriptionServerUrl}/api/cms/bucket-keys`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({ keyId }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to fetch bucket keys: ${error}`);
    }

    const data = await response.json() as BucketKeysApiResponse;
    return {
      current: {
        bucketId: data.current.bucketId,
        key: Buffer.from(data.current.key, "base64"),
        expiresAt: new Date(data.current.expiresAt),
      },
      next: {
        bucketId: data.next.bucketId,
        key: Buffer.from(data.next.key, "base64"),
        expiresAt: new Date(data.next.expiresAt),
      },
    };
  }

  /**
   * Encrypt article content with envelope encryption.
   * 
   * The content is encrypted once with a unique DEK, then the DEK is wrapped
   * with multiple key-wrapping keys for different unlock paths.
   * 
   * @param articleId - Unique article identifier
   * @param content - Plaintext content to encrypt
   * @param keyConfigs - Array of key-wrapping configurations
   * @returns Encrypted article with wrapped keys
   */
  encryptArticle(
    articleId: string,
    content: string,
    keyConfigs: KeyWrapConfig[]
  ): EncryptedArticle {
    if (keyConfigs.length === 0) {
      throw new Error("At least one key configuration is required");
    }

    // Generate unique DEK for this article
    const dek = generateDek();

    // Encrypt content ONCE with the DEK
    const { encryptedContent, iv } = encryptContent(content, dek);

    // Wrap the DEK with each key-wrapping key (serialize dates to ISO strings)
    const wrappedKeys: WrappedKey[] = keyConfigs.map(config => ({
      keyId: config.keyId,
      wrappedDek: wrapDek(dek, config.key).toString("base64"),
      expiresAt: config.expiresAt?.toISOString(),
    }));

    return {
      articleId,
      encryptedContent: encryptedContent.toString("base64"),
      iv: iv.toString("base64"),
      wrappedKeys,
    };
  }

  /**
   * Encrypt article with tier-based time-bucket keys.
   * 
   * Automatically gets current and next bucket keys for the specified tier,
   * plus any additional static keys (e.g., per-article keys).
   * 
   * @param articleId - Unique article identifier
   * @param content - Plaintext content to encrypt
   * @param tier - Subscription tier (e.g., "premium")
   * @param additionalKeys - Optional additional key configurations (e.g., per-article keys)
   */
  async encryptArticleWithTier(
    articleId: string,
    content: string,
    tier: string,
    additionalKeys: KeyWrapConfig[] = []
  ): Promise<EncryptedArticle> {
    // Get time-bucket keys for this tier
    const bucketKeys = await this.getBucketKeys(tier);

    const keyConfigs: KeyWrapConfig[] = [
      // Current bucket key
      {
        keyId: `${tier}:${bucketKeys.current.bucketId}`,
        key: bucketKeys.current.key,
        expiresAt: bucketKeys.current.expiresAt,
      },
      // Next bucket key (handles clock drift)
      {
        keyId: `${tier}:${bucketKeys.next.bucketId}`,
        key: bucketKeys.next.key,
        expiresAt: bucketKeys.next.expiresAt,
      },
      // Additional keys (e.g., per-article access)
      ...additionalKeys,
    ];

    return this.encryptArticle(articleId, content, keyConfigs);
  }
}

/**
 * Create a simple encryptor for TOTP mode.
 */
export function createTotpEncryptor(
  masterSecret: string | Buffer,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): CmsEncryptor {
  const secret = typeof masterSecret === "string" 
    ? masterSecret 
    : masterSecret.toString("base64");
  
  return new CmsEncryptor({
    masterSecret: secret,
    bucketPeriodSeconds,
  });
}

/**
 * Create an encryptor that fetches keys from subscription server.
 */
export function createApiEncryptor(
  subscriptionServerUrl: string,
  apiKey: string
): CmsEncryptor {
  return new CmsEncryptor({
    subscriptionServerUrl,
    apiKey,
  });
}
