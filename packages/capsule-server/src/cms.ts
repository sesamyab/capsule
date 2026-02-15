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
 *
 * Uses Web Crypto API for cross-platform compatibility (Node.js, Cloudflare Workers, browsers).
 */

import { encryptContent, wrapDek, generateDek } from "./encryption";
import { getBucketKeys, DEFAULT_BUCKET_PERIOD_SECONDS } from "./time-buckets";
import { fromBase64, toBase64 } from "./web-crypto";
import type {
  EncryptedArticle,
  WrappedKey,
  KeyWrapConfig,
  CmsEncryptorOptions,
  BucketKey,
} from "./types";

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
  private masterSecret: Uint8Array | null;
  private subscriptionServerUrl: string | null;
  private apiKey: string | null;
  private bucketPeriodSeconds: number;

  constructor(options: CmsEncryptorOptions = {}) {
    this.masterSecret = options.masterSecret
      ? fromBase64(options.masterSecret)
      : null;
    this.subscriptionServerUrl = options.subscriptionServerUrl ?? null;
    this.apiKey = options.apiKey ?? null;
    this.bucketPeriodSeconds =
      options.bucketPeriodSeconds ?? DEFAULT_BUCKET_PERIOD_SECONDS;

    // Validate configuration
    if (!this.masterSecret && !this.subscriptionServerUrl) {
      throw new Error(
        "CmsEncryptor requires either masterSecret (TOTP mode) or subscriptionServerUrl (API mode)",
      );
    }
  }

  /**
   * Get bucket keys for a key ID.
   *
   * In TOTP mode: derives from master secret locally.
   * In API mode: fetches from subscription server (with 10s timeout).
   */
  async getBucketKeys(
    keyId: string,
  ): Promise<{ current: BucketKey; next: BucketKey }> {
    if (this.masterSecret) {
      // TOTP mode - derive locally
      return getBucketKeys(this.masterSecret, keyId, this.bucketPeriodSeconds);
    }

    // API mode - fetch from subscription server
    if (!this.subscriptionServerUrl || !this.apiKey) {
      throw new Error("API mode requires subscriptionServerUrl and apiKey");
    }

    // Set up timeout to prevent hanging on slow/unresponsive servers
    const TIMEOUT_MS = 10000;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      const response = await fetch(
        `${this.subscriptionServerUrl}/api/cms/bucket-keys`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.apiKey}`,
          },
          body: JSON.stringify({ keyId }),
          signal: controller.signal,
        },
      );

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Failed to fetch bucket keys: ${error}`);
      }

      const data = (await response.json()) as BucketKeysApiResponse;
      return {
        current: {
          bucketId: data.current.bucketId,
          key: fromBase64(data.current.key),
          expiresAt: new Date(data.current.expiresAt),
        },
        next: {
          bucketId: data.next.bucketId,
          key: fromBase64(data.next.key),
          expiresAt: new Date(data.next.expiresAt),
        },
      };
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(
          `Subscription server request timed out after ${TIMEOUT_MS}ms`,
        );
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
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
  async encryptArticle(
    articleId: string,
    content: string,
    keyConfigs: KeyWrapConfig[],
  ): Promise<EncryptedArticle> {
    if (keyConfigs.length === 0) {
      throw new Error("At least one key configuration is required");
    }

    // Generate unique DEK for this article
    const dek = generateDek();

    // Encrypt content ONCE with the DEK
    const { encryptedContent, iv } = await encryptContent(content, dek);

    // Wrap the DEK with each key-wrapping key (serialize dates to ISO strings)
    const wrappedKeys: WrappedKey[] = await Promise.all(
      keyConfigs.map(async (config) => ({
        keyId: config.keyId,
        wrappedDek: toBase64(await wrapDek(dek, config.key)),
        expiresAt: config.expiresAt?.toISOString(),
      })),
    );

    return {
      articleId,
      encryptedContent: toBase64(encryptedContent),
      iv: toBase64(iv),
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
    additionalKeys: KeyWrapConfig[] = [],
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
  masterSecret: string | Uint8Array,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS,
): CmsEncryptor {
  const secret =
    typeof masterSecret === "string" ? masterSecret : toBase64(masterSecret);

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
  apiKey: string,
): CmsEncryptor {
  return new CmsEncryptor({
    subscriptionServerUrl,
    apiKey,
  });
}
