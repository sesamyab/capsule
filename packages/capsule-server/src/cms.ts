/**
 * CMS Content Encryptor
 *
 * Provides envelope encryption for article content:
 * 1. Content is encrypted ONCE with a unique content key (AES-256-GCM)
 * 2. The content key is wrapped with MULTIPLE key-wrapping keys for different unlock paths
 *
 * Supports two modes for obtaining period keys:
 * - Period: Derive keys locally from period secret (no network calls)
 * - API: Fetch keys from subscription server
 *
 * Uses Web Crypto API for cross-platform compatibility (Node.js, Cloudflare Workers, browsers).
 */

import { encryptContent, wrapContentKey, generateContentKey } from "./encryption";
import { getPeriodKeys, DEFAULT_PERIOD_DURATION_SECONDS } from "./time-periods";
import { fromBase64, toBase64 } from "./web-crypto";
import type {
  EncryptedArticle,
  WrappedKey,
  KeyWrapConfig,
  CmsEncryptorOptions,
  PeriodKey,
} from "./types";

/** API response type for period keys */
interface PeriodKeysApiResponse {
  current: { periodId: string; key: string; expiresAt: string };
  next: { periodId: string; key: string; expiresAt: string };
}

/**
 * CMS Content Encryptor for Capsule.
 *
 * Use this in your CMS to encrypt article content with envelope encryption.
 */
export class CmsEncryptor {
  private periodSecret: Uint8Array | null;
  private subscriptionServerUrl: string | null;
  private apiKey: string | null;
  private periodDurationSeconds: number;

  constructor(options: CmsEncryptorOptions = {}) {
    this.periodSecret = options.periodSecret
      ? fromBase64(options.periodSecret)
      : null;
    this.subscriptionServerUrl = options.subscriptionServerUrl ?? null;
    this.apiKey = options.apiKey ?? null;
    this.periodDurationSeconds =
      options.periodDurationSeconds ?? DEFAULT_PERIOD_DURATION_SECONDS;

    // Validate configuration
    if (!this.periodSecret && !this.subscriptionServerUrl) {
      throw new Error(
        "CmsEncryptor requires either periodSecret (period mode) or subscriptionServerUrl (API mode)",
      );
    }
  }

  /**
   * Get period keys for a key ID.
   *
   * In period mode: derives from period secret locally.
   * In API mode: fetches from subscription server (with 10s timeout).
   */
  async getPeriodKeys(
    keyId: string,
  ): Promise<{ current: PeriodKey; next: PeriodKey }> {
    if (this.periodSecret) {
      // period mode - derive locally
      return getPeriodKeys(this.periodSecret, keyId, this.periodDurationSeconds);
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
        `${this.subscriptionServerUrl}/api/cms/period-keys`,
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
        throw new Error(`Failed to fetch period keys: ${error}`);
      }

      const data = (await response.json()) as PeriodKeysApiResponse;
      return {
        current: {
          periodId: data.current.periodId,
          key: fromBase64(data.current.key),
          expiresAt: new Date(data.current.expiresAt),
        },
        next: {
          periodId: data.next.periodId,
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
   * The content is encrypted once with a unique content key, then the content key is wrapped
   * with multiple key-wrapping keys for different unlock paths.
   *
   * @param resourceId - Unique resource identifier (specific page/article)
   * @param content - Plaintext content to encrypt
   * @param keyConfigs - Array of key-wrapping configurations
   * @param contentId - Optional content name identifier (e.g., "premium", "bodytext")
   * @returns Encrypted article with wrapped keys
   */
  async encryptArticle(
    resourceId: string,
    content: string,
    keyConfigs: KeyWrapConfig[],
    contentId?: string,
  ): Promise<EncryptedArticle> {
    if (keyConfigs.length === 0) {
      throw new Error("At least one key configuration is required");
    }

    // Generate unique content key for this article
    const contentKey = generateContentKey();

    // Encrypt content ONCE with the content key
    const { encryptedContent, iv } = await encryptContent(content, contentKey);

    // Wrap the content key with each key-wrapping key (serialize dates to ISO strings)
    const wrappedKeys: WrappedKey[] = await Promise.all(
      keyConfigs.map(async (config) => ({
        keyId: config.keyId,
        wrappedContentKey: toBase64(await wrapContentKey(contentKey, config.key)),
        expiresAt: config.expiresAt?.toISOString(),
      })),
    );

    return {
      resourceId,
      contentId,
      encryptedContent: toBase64(encryptedContent),
      iv: toBase64(iv),
      wrappedKeys,
    };
  }

  /**
   * Encrypt article with content-name-based time-period keys.
   *
   * Automatically gets current and next period keys for the specified content name,
   * plus any additional static keys (e.g., per-article keys).
   *
   * @param resourceId - Unique resource identifier (specific page/article)
   * @param content - Plaintext content to encrypt
   * @param contentName - Content name for period key derivation (e.g., "premium", "bodytext")
   * @param additionalKeys - Optional additional key configurations (e.g., per-article keys)
   */
  async encryptArticleWithContentName(
    resourceId: string,
    content: string,
    contentName: string,
    additionalKeys: KeyWrapConfig[] = [],
  ): Promise<EncryptedArticle> {
    // Get time-period keys for this content name
    const periodKeys = await this.getPeriodKeys(contentName);

    const keyConfigs: KeyWrapConfig[] = [
      // Current period key
      {
        keyId: `${contentName}:${periodKeys.current.periodId}`,
        key: periodKeys.current.key,
        expiresAt: periodKeys.current.expiresAt,
      },
      // Next period key (handles clock drift)
      {
        keyId: `${contentName}:${periodKeys.next.periodId}`,
        key: periodKeys.next.key,
        expiresAt: periodKeys.next.expiresAt,
      },
      // Additional keys (e.g., per-article access)
      ...additionalKeys,
    ];

    return this.encryptArticle(resourceId, content, keyConfigs, contentName);
  }
}

/**
 * Create a simple encryptor for period mode.
 */
export function createPeriodEncryptor(
  periodSecret: string | Uint8Array,
  periodDurationSeconds: number = DEFAULT_PERIOD_DURATION_SECONDS,
): CmsEncryptor {
  const secret =
    typeof periodSecret === "string" ? periodSecret : toBase64(periodSecret);

  return new CmsEncryptor({
    periodSecret: secret,
    periodDurationSeconds,
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
