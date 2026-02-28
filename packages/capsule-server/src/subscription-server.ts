/**
 * Subscription Server Utilities
 *
 * For building subscription server endpoints that:
 * 1. Provide period keys to CMS (for encryption)
 * 2. Unwrap content keys for authenticated users (for decryption)
 * 3. Handle token-based unlock for pre-signed share links
 *
 * Uses Web Crypto API for cross-platform compatibility (Node.js, Cloudflare Workers, browsers).
 *
 * @example
 * ```typescript
 * import { createSubscriptionServer, createTokenManager } from '@sesamy/capsule-server';
 *
 * const server = createSubscriptionServer({
 *   periodSecret: process.env.PERIOD_SECRET,
 *   periodDurationSeconds: 30,
 * });
 *
 * const tokens = createTokenManager({
 *   secret: process.env.TOKEN_SECRET,
 * });
 *
 * // Endpoint for users to unlock content with a token
 * app.post('/api/unlock', async (req, res) => {
 *   const { token, wrappedContentKey, publicKey } = req.body;
 *
 *   // Validate token
 *   const validation = await tokens.validate(token);
 *   if (!validation.valid) {
 *     return res.status(401).json({ error: validation.message });
 *   }
 *
 *   // Unlock with token
 *   const result = await server.unlockWithToken(
 *     validation.payload,
 *     wrappedContentKey,
 *     publicKey
 *   );
 *   res.json(result);
 * });
 * ```
 */

import {
  importRsaPublicKey,
  rsaOaepEncrypt,
  fromBase64,
  toBase64,
} from "./web-crypto";
import {
  derivePeriodKey,
  getPeriodKeys,
  getCurrentPeriod,
  getPeriodExpiration,
  isPeriodValid,
  DEFAULT_PERIOD_DURATION_SECONDS,
} from "./time-periods";
import { unwrapContentKey } from "./encryption";
import type { PeriodKey, UnlockResponse, WrappedKey } from "./types";
import type { UnlockTokenPayload } from "./tokens";

/** Check if a string looks like a numeric period ID */
function isNumericPeriodId(str: string): boolean {
  return /^\d+$/.test(str);
}

/** Options for creating a subscription server */
export interface SubscriptionServerOptions {
  /** Period secret for deriving period keys (base64 encoded string or Uint8Array) */
  periodSecret: string | Uint8Array;
  /** Period duration in seconds (default: 30) */
  periodDurationSeconds?: number;
}

/**
 * Subscription Server for Capsule.
 *
 * Manages period secret and provides:
 * - Period keys for CMS (time-limited)
 * - DEK unwrapping for authenticated users
 *
 * @see createSubscriptionServer for the recommended way to create an instance
 */
export class SubscriptionServer {
  private periodSecret: Uint8Array;
  private periodDurationSeconds: number;

  constructor(options: SubscriptionServerOptions) {
    if (options.periodSecret instanceof Uint8Array) {
      this.periodSecret = options.periodSecret;
    } else {
      this.periodSecret = fromBase64(options.periodSecret);
    }
    this.periodDurationSeconds =
      options.periodDurationSeconds ?? DEFAULT_PERIOD_DURATION_SECONDS;
  }

  /**
   * Get period keys for a key ID (for CMS).
   *
   * Returns current and next period keys so CMS can encrypt
   * content that works across period boundaries.
   */
  async getPeriodKeysForCms(
    keyId: string,
  ): Promise<{ current: PeriodKey; next: PeriodKey }> {
    return getPeriodKeys(this.periodSecret, keyId, this.periodDurationSeconds);
  }

  /**
   * Get period keys formatted for API response.
   */
  async getPeriodKeysResponse(keyId: string): Promise<{
    current: { periodId: string; key: string; expiresAt: string };
    next: { periodId: string; key: string; expiresAt: string };
  }> {
    const keys = await this.getPeriodKeysForCms(keyId);
    return {
      current: {
        periodId: keys.current.periodId,
        key: toBase64(keys.current.key),
        expiresAt: keys.current.expiresAt.toISOString(),
      },
      next: {
        periodId: keys.next.periodId,
        key: toBase64(keys.next.key),
        expiresAt: keys.next.expiresAt.toISOString(),
      },
    };
  }

  /**
   * Validate that a period ID is current or adjacent.
   */
  isPeriodValid(periodId: string): boolean {
    return isPeriodValid(periodId, this.periodDurationSeconds);
  }

  /**
   * Unwrap a content key and re-wrap it with a user's RSA public key.
   *
   * This is the core unlock operation:
   * 1. Parse the wrapped key to extract keyId and period info
   * 2. Derive the key-wrapping key from period secret
   * 3. Unwrap the content key
   * 4. Re-wrap with user's RSA public key
   *
   * @param wrappedKey - The wrapped key entry from the article
   * @param userPublicKeyB64 - User's RSA public key (Base64 SPKI format)
   * @param staticKeyLookup - Optional function to look up static keys (for per-article keys). Can be sync or async.
   */
  async unlockForUser(
    wrappedKey: WrappedKey,
    userPublicKeyB64: string,
    staticKeyLookup?: (
      keyId: string,
    ) => Uint8Array | null | Promise<Uint8Array | null>,
  ): Promise<UnlockResponse> {
    const { keyId, wrappedContentKey } = wrappedKey;
    const wrappedContentKeyBytes = fromBase64(wrappedContentKey);

    let keyWrappingKey: Uint8Array;
    let expiresAt: Date;

    // First, try static key lookup if provided (handles "article:xxx" keys)
    if (staticKeyLookup) {
      const staticKey = await Promise.resolve(staticKeyLookup(keyId));
      if (staticKey) {
        keyWrappingKey = staticKey;
        // Static keys use current period expiration for client cache timing
        const currentPeriod = getCurrentPeriod(this.periodDurationSeconds);
        expiresAt = getPeriodExpiration(
          currentPeriod,
          this.periodDurationSeconds,
        );

        // Unwrap and re-wrap
        return this.unwrapAndRewrap(
          wrappedContentKeyBytes,
          keyWrappingKey,
          userPublicKeyB64,
          keyId,
          undefined,
          expiresAt,
        );
      }
    }

    // Parse keyId as period key: "contentId:periodId" (only if suffix is numeric)
    const colonIndex = keyId.lastIndexOf(":");
    if (colonIndex === -1) {
      throw new Error(
        `Invalid keyId format: ${keyId}. Expected 'contentId:periodId' or use staticKeyLookup for static keys.`,
      );
    }

    const baseKeyId = keyId.substring(0, colonIndex);
    const suffix = keyId.substring(colonIndex + 1);

    // Only treat as period key if suffix is numeric
    if (!isNumericPeriodId(suffix)) {
      throw new Error(
        `No static key found for '${keyId}' and suffix '${suffix}' is not a valid period ID. Provide a staticKeyLookup function.`,
      );
    }

    const periodId = suffix;

    // Time-period key - validate and derive
    if (!this.isPeriodValid(periodId)) {
      throw new Error(`Period ${periodId} is expired or invalid`);
    }
    keyWrappingKey = await derivePeriodKey(
      this.periodSecret,
      baseKeyId,
      periodId,
    );
    expiresAt = getPeriodExpiration(periodId, this.periodDurationSeconds);

    return this.unwrapAndRewrap(
      wrappedContentKeyBytes,
      keyWrappingKey,
      userPublicKeyB64,
      keyId,
      periodId,
      expiresAt,
    );
  }

  /**
   * Internal helper to unwrap content key and re-wrap with user's public key.
   */
  private async unwrapAndRewrap(
    wrappedContentKeyBytes: Uint8Array,
    keyWrappingKey: Uint8Array,
    userPublicKeyB64: string,
    keyId: string,
    periodId: string | undefined,
    expiresAt: Date,
  ): Promise<UnlockResponse> {
    // Unwrap the content key
    const contentKey = await unwrapContentKey(wrappedContentKeyBytes, keyWrappingKey);

    // Import user's public key and re-wrap DEK with RSA-OAEP
    const pubKey = await importRsaPublicKey(userPublicKeyB64);
    const encryptedContentKey = await rsaOaepEncrypt(pubKey, contentKey);

    return {
      encryptedContentKey: toBase64(encryptedContentKey),
      keyId,
      periodId,
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Simple unlock when you already have the key-wrapping key.
   * Used when the unlock logic is separate from period key derivation.
   */
  async wrapContentKeyForUser(
    contentKey: Uint8Array,
    userPublicKeyB64: string,
    keyId: string,
    expiresAt: Date,
  ): Promise<UnlockResponse> {
    const pubKey = await importRsaPublicKey(userPublicKeyB64);
    const encryptedContentKey = await rsaOaepEncrypt(pubKey, contentKey);

    // Only extract periodId if suffix is numeric (otherwise it's a static key like "article:crypto-guide")
    let periodId: string | undefined;
    const colonIndex = keyId.lastIndexOf(":");
    if (colonIndex !== -1) {
      const suffix = keyId.substring(colonIndex + 1);
      if (isNumericPeriodId(suffix)) {
        periodId = suffix;
      }
    }

    return {
      encryptedContentKey: toBase64(encryptedContentKey),
      keyId,
      periodId,
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Get the key-wrapping key for a period key ID.
   * Useful when you need the raw key for custom logic.
   */
  async getPeriodKey(keyId: string, periodId: string): Promise<Uint8Array> {
    return derivePeriodKey(this.periodSecret, keyId, periodId);
  }

  /**
   * Get the key-wrapping key for a content ID, wrapped with user's RSA public key.
   *
   * This enables "unlock once, access all" for shared content:
   * - Client receives the AES-KW key (not the content key)
   * - Client can unwrap any article's content key locally
   * - No per-article unlock requests needed
   *
   * @param contentId - The content identifier (e.g., "premium")
   * @param periodId - The period ID to get the key for
   * @param userPublicKeyB64 - User's RSA public key (Base64 SPKI format)
   */
  async getSharedKeyForUser(
    contentId: string,
    periodId: string,
    userPublicKeyB64: string,
  ): Promise<UnlockResponse> {
    if (!this.isPeriodValid(periodId)) {
      throw new Error(`Period ${periodId} is expired or invalid`);
    }

    const keyWrappingKey = await derivePeriodKey(
      this.periodSecret,
      contentId,
      periodId,
    );
    const expiresAt = getPeriodExpiration(periodId, this.periodDurationSeconds);

    const pubKey = await importRsaPublicKey(userPublicKeyB64);
    const encryptedKey = await rsaOaepEncrypt(pubKey, keyWrappingKey);

    return {
      encryptedContentKey: toBase64(encryptedKey), // Actually the KEK, not content key
      keyId: `${contentId}:${periodId}`,
      periodId,
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Unlock content using a pre-signed token.
   *
   * This is the recommended flow for share links:
   * 1. Publisher generates token with content access
   * 2. Reader clicks share link, page loads with encrypted content
   * 3. Client sends token + wrappedContentKey + publicKey
   * 4. Server validates token, unwraps content key, re-wraps for reader
   *
   * Benefits:
   * - Full audit trail (every unlock is logged)
   * - Works without user authentication
   * - Supports usage limits and expiration
   *
   * @param tokenPayload - Validated token payload (from TokenManager.validate())
   * @param wrappedContentKeyB64 - Base64 wrapped content key from the article
   * @param userPublicKeyB64 - Reader's RSA public key (Base64 SPKI)
   * @param expectedContentId - Optional content ID for validation (compared against token.contentId)
   * @returns Unlock response with content key wrapped for the reader
   */
  async unlockWithToken(
    tokenPayload: UnlockTokenPayload,
    wrappedContentKeyB64: string,
    userPublicKeyB64: string,
    expectedContentId?: string,
  ): Promise<UnlockResponse> {
    const { contentId } = tokenPayload;

    // Validate contentId matches
    if (expectedContentId && contentId !== expectedContentId) {
      throw new Error(
        `Token is for content '${contentId}', not '${expectedContentId}'`,
      );
    }

    // Parse the wrapped content key to extract the period ID from the keyId
    // The wrappedContentKey comes from the article, which has keyId like "premium:123456"
    const wrappedContentKeyBytes = fromBase64(wrappedContentKeyB64);

    // For token-based unlock, we need to try current and adjacent periods
    // since the article might have been encrypted in a different period
    const currentPeriodNum = parseInt(
      getCurrentPeriod(this.periodDurationSeconds),
      10,
    );
    const periodsToTry = [
      currentPeriodNum.toString(),
      (currentPeriodNum - 1).toString(),
      (currentPeriodNum + 1).toString(),
    ];

    let lastError: Error | null = null;

    for (const periodId of periodsToTry) {
      try {
        const keyWrappingKey = await derivePeriodKey(
          this.periodSecret,
          contentId,
          periodId,
        );
        const contentKey = await unwrapContentKey(wrappedContentKeyBytes, keyWrappingKey);

        // Success! Re-wrap for user
        const pubKey = await importRsaPublicKey(userPublicKeyB64);
        const encryptedContentKey = await rsaOaepEncrypt(pubKey, contentKey);

        const expiresAt = getPeriodExpiration(
          periodId,
          this.periodDurationSeconds,
        );

        return {
          encryptedContentKey: toBase64(encryptedContentKey),
          keyId: `${contentId}:${periodId}`,
          periodId,
          expiresAt: expiresAt.toISOString(),
        };
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        // Try next period
      }
    }

    throw new Error(
      `Failed to unlock with token for contentId '${contentId}': ${lastError?.message}`,
    );
  }
}

/**
 * Create a subscription server for handling unlock requests.
 *
 * @example
 * ```typescript
 * const server = createSubscriptionServer({
 *   periodSecret: process.env.PERIOD_SECRET,
 *   periodDurationSeconds: 30,
 * });
 *
 * app.post('/api/unlock', async (req, res) => {
 *   const { keyId, wrappedContentKey, publicKey } = req.body;
 *   const result = await server.unlockForUser({ keyId, wrappedContentKey }, publicKey);
 *   res.json(result);
 * });
 * ```
 */
export function createSubscriptionServer(
  options: SubscriptionServerOptions,
): SubscriptionServer {
  return new SubscriptionServer(options);
}
