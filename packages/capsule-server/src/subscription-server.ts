/**
 * Subscription Server Utilities
 * 
 * For building subscription server endpoints that:
 * 1. Provide bucket keys to CMS (for encryption)
 * 2. Unwrap DEKs for authenticated users (for decryption)
 * 
 * @example
 * ```typescript
 * import { createSubscriptionServer } from '@sesamy/capsule-server';
 * 
 * const server = createSubscriptionServer({
 *   masterSecret: process.env.MASTER_SECRET,
 *   bucketPeriodSeconds: 30,
 * });
 * 
 * // Endpoint for users to unlock content
 * app.post('/api/unlock', async (req, res) => {
 *   const { keyId, wrappedDek, publicKey } = req.body;
 *   const result = await server.unlockForUser({ keyId, wrappedDek }, publicKey);
 *   res.json(result);
 * });
 * ```
 */

import { publicEncrypt, constants, createPublicKey } from "crypto";
import { deriveBucketKey, getBucketKeys, getCurrentBucket, getBucketExpiration, isBucketValid, DEFAULT_BUCKET_PERIOD_SECONDS } from "./time-buckets";
import { unwrapDek } from "./encryption";
import type { BucketKey, UnlockResponse, WrappedKey } from "./types";

/** Check if a string looks like a numeric bucket ID */
function isNumericBucketId(str: string): boolean {
  return /^\d+$/.test(str);
}

/** Options for creating a subscription server */
export interface SubscriptionServerOptions {
  /** Master secret for deriving bucket keys (base64 encoded string or Buffer) */
  masterSecret: string | Buffer;
  /** Bucket period in seconds (default: 30) */
  bucketPeriodSeconds?: number;
}

/**
 * Subscription Server for Capsule.
 * 
 * Manages master secret and provides:
 * - Bucket keys for CMS (time-limited)
 * - DEK unwrapping for authenticated users
 * 
 * @see createSubscriptionServer for the recommended way to create an instance
 */
export class SubscriptionServer {
  private masterSecret: Buffer;
  private bucketPeriodSeconds: number;

  constructor(options: SubscriptionServerOptions) {
    this.masterSecret = Buffer.isBuffer(options.masterSecret)
      ? options.masterSecret
      : Buffer.from(options.masterSecret, "base64");
    this.bucketPeriodSeconds = options.bucketPeriodSeconds ?? DEFAULT_BUCKET_PERIOD_SECONDS;
  }

  /**
   * Get bucket keys for a key ID (for CMS).
   * 
   * Returns current and next bucket keys so CMS can encrypt
   * content that works across bucket boundaries.
   */
  getBucketKeysForCms(keyId: string): { current: BucketKey; next: BucketKey } {
    return getBucketKeys(this.masterSecret, keyId, this.bucketPeriodSeconds);
  }

  /**
   * Get bucket keys formatted for API response.
   */
  getBucketKeysResponse(keyId: string): {
    current: { bucketId: string; key: string; expiresAt: string };
    next: { bucketId: string; key: string; expiresAt: string };
  } {
    const keys = this.getBucketKeysForCms(keyId);
    return {
      current: {
        bucketId: keys.current.bucketId,
        key: keys.current.key.toString("base64"),
        expiresAt: keys.current.expiresAt.toISOString(),
      },
      next: {
        bucketId: keys.next.bucketId,
        key: keys.next.key.toString("base64"),
        expiresAt: keys.next.expiresAt.toISOString(),
      },
    };
  }

  /**
   * Validate that a bucket ID is current or adjacent.
   */
  isBucketValid(bucketId: string): boolean {
    return isBucketValid(bucketId, this.bucketPeriodSeconds);
  }

  /**
   * Unwrap a DEK and re-wrap it with a user's RSA public key.
   * 
   * This is the core unlock operation:
   * 1. Parse the wrapped key to extract keyId and bucket info
   * 2. Derive the key-wrapping key from master secret
   * 3. Unwrap the DEK
   * 4. Re-wrap with user's RSA public key
   * 
   * @param wrappedKey - The wrapped key entry from the article
   * @param userPublicKeyB64 - User's RSA public key (Base64 SPKI format)
   * @param staticKeyLookup - Optional function to look up static keys (for per-article keys). Can be sync or async.
   */
  async unlockForUser(
    wrappedKey: WrappedKey,
    userPublicKeyB64: string,
    staticKeyLookup?: (keyId: string) => Buffer | null | Promise<Buffer | null>
  ): Promise<UnlockResponse> {
    const { keyId, wrappedDek } = wrappedKey;
    const wrappedDekBuffer = Buffer.from(wrappedDek, "base64");

    let keyWrappingKey: Buffer;
    let expiresAt: Date;

    // First, try static key lookup if provided (handles "article:xxx" keys)
    if (staticKeyLookup) {
      const staticKey = await Promise.resolve(staticKeyLookup(keyId));
      if (staticKey) {
        keyWrappingKey = staticKey;
        // Static keys use current bucket expiration for client cache timing
        const currentBucket = getCurrentBucket(this.bucketPeriodSeconds);
        expiresAt = getBucketExpiration(currentBucket, this.bucketPeriodSeconds);
        
        // Unwrap and re-wrap
        return this.unwrapAndRewrap(wrappedDekBuffer, keyWrappingKey, userPublicKeyB64, keyId, undefined, expiresAt);
      }
    }

    // Parse keyId as bucket key: "tier:bucketId" (only if suffix is numeric)
    const colonIndex = keyId.lastIndexOf(":");
    if (colonIndex === -1) {
      throw new Error(`Invalid keyId format: ${keyId}. Expected 'tier:bucketId' or use staticKeyLookup for static keys.`);
    }

    const baseKeyId = keyId.substring(0, colonIndex);
    const suffix = keyId.substring(colonIndex + 1);

    // Only treat as bucket key if suffix is numeric
    if (!isNumericBucketId(suffix)) {
      throw new Error(`No static key found for '${keyId}' and suffix '${suffix}' is not a valid bucket ID. Provide a staticKeyLookup function.`);
    }

    const bucketId = suffix;

    // Time-bucket key - validate and derive
    if (!this.isBucketValid(bucketId)) {
      throw new Error(`Bucket ${bucketId} is expired or invalid`);
    }
    keyWrappingKey = deriveBucketKey(this.masterSecret, baseKeyId, bucketId);
    expiresAt = getBucketExpiration(bucketId, this.bucketPeriodSeconds);

    return this.unwrapAndRewrap(wrappedDekBuffer, keyWrappingKey, userPublicKeyB64, keyId, bucketId, expiresAt);
  }

  /**
   * Internal helper to unwrap DEK and re-wrap with user's public key.
   */
  private async unwrapAndRewrap(
    wrappedDekBuffer: Buffer,
    keyWrappingKey: Buffer,
    userPublicKeyB64: string,
    keyId: string,
    bucketId: string | undefined,
    expiresAt: Date
  ): Promise<UnlockResponse> {
    // Unwrap the DEK
    const dek = unwrapDek(wrappedDekBuffer, keyWrappingKey);

    // Convert user's public key to PEM format
    const publicKeyPem = this.convertToPem(userPublicKeyB64);
    const pubKey = createPublicKey(publicKeyPem);

    // Re-wrap DEK with user's RSA public key
    const encryptedDek = publicEncrypt(
      {
        key: pubKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      dek
    );

    return {
      encryptedDek: encryptedDek.toString("base64"),
      keyId,
      bucketId,
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Simple unlock when you already have the key-wrapping key.
   * Used when the unlock logic is separate from bucket key derivation.
   */
  wrapDekForUser(
    dek: Buffer,
    userPublicKeyB64: string,
    keyId: string,
    expiresAt: Date
  ): UnlockResponse {
    const publicKeyPem = this.convertToPem(userPublicKeyB64);
    const pubKey = createPublicKey(publicKeyPem);

    const encryptedDek = publicEncrypt(
      {
        key: pubKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      dek
    );

    // Only extract bucketId if suffix is numeric (otherwise it's a static key like "article:crypto-guide")
    let bucketId: string | undefined;
    const colonIndex = keyId.lastIndexOf(":");
    if (colonIndex !== -1) {
      const suffix = keyId.substring(colonIndex + 1);
      if (isNumericBucketId(suffix)) {
        bucketId = suffix;
      }
    }

    return {
      encryptedDek: encryptedDek.toString("base64"),
      keyId,
      bucketId,
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Get the key-wrapping key for a bucket key ID.
   * Useful when you need the raw key for custom logic.
   */
  getBucketKey(keyId: string, bucketId: string): Buffer {
    return deriveBucketKey(this.masterSecret, keyId, bucketId);
  }

  /**
   * Get the key-wrapping key for a tier, wrapped with user's RSA public key.
   * 
   * This enables "unlock once, access all" for tier content:
   * - Client receives the AES-KW key (not the DEK)
   * - Client can unwrap any article's DEK locally
   * - No per-article unlock requests needed
   * 
   * @param tier - The tier name (e.g., "premium")
   * @param bucketId - The bucket ID to get the key for
   * @param userPublicKeyB64 - User's RSA public key (Base64 SPKI format)
   */
  getTierKeyForUser(
    tier: string,
    bucketId: string,
    userPublicKeyB64: string
  ): UnlockResponse {
    if (!this.isBucketValid(bucketId)) {
      throw new Error(`Bucket ${bucketId} is expired or invalid`);
    }

    const keyWrappingKey = deriveBucketKey(this.masterSecret, tier, bucketId);
    const expiresAt = getBucketExpiration(bucketId, this.bucketPeriodSeconds);

    const publicKeyPem = this.convertToPem(userPublicKeyB64);
    const pubKey = createPublicKey(publicKeyPem);

    const encryptedKey = publicEncrypt(
      {
        key: pubKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      keyWrappingKey
    );

    return {
      encryptedDek: encryptedKey.toString("base64"), // Actually the KEK, not DEK
      keyId: `${tier}:${bucketId}`,
      bucketId,
      expiresAt: expiresAt.toISOString(),
    };
  }

  /**
   * Convert Base64 SPKI to PEM format for Node.js crypto.
   */
  private convertToPem(publicKeyB64: string): string {
    const keyDer = Buffer.from(publicKeyB64, "base64");
    const base64Lines: string[] = [];
    const base64 = keyDer.toString("base64");

    for (let i = 0; i < base64.length; i += 64) {
      base64Lines.push(base64.slice(i, i + 64));
    }

    return `-----BEGIN PUBLIC KEY-----\n${base64Lines.join("\n")}\n-----END PUBLIC KEY-----`;
  }
}

/**
 * Create a subscription server for handling unlock requests.
 * 
 * @example
 * ```typescript
 * const server = createSubscriptionServer({
 *   masterSecret: process.env.MASTER_SECRET,
 *   bucketPeriodSeconds: 30,
 * });
 * 
 * app.post('/api/unlock', async (req, res) => {
 *   const { keyId, wrappedDek, publicKey } = req.body;
 *   const result = await server.unlockForUser({ keyId, wrappedDek }, publicKey);
 *   res.json(result);
 * });
 * ```
 */
export function createSubscriptionServer(options: SubscriptionServerOptions): SubscriptionServer;
/**
 * Create a subscription server (legacy signature).
 * @deprecated Use createSubscriptionServer({ masterSecret, bucketPeriodSeconds }) instead
 */
export function createSubscriptionServer(
  masterSecret: string | Buffer,
  bucketPeriodSeconds?: number
): SubscriptionServer;
export function createSubscriptionServer(
  optionsOrSecret: SubscriptionServerOptions | string | Buffer,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): SubscriptionServer {
  // Handle both signatures
  if (typeof optionsOrSecret === 'object' && !Buffer.isBuffer(optionsOrSecret)) {
    return new SubscriptionServer(optionsOrSecret);
  }
  
  // Legacy signature
  const secret = typeof optionsOrSecret === "string"
    ? optionsOrSecret
    : optionsOrSecret.toString("base64");

  return new SubscriptionServer({
    masterSecret: secret,
    bucketPeriodSeconds,
  });
}
