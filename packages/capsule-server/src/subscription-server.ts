/**
 * Subscription Server Utilities
 * 
 * For building subscription server endpoints that:
 * 1. Provide bucket keys to CMS (for encryption)
 * 2. Unwrap DEKs for authenticated users (for decryption)
 */

import { publicEncrypt, constants, createPublicKey } from "crypto";
import { deriveBucketKey, getBucketKeys, getCurrentBucket, getBucketExpiration, isBucketValid, DEFAULT_BUCKET_PERIOD_SECONDS } from "./time-buckets";
import { unwrapDek } from "./encryption";
import type { BucketKey, UnlockResponse, WrappedKey } from "./types";

export interface SubscriptionServerOptions {
  /** Master secret for deriving bucket keys (base64 encoded) */
  masterSecret: string;
  /** Bucket period in seconds (default: 30) */
  bucketPeriodSeconds?: number;
}

/**
 * Subscription Server for Capsule.
 * 
 * Manages master secret and provides:
 * - Bucket keys for CMS (time-limited)
 * - DEK unwrapping for authenticated users
 */
export class SubscriptionServer {
  private masterSecret: Buffer;
  private bucketPeriodSeconds: number;

  constructor(options: SubscriptionServerOptions) {
    this.masterSecret = Buffer.from(options.masterSecret, "base64");
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
   * @param staticKeyLookup - Optional function to look up static keys (for per-article keys)
   */
  async unlockForUser(
    wrappedKey: WrappedKey,
    userPublicKeyB64: string,
    staticKeyLookup?: (keyId: string) => Buffer | null
  ): Promise<UnlockResponse> {
    const { keyId, wrappedDek } = wrappedKey;
    const wrappedDekBuffer = Buffer.from(wrappedDek, "base64");

    // Parse keyId to determine if it's a bucket key or static key
    // Format: "tier:bucketId" for bucket keys, or just "keyId" for static keys
    const [baseKeyId, bucketId] = keyId.includes(":") 
      ? keyId.split(":") 
      : [keyId, null];

    let keyWrappingKey: Buffer;
    let expiresAt: Date;

    if (bucketId) {
      // Time-bucket key - validate and derive
      if (!this.isBucketValid(bucketId)) {
        throw new Error(`Bucket ${bucketId} is expired or invalid`);
      }
      keyWrappingKey = deriveBucketKey(this.masterSecret, baseKeyId, bucketId);
      expiresAt = getBucketExpiration(bucketId, this.bucketPeriodSeconds);
    } else {
      // Static key - look up
      if (!staticKeyLookup) {
        throw new Error(`Static key lookup required for keyId: ${keyId}`);
      }
      const staticKey = staticKeyLookup(keyId);
      if (!staticKey) {
        throw new Error(`Unknown static key: ${keyId}`);
      }
      keyWrappingKey = staticKey;
      // Static keys use current bucket expiration for client cache timing
      const currentBucket = getCurrentBucket(this.bucketPeriodSeconds);
      expiresAt = getBucketExpiration(currentBucket, this.bucketPeriodSeconds);
    }

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
      bucketId: bucketId ?? undefined,
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

    const [, bucketId] = keyId.includes(":") ? keyId.split(":") : [keyId, null];

    return {
      encryptedDek: encryptedDek.toString("base64"),
      keyId,
      bucketId: bucketId ?? undefined,
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
 * Create a subscription server instance.
 */
export function createSubscriptionServer(
  masterSecret: string | Buffer,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): SubscriptionServer {
  const secret = typeof masterSecret === "string"
    ? masterSecret
    : masterSecret.toString("base64");

  return new SubscriptionServer({
    masterSecret: secret,
    bucketPeriodSeconds,
  });
}
