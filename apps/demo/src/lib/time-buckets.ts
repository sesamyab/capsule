/**
 * Time-bucket key derivation using HKDF.
 * 
 * Derives deterministic AES-256 keys from a master secret and time bucket ID.
 * Bucket keys rotate based on configured interval.
 * 
 * Supports two modes:
 * - TOTP: Keys derived locally (no API calls)
 * - API: Keys fetched from subscription server
 */

import { createHmac, randomBytes, timingSafeEqual } from "crypto";

/**
 * Configuration from environment variables
 */
export type KeyExchangeMethod = "totp" | "api";

/** Key exchange method: "totp" (default) or "api" */
export const KEY_EXCHANGE_METHOD: KeyExchangeMethod = 
  (process.env.CAPSULE_KEY_METHOD as KeyExchangeMethod) || "totp";

/** Bucket duration in seconds (default: 30 seconds for TOTP) */
export const BUCKET_PERIOD_SECONDS = parseInt(
  process.env.CAPSULE_BUCKET_PERIOD || "30", 
  10
);

/** Bucket duration in milliseconds */
export const BUCKET_DURATION_MS = BUCKET_PERIOD_SECONDS * 1000;

/**
 * Master/shared secret for deriving bucket keys.
 * In production, store this in KMS (AWS Secrets Manager, Google Secret Manager, etc.)
 */
const MASTER_SECRET = process.env.CAPSULE_MASTER_SECRET 
  ? Buffer.from(process.env.CAPSULE_MASTER_SECRET, "base64")
  : (() => {
      const secret = randomBytes(32);
      console.log("[Capsule] Generated demo secret:", secret.toString("base64"));
      console.log("[Capsule] Key method:", KEY_EXCHANGE_METHOD);
      console.log("[Capsule] Bucket period:", BUCKET_PERIOD_SECONDS, "seconds");
      return secret;
    })();

/** Export for client display */
export function getConfig() {
  return {
    method: KEY_EXCHANGE_METHOD,
    bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
    hasCustomSecret: !!process.env.CAPSULE_MASTER_SECRET
  };
}

/**
 * Get the current time bucket ID.
 * Uses seconds-based calculation (TOTP standard).
 */
export function getCurrentBucket(): string {
  const now = Math.floor(Date.now() / 1000); // Unix timestamp in seconds
  const bucketNum = Math.floor(now / BUCKET_PERIOD_SECONDS);
  return bucketNum.toString();
}

/**
 * Get the next time bucket ID.
 */
export function getNextBucket(): string {
  const current = parseInt(getCurrentBucket());
  return (current + 1).toString();
}

/**
 * Get the previous time bucket ID.
 */
export function getPreviousBucket(): string {
  const current = parseInt(getCurrentBucket());
  return (current - 1).toString();
}

/**
 * Get when a bucket expires.
 */
export function getBucketExpiration(bucketId: string): Date {
  const bucketNum = parseInt(bucketId);
  const expiresAt = (bucketNum + 1) * BUCKET_PERIOD_SECONDS * 1000;
  return new Date(expiresAt);
}

/**
 * Check if a bucket is still valid (current, next, or previous for grace period).
 */
export function isBucketValid(bucketId: string): boolean {
  const current = getCurrentBucket();
  const next = getNextBucket();
  const previous = getPreviousBucket();
  return bucketId === current || bucketId === next || bucketId === previous;
}

/**
 * HKDF (HMAC-based Key Derivation Function) implementation.
 * 
 * @param ikm - Input key material (master secret)
 * @param salt - Salt value (bucket ID)
 * @param info - Context information
 * @param length - Output length in bytes
 */
function hkdf(
  ikm: Buffer,
  salt: Buffer,
  info: Buffer,
  length: number
): Buffer {
  // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
  const prk = createHmac("sha256", salt).update(ikm).digest();
  
  // HKDF-Expand: OKM = HMAC-Hash(PRK, T(0) | info | 0x01)
  const okm = Buffer.alloc(length);
  let previousBlock = Buffer.alloc(0);
  let counter = 1;
  let offset = 0;
  
  while (offset < length) {
    const hmac = createHmac("sha256", prk);
    hmac.update(previousBlock);
    hmac.update(info);
    hmac.update(Buffer.from([counter]));
    
    previousBlock = hmac.digest();
    const remaining = length - offset;
    const toCopy = Math.min(remaining, previousBlock.length);
    
    previousBlock.copy(okm, offset, 0, toCopy);
    offset += toCopy;
    counter++;
  }
  
  return okm;
}

/**
 * Derive a time-bucket key for a specific tier and bucket.
 * 
 * @param tier - Subscription tier (e.g., "premium", "basic")
 * @param bucketId - Time bucket identifier
 * @returns 256-bit AES key material
 */
export function deriveBucketKey(tier: string, bucketId: string): Buffer {
  const salt = Buffer.from(bucketId, "utf8");
  const info = Buffer.from(`capsule-bucket-${tier}`, "utf8");
  
  return hkdf(MASTER_SECRET, salt, info, 32); // 32 bytes = 256 bits
}

/**
 * Get bucket keys for current and next time windows.
 */
export function getCurrentBucketKeys(tier: string): {
  current: { bucketId: string; key: Buffer; expiresAt: Date };
  next: { bucketId: string; key: Buffer; expiresAt: Date };
} {
  const currentBucket = getCurrentBucket();
  const nextBucket = getNextBucket();
  
  return {
    current: {
      bucketId: currentBucket,
      key: deriveBucketKey(tier, currentBucket),
      expiresAt: getBucketExpiration(currentBucket)
    },
    next: {
      bucketId: nextBucket,
      key: deriveBucketKey(tier, nextBucket),
      expiresAt: getBucketExpiration(nextBucket)
    }
  };
}

/**
 * Wrap (encrypt) a DEK with a bucket key using AES-256-GCM.
 */
export function wrapDekWithBucketKey(dek: Buffer, bucketKey: Buffer): Buffer {
  const { createCipheriv } = require("crypto");
  
  const iv = randomBytes(12); // 96-bit IV for GCM
  const cipher = createCipheriv("aes-256-gcm", bucketKey, iv);
  
  const encrypted = Buffer.concat([
    cipher.update(dek),
    cipher.final()
  ]);
  
  const authTag = cipher.getAuthTag();
  
  // Format: [IV (12 bytes) | Ciphertext | Auth Tag (16 bytes)]
  return Buffer.concat([iv, encrypted, authTag]);
}

/**
 * Unwrap (decrypt) a DEK with a bucket key using AES-256-GCM.
 */
export function unwrapDekWithBucketKey(wrappedDek: Buffer, bucketKey: Buffer): Buffer {
  const { createDecipheriv } = require("crypto");
  
  // Parse format: [IV (12 bytes) | Ciphertext | Auth Tag (16 bytes)]
  const iv = wrappedDek.subarray(0, 12);
  const authTag = wrappedDek.subarray(wrappedDek.length - 16);
  const ciphertext = wrappedDek.subarray(12, wrappedDek.length - 16);
  
  const decipher = createDecipheriv("aes-256-gcm", bucketKey, iv);
  decipher.setAuthTag(authTag);
  
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
}

/**
 * Constant-time string comparison to prevent timing attacks.
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
