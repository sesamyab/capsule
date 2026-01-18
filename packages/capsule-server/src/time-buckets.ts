/**
 * Time-bucket key derivation using HKDF (TOTP-style).
 * 
 * Derives deterministic AES-256 keys from a master secret and time bucket ID.
 * Keys rotate every `bucketPeriodSeconds` (default: 30 seconds like TOTP).
 */

import { createHmac, randomBytes } from "crypto";
import type { BucketKey } from "./types";

/** Default bucket period in seconds (30s like TOTP) */
export const DEFAULT_BUCKET_PERIOD_SECONDS = 30;

/**
 * HKDF-Extract: Extract a pseudorandom key from input keying material.
 */
function hkdfExtract(ikm: Buffer, salt: Buffer): Buffer {
  return createHmac("sha256", salt).update(ikm).digest();
}

/**
 * HKDF-Expand: Expand a pseudorandom key into output keying material.
 */
function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
  const hashLen = 32; // SHA-256 output length
  const n = Math.ceil(length / hashLen);
  const okm = Buffer.alloc(n * hashLen);
  
  let t = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    const hmac = createHmac("sha256", prk);
    hmac.update(t);
    hmac.update(info);
    hmac.update(Buffer.from([i]));
    t = hmac.digest();
    t.copy(okm, (i - 1) * hashLen);
  }
  
  return okm.subarray(0, length);
}

/**
 * HKDF key derivation function (RFC 5869).
 * Derives a key from input keying material using HMAC-SHA256.
 */
export function hkdf(
  ikm: Buffer,
  salt: Buffer | string,
  info: Buffer | string,
  length: number
): Buffer {
  const saltBuf = typeof salt === "string" ? Buffer.from(salt) : salt;
  const infoBuf = typeof info === "string" ? Buffer.from(info) : info;
  
  const prk = hkdfExtract(ikm, saltBuf);
  return hkdfExpand(prk, infoBuf, length);
}

/**
 * Get the bucket ID for a given timestamp.
 */
export function getBucketId(
  timestampMs: number = Date.now(),
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): string {
  const timestampSec = Math.floor(timestampMs / 1000);
  const bucketNum = Math.floor(timestampSec / bucketPeriodSeconds);
  return bucketNum.toString();
}

/**
 * Get the current bucket ID.
 */
export function getCurrentBucket(
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): string {
  return getBucketId(Date.now(), bucketPeriodSeconds);
}

/**
 * Get the next bucket ID.
 */
export function getNextBucket(
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): string {
  const current = parseInt(getCurrentBucket(bucketPeriodSeconds));
  return (current + 1).toString();
}

/**
 * Get the previous bucket ID.
 */
export function getPreviousBucket(
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): string {
  const current = parseInt(getCurrentBucket(bucketPeriodSeconds));
  return (current - 1).toString();
}

/**
 * Get when a bucket expires.
 */
export function getBucketExpiration(
  bucketId: string,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): Date {
  const bucketNum = parseInt(bucketId);
  const expiresAtMs = (bucketNum + 1) * bucketPeriodSeconds * 1000;
  return new Date(expiresAtMs);
}

/**
 * Check if a bucket is currently valid (current, next, or previous for grace period).
 */
export function isBucketValid(
  bucketId: string,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): boolean {
  const current = getCurrentBucket(bucketPeriodSeconds);
  const next = getNextBucket(bucketPeriodSeconds);
  const previous = getPreviousBucket(bucketPeriodSeconds);
  return bucketId === current || bucketId === next || bucketId === previous;
}

/**
 * Derive a bucket key from master secret + bucket ID using HKDF.
 * 
 * @param masterSecret - The master secret (256-bit)
 * @param keyId - The key identifier (e.g., tier name like "premium")
 * @param bucketId - The bucket identifier
 * @returns 256-bit AES key
 */
export function deriveBucketKey(
  masterSecret: Buffer,
  keyId: string,
  bucketId: string
): Buffer {
  const info = `capsule-bucket-${keyId}`;
  return hkdf(masterSecret, bucketId, info, 32);
}

/**
 * Get bucket key with metadata.
 */
export function getBucketKey(
  masterSecret: Buffer,
  keyId: string,
  bucketId: string,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): BucketKey {
  return {
    bucketId,
    key: deriveBucketKey(masterSecret, keyId, bucketId),
    expiresAt: getBucketExpiration(bucketId, bucketPeriodSeconds),
  };
}

/**
 * Get current and next bucket keys for a key ID.
 * Used by CMS to wrap content DEKs for both time windows.
 */
export function getBucketKeys(
  masterSecret: Buffer,
  keyId: string,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS
): { current: BucketKey; next: BucketKey } {
  const currentBucketId = getCurrentBucket(bucketPeriodSeconds);
  const nextBucketId = getNextBucket(bucketPeriodSeconds);
  
  return {
    current: getBucketKey(masterSecret, keyId, currentBucketId, bucketPeriodSeconds),
    next: getBucketKey(masterSecret, keyId, nextBucketId, bucketPeriodSeconds),
  };
}

/**
 * Generate a new master secret (256-bit random).
 */
export function generateMasterSecret(): Buffer {
  return randomBytes(32);
}
