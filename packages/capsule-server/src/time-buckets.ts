/**
 * Time-bucket key derivation using HKDF (TOTP-style).
 *
 * Derives deterministic AES-256 keys from a master secret and time bucket ID.
 * Keys rotate every `bucketPeriodSeconds` (default: 30 seconds like TOTP).
 * Uses Web Crypto API for cross-platform compatibility.
 */

import {
  hkdf,
  getRandomBytes,
} from "./web-crypto";
import type { BucketKey } from "./types";

/** Default bucket period in seconds (30s like TOTP) */
export const DEFAULT_BUCKET_PERIOD_SECONDS = 30;

// Re-export HKDF for any consumers that need it
export { hkdf };

/**
 * Get the bucket ID for a given timestamp.
 */
export function getBucketId(
  timestampMs: number = Date.now(),
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS,
): string {
  const timestampSec = Math.floor(timestampMs / 1000);
  const bucketNum = Math.floor(timestampSec / bucketPeriodSeconds);
  return bucketNum.toString();
}

/**
 * Get the current bucket ID.
 */
export function getCurrentBucket(
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS,
): string {
  return getBucketId(Date.now(), bucketPeriodSeconds);
}

/**
 * Get the next bucket ID.
 */
export function getNextBucket(
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS,
): string {
  const current = parseInt(getCurrentBucket(bucketPeriodSeconds));
  return (current + 1).toString();
}

/**
 * Get the previous bucket ID.
 */
export function getPreviousBucket(
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS,
): string {
  const current = parseInt(getCurrentBucket(bucketPeriodSeconds));
  return (current - 1).toString();
}

/**
 * Get when a bucket expires.
 */
export function getBucketExpiration(
  bucketId: string,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS,
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
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS,
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
export async function deriveBucketKey(
  masterSecret: Uint8Array,
  keyId: string,
  bucketId: string,
): Promise<Uint8Array> {
  const info = `capsule-bucket-${keyId}`;
  return hkdf(masterSecret, bucketId, info, 32);
}

/**
 * Get bucket key with metadata.
 */
export async function getBucketKey(
  masterSecret: Uint8Array,
  keyId: string,
  bucketId: string,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS,
): Promise<BucketKey> {
  return {
    bucketId,
    key: await deriveBucketKey(masterSecret, keyId, bucketId),
    expiresAt: getBucketExpiration(bucketId, bucketPeriodSeconds),
  };
}

/**
 * Get current and next bucket keys for a key ID.
 * Used by CMS to wrap content DEKs for both time windows.
 */
export async function getBucketKeys(
  masterSecret: Uint8Array,
  keyId: string,
  bucketPeriodSeconds: number = DEFAULT_BUCKET_PERIOD_SECONDS,
): Promise<{ current: BucketKey; next: BucketKey }> {
  const currentBucketId = getCurrentBucket(bucketPeriodSeconds);
  const nextBucketId = getNextBucket(bucketPeriodSeconds);

  const [current, next] = await Promise.all([
    getBucketKey(masterSecret, keyId, currentBucketId, bucketPeriodSeconds),
    getBucketKey(masterSecret, keyId, nextBucketId, bucketPeriodSeconds),
  ]);

  return { current, next };
}

/**
 * Generate a new master secret (256-bit random).
 */
export function generateMasterSecret(): Uint8Array {
  return getRandomBytes(32);
}
