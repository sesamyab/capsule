/**
 * Time-bucket utilities for the demo app.
 * 
 * Re-exports from @sesamy/capsule-server with some demo-specific wrappers.
 */

import { timingSafeEqual } from "crypto";
import {
  deriveBucketKey as deriveBucketKeyBase,
  getCurrentBucket as getCurrentBucketBase,
  getNextBucket as getNextBucketBase,
  getPreviousBucket as getPreviousBucketBase,
  getBucketExpiration as getBucketExpirationBase,
  getBucketId,
  isBucketValid as isBucketValidBase,
  DEFAULT_BUCKET_PERIOD_SECONDS,
} from "@sesamy/capsule-server";

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
export const MASTER_SECRET = process.env.CAPSULE_MASTER_SECRET 
  ? Buffer.from(process.env.CAPSULE_MASTER_SECRET, "base64")
  : (() => {
      const { randomBytes } = require("crypto");
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
  return getCurrentBucketBase(BUCKET_PERIOD_SECONDS);
}

/**
 * Get the next time bucket ID.
 */
export function getNextBucket(): string {
  return getNextBucketBase(BUCKET_PERIOD_SECONDS);
}

/**
 * Get the previous time bucket ID.
 */
export function getPreviousBucket(): string {
  return getPreviousBucketBase(BUCKET_PERIOD_SECONDS);
}

/**
 * Get when a bucket expires.
 */
export function getBucketExpiration(bucketId: string): Date {
  return getBucketExpirationBase(bucketId, BUCKET_PERIOD_SECONDS);
}

/**
 * Check if a bucket is still valid (current, next, or previous for grace period).
 */
export function isBucketValid(bucketId: string): boolean {
  return isBucketValidBase(bucketId, BUCKET_PERIOD_SECONDS);
}

/**
 * Derive a time-bucket key for a specific tier and bucket.
 * 
 * @param tier - Subscription tier (e.g., "premium", "basic")
 * @param bucketId - Time bucket identifier
 * @returns 256-bit AES key material
 */
export function deriveBucketKey(tier: string, bucketId: string): Buffer {
  return deriveBucketKeyBase(MASTER_SECRET, tier, bucketId);
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
 * Constant-time string comparison to prevent timing attacks.
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// Re-export defaults
export { DEFAULT_BUCKET_PERIOD_SECONDS, getBucketId };
