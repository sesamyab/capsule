/**
 * Server-side encryption keys for different subscription tiers and articles.
 * 
 * TIER KEYS: Derived from master secret + time bucket using HKDF.
 * This provides forward secrecy - old bucket keys can't decrypt new content.
 * 
 * ARTICLE KEYS: Static per-article DEKs (for permanent article-specific access).
 * In production, these would be stored in a KMS.
 */

import { deriveBucketKey, getCurrentBucket, getNextBucket, getBucketExpiration } from "./time-buckets";

/** Valid subscription tiers */
export const VALID_TIERS = ["premium", "basic"] as const;
export type SubscriptionTier = typeof VALID_TIERS[number];

// Per-article DEKs (for article-specific access control)
// These are static - once purchased, the article is accessible forever
export const ARTICLE_KEYS: Record<string, { dek: string }> = {
  "premium-guide": {
    dek: "xQGvT8HnJkLmPq2Rs3TuVw4XyZ0A1B2C3D4E5F6G7H8=",
  },
  "crypto-basics": {
    dek: "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V=",
  },
};

/**
 * Check if a tier is valid.
 */
export function isValidTier(tier: string): tier is SubscriptionTier {
  return VALID_TIERS.includes(tier as SubscriptionTier);
}

/**
 * Get the DEK for a subscription tier at a specific time bucket.
 * The DEK is derived using HKDF from master secret + bucket ID.
 */
export function getSubscriptionKey(tier: string, bucketId?: string): Buffer {
  if (!isValidTier(tier)) {
    throw new Error(`Unknown subscription tier: ${tier}`);
  }
  const bucket = bucketId ?? getCurrentBucket();
  return deriveBucketKey(tier, bucket);
}

/**
 * Get DEKs for both current and next time buckets.
 * Used by CMS to encrypt content for both windows (handles clock drift).
 */
export function getSubscriptionKeysForEncryption(tier: string): {
  current: { bucketId: string; dek: Buffer; expiresAt: Date };
  next: { bucketId: string; dek: Buffer; expiresAt: Date };
} {
  if (!isValidTier(tier)) {
    throw new Error(`Unknown subscription tier: ${tier}`);
  }
  
  const currentBucket = getCurrentBucket();
  const nextBucket = getNextBucket();
  
  return {
    current: {
      bucketId: currentBucket,
      dek: deriveBucketKey(tier, currentBucket),
      expiresAt: getBucketExpiration(currentBucket),
    },
    next: {
      bucketId: nextBucket,
      dek: deriveBucketKey(tier, nextBucket),
      expiresAt: getBucketExpiration(nextBucket),
    },
  };
}

/**
 * Get the DEK for a specific article.
 * Article keys are static (not bucket-based) for permanent access.
 */
export function getArticleKey(articleId: string): Buffer {
  const keyData = ARTICLE_KEYS[articleId];
  if (!keyData) {
    throw new Error(`No article-specific key for: ${articleId}`);
  }
  return Buffer.from(keyData.dek, "base64");
}

/**
 * Check if an article has its own specific key.
 */
export function hasArticleKey(articleId: string): boolean {
  return articleId in ARTICLE_KEYS;
}
