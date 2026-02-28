/**
 * Server-side encryption keys for different content IDs and articles.
 * 
 * SHARED KEYS: Derived from period secret + time period using HKDF via @sesamy/capsule-server.
 * This provides forward secrecy - old period keys can't decrypt new content.
 * 
 * ARTICLE KEYS: Static per-content keys (for permanent article-specific access).
 * In production, these would be stored in a KMS.
 */

import {
  derivePeriodKey as derivePeriodKeyFromServer,
  getCurrentPeriod,
  getNextPeriod,
  getPeriodExpiration,
} from "@sesamy/capsule-server";
import { PERIOD_SECRET, PERIOD_DURATION_SECONDS } from "./time-periods";

/** Valid content IDs */
export const VALID_CONTENT_IDS = ["premium", "basic"] as const;
export type ContentId = typeof VALID_CONTENT_IDS[number];

// Per-content keys (for article-specific access control)
// These are static - once purchased, the article is accessible forever
export const ARTICLE_KEYS: Record<string, { contentKey: string }> = {
  "premium-guide": {
    contentKey: "xQGvT8HnJkLmPq2Rs3TuVw4XyZ0A1B2C3D4E5F6G7H8=",
  },
  "crypto-basics": {
    contentKey: "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V=",
  },
};

/**
 * Check if a content ID is valid.
 */
export function isValidContentId(contentId: string): contentId is ContentId {
  return VALID_CONTENT_IDS.includes(contentId as ContentId);
}

/**
 * Get the content key for a content ID at a specific time period.
 * The content key is derived using HKDF from period secret + period ID.
 */
export async function getSubscriptionKey(contentId: string, periodId?: string): Promise<Uint8Array> {
  if (!isValidContentId(contentId)) {
    throw new Error(`Unknown content ID: ${contentId}`);
  }
  const period = periodId ?? getCurrentPeriod(PERIOD_DURATION_SECONDS);
  return await derivePeriodKeyFromServer(PERIOD_SECRET, contentId, period);
}

/**
 * Get DEKs for both current and next time periods.
 * Used by CMS to encrypt content for both windows (handles clock drift).
 */
export async function getSubscriptionKeysForEncryption(contentId: string): Promise<{
  current: { periodId: string; contentKey: Uint8Array; expiresAt: Date };
  next: { periodId: string; contentKey: Uint8Array; expiresAt: Date };
}> {
  if (!isValidContentId(contentId)) {
    throw new Error(`Unknown content ID: ${contentId}`);
  }

  const currentPeriod = getCurrentPeriod(PERIOD_DURATION_SECONDS);
  const nextPeriod = getNextPeriod(PERIOD_DURATION_SECONDS);

  return {
    current: {
      periodId: currentPeriod,
      contentKey: await derivePeriodKeyFromServer(PERIOD_SECRET, contentId, currentPeriod),
      expiresAt: getPeriodExpiration(currentPeriod, PERIOD_DURATION_SECONDS),
    },
    next: {
      periodId: nextPeriod,
      contentKey: await derivePeriodKeyFromServer(PERIOD_SECRET, contentId, nextPeriod),
      expiresAt: getPeriodExpiration(nextPeriod, PERIOD_DURATION_SECONDS),
    },
  };
}

/**
 * Get the content key for a specific article.
 * Article keys are static (not period-based) for permanent access.
 */
export function getArticleKey(contentId: string): Uint8Array {
  const keyData = ARTICLE_KEYS[contentId];
  if (!keyData) {
    throw new Error(`No article-specific key for: ${contentId}`);
  }
  // Decode base64 to Uint8Array
  const binaryString = atob(keyData.contentKey);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Check if an article has its own specific key.
 */
export function hasArticleKey(contentId: string): boolean {
  return contentId in ARTICLE_KEYS;
}
