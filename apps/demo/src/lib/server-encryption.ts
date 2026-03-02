/**
 * Server-side encryption utilities using @sesamy/capsule-server.
 *
 * This is a thin wrapper that provides the encrypted article data
 * for the demo pages. The actual encryption is handled by CmsServer.
 */

import { getCms, PERIOD_DURATION_SECONDS } from "./capsule";
import { hasArticleKey } from "./encryption-keys";
import type { EncryptedArticle } from "@sesamy/capsule-server";

// Re-export types for consumers
export type { EncryptedArticle };

/**
 * Cache for encrypted articles, keyed by resourceId.
 * Each entry includes the period ID it was encrypted for.
 */
interface CachedEncryption {
  data: EncryptedArticle;
  periodId: string;
}
const encryptionCache = new Map<string, CachedEncryption>();

/**
 * Get the current time period ID.
 */
function getCurrentPeriodId(): string {
  const now = Math.floor(Date.now() / 1000);
  return String(Math.floor(now / PERIOD_DURATION_SECONDS));
}

/**
 * Get encrypted article for display.
 *
 * Uses the high-level CmsServer API to encrypt content with:
 * - Current and next period keys for the content name (handles clock drift)
 * - Article-specific key if available (for per-article purchases)
 *
 * Caches the encrypted content within a key rotation period so that:
 * - Page refreshes don't break client-side content key caching
 * - The same content key is used consistently within a time window
 */
export async function getEncryptedArticle(
  resourceId: string
): Promise<EncryptedArticle | null> {
  const currentPeriod = getCurrentPeriodId();

  // Check cache - reuse if same period
  const cached = encryptionCache.get(resourceId);
  if (cached && cached.periodId === currentPeriod) {
    return cached.data;
  }

  // Import articles here to avoid circular dependency
  const { articles } = await import("./articles");

  const article = articles[resourceId];
  if (!article) {
    return null;
  }

  // Build key IDs list
  const keyIds = ["premium"];
  if (hasArticleKey(resourceId)) {
    keyIds.push(`article:${resourceId}`);
  }

  // Use CmsServer to encrypt with key IDs
  const encrypted = await getCms().encrypt(resourceId, article.premiumContent, {
    keyIds,
    contentId: "premium",
  });

  // Cache for this rotation period
  encryptionCache.set(resourceId, {
    data: encrypted,
    periodId: currentPeriod,
  });

  return encrypted;
}
