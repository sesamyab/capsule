/**
 * Server-side encryption utilities using @sesamy/capsule-server.
 * 
 * This is a thin wrapper that provides the encrypted article data
 * for the demo pages. The actual encryption is handled by CmsServer.
 */

import { cms, BUCKET_PERIOD_SECONDS } from "./capsule";
import { hasArticleKey } from "./encryption-keys";
import type { EncryptedArticle } from "@sesamy/capsule-server";

// Re-export types for consumers
export type { EncryptedArticle };

/**
 * Cache for encrypted articles, keyed by articleId.
 * Each entry includes the bucket ID it was encrypted for.
 */
interface CachedEncryption {
  data: EncryptedArticle;
  bucketId: string;
}
const encryptionCache = new Map<string, CachedEncryption>();

/**
 * Get the current time bucket ID.
 */
function getCurrentBucketId(): string {
  const now = Math.floor(Date.now() / 1000);
  return String(Math.floor(now / BUCKET_PERIOD_SECONDS));
}

/**
 * Get encrypted article for display.
 * 
 * Uses the high-level CmsServer API to encrypt content with:
 * - Current and next bucket keys for the tier (handles clock drift)
 * - Article-specific key if available (for per-article purchases)
 * 
 * Caches the encrypted content within a bucket period so that:
 * - Page refreshes don't break client-side DEK caching
 * - The same DEK is used consistently within a time window
 */
export async function getEncryptedArticle(articleId: string): Promise<EncryptedArticle | null> {
  const currentBucket = getCurrentBucketId();
  
  // Check cache - reuse if same bucket
  const cached = encryptionCache.get(articleId);
  if (cached && cached.bucketId === currentBucket) {
    return cached.data;
  }
  
  // Import articles here to avoid circular dependency
  const { articles } = await import("./articles");
  
  const article = articles[articleId];
  if (!article) {
    return null;
  }
  
  // Build key IDs list
  const keyIds = ["premium"];
  if (hasArticleKey(articleId)) {
    keyIds.push(`article:${articleId}`);
  }

  // Use CmsServer to encrypt with key IDs
  const encrypted = await cms.encrypt(articleId, article.premiumContent, {
    keyIds,
  });
  
  // Cache for this bucket period
  encryptionCache.set(articleId, {
    data: encrypted,
    bucketId: currentBucket,
  });

  return encrypted;
}
