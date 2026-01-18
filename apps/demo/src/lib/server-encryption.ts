/**
 * Server-side encryption utilities using @sesamy/capsule-server.
 * 
 * This is a thin wrapper that provides the encrypted article data
 * for the demo pages. The actual encryption is handled by CapsuleServer.
 */

import { capsule } from "./capsule";
import { hasArticleKey, getArticleKey } from "./encryption-keys";
import type { EncryptedArticle } from "@sesamy/capsule-server";

// Re-export types for consumers
export type { EncryptedArticle };

/**
 * Get encrypted article for display.
 * 
 * Uses the high-level CapsuleServer API to encrypt content with:
 * - Current and next bucket keys for the tier (handles clock drift)
 * - Article-specific key if available (for per-article purchases)
 * 
 * NOTE: Re-encrypts on every request since bucket keys rotate.
 * In production with longer bucket periods, you'd cache within the bucket window.
 */
export async function getEncryptedArticle(articleId: string): Promise<EncryptedArticle | null> {
  // Import articles here to avoid circular dependency
  const { articles } = await import("./articles");
  
  const article = articles[articleId];
  if (!article) {
    return null;
  }
  
  // Build additional keys (per-article access)
  const additionalKeys = [];
  if (hasArticleKey(articleId)) {
    additionalKeys.push({
      keyId: `article:${articleId}`,
      key: getArticleKey(articleId),
    });
  }

  // Use CapsuleServer to encrypt with tier-based access
  return capsule.encrypt(articleId, article.premiumContent, {
    tiers: ["premium"],
    additionalKeys,
  });
}

/**
 * Synchronous wrapper for getEncryptedArticle.
 * Uses a cached promise to avoid re-encryption on subsequent calls.
 */
const encryptionCache = new Map<string, EncryptedArticle>();

export function getEncryptedArticleSync(articleId: string): EncryptedArticle | null {
  // Check cache first
  if (encryptionCache.has(articleId)) {
    return encryptionCache.get(articleId)!;
  }
  
  // For SSR, we need synchronous access. The CapsuleServer encrypt is async
  // but in TOTP mode it doesn't actually do any async operations.
  // We'll pre-populate the cache in a build step or use the async version.
  return null;
}

// Pre-encrypt all articles at module load time for SSR
(async () => {
  try {
    const { articles } = await import("./articles");
    for (const articleId of Object.keys(articles)) {
      const encrypted = await getEncryptedArticle(articleId);
      if (encrypted) {
        encryptionCache.set(articleId, encrypted);
      }
    }
  } catch (e) {
    // Ignore errors during module initialization
  }
})();

/**
 * Get encrypted article (sync, from cache).
 * Falls back to null if not cached yet.
 */
export function getEncryptedArticleCached(articleId: string): EncryptedArticle | null {
  return encryptionCache.get(articleId) ?? null;
}
