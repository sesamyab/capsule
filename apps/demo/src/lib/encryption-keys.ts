/**
 * Server-side encryption keys for different subscription tiers and articles.
 * 
 * In production, these would be stored securely (e.g., in a KMS).
 * Each subscription tier has its own DEK that's used to encrypt all articles in that tier.
 * Articles can also have their own unique DEKs for per-article access.
 */

// Pre-generated DEKs for each subscription tier (Base64 encoded)
// In production, use a proper key management system
export const SUBSCRIPTION_KEYS: Record<string, { dek: string }> = {
  premium: {
    // 256-bit AES key (32 bytes) - in production, generate securely and store in KMS
    dek: "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
  },
};

// Per-article DEKs (for article-specific access control)
// In production, these would be generated and stored securely
export const ARTICLE_KEYS: Record<string, { dek: string }> = {
  "premium-guide": {
    dek: "xQGvT8HnJkLmPq2Rs3TuVw4XyZ0A1B2C3D4E5F6G7H8=",
  },
  "crypto-basics": {
    dek: "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V=",
  },
};

/**
 * Get the DEK for a subscription tier.
 */
export function getSubscriptionKey(tier: string): Buffer {
  const keyData = SUBSCRIPTION_KEYS[tier];
  if (!keyData) {
    throw new Error(`Unknown subscription tier: ${tier}`);
  }
  return Buffer.from(keyData.dek, "base64");
}

/**
 * Get the DEK for a specific article.
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
