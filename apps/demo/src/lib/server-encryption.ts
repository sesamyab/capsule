/**
 * Server-side encryption utilities.
 * 
 * Pre-encrypts article content using subscription-tier DEKs and article-specific DEKs.
 * The encrypted content is embedded in the SSR page.
 */

import { createCipheriv, randomBytes } from "crypto";
import { getSubscriptionKey, getArticleKey, hasArticleKey } from "./encryption-keys";

/** GCM IV size in bytes (96 bits as recommended by NIST) */
const GCM_IV_SIZE = 12;

/** GCM authentication tag length in bytes */
const GCM_TAG_LENGTH = 16;

export interface EncryptedArticleData {
  /** Base64-encoded encrypted content (ciphertext + auth tag) */
  encryptedContent: string;
  /** Base64-encoded IV used for this specific article */
  iv: string;
  /** Key type: "tier" for subscription-based, "article" for per-article */
  keyType: "tier" | "article";
  /** Subscription tier (for tier keys) or article ID (for article keys) */
  keyId: string;
}

export interface MultiEncryptedArticle {
  /** Tier-based encryption (unlocks all articles in tier) */
  tier: EncryptedArticleData;
  /** Article-specific encryption (unlocks only this article) */
  article: EncryptedArticleData | null;
}

/**
 * Encrypt content with a specific key.
 */
function encryptWithKey(
  content: string,
  dek: Buffer,
  keyType: "tier" | "article",
  keyId: string
): EncryptedArticleData {
  const iv = randomBytes(GCM_IV_SIZE);
  
  const cipher = createCipheriv("aes-256-gcm", dek, iv, {
    authTagLength: GCM_TAG_LENGTH,
  });
  
  const plaintext = Buffer.from(content, "utf-8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  // Combine ciphertext and auth tag (same format as Web Crypto API)
  const combined = Buffer.concat([encrypted, authTag]);
  
  return {
    encryptedContent: combined.toString("base64"),
    iv: iv.toString("base64"),
    keyType,
    keyId,
  };
}

/**
 * Encrypt article content using both tier and article-specific keys.
 * Returns both encrypted versions so the client can choose.
 */
export function encryptArticleContent(
  articleId: string,
  content: string,
  tier: string
): MultiEncryptedArticle {
  const tierDek = getSubscriptionKey(tier);
  const tierEncrypted = encryptWithKey(content, tierDek, "tier", tier);
  
  let articleEncrypted: EncryptedArticleData | null = null;
  if (hasArticleKey(articleId)) {
    const articleDek = getArticleKey(articleId);
    articleEncrypted = encryptWithKey(content, articleDek, "article", articleId);
  }
  
  return {
    tier: tierEncrypted,
    article: articleEncrypted,
  };
}

/**
 * Pre-encrypt all articles for SSR embedding.
 * In production, this would be done at build time or cached.
 */
export function getPreEncryptedArticles(): Record<string, MultiEncryptedArticle> {
  // Import articles here to avoid circular dependency
  const { articles } = require("./articles");
  
  const encrypted: Record<string, MultiEncryptedArticle> = {};
  
  for (const [id, article] of Object.entries(articles)) {
    encrypted[id] = encryptArticleContent(
      id,
      (article as { premiumContent: string }).premiumContent,
      "premium" // All demo articles use premium tier
    );
  }
  
  return encrypted;
}

// Cache the pre-encrypted articles (would be done at build time in production)
let cachedEncryptedArticles: Record<string, MultiEncryptedArticle> | null = null;

export function getEncryptedArticle(articleId: string): MultiEncryptedArticle | null {
  if (!cachedEncryptedArticles) {
    cachedEncryptedArticles = getPreEncryptedArticles();
  }
  return cachedEncryptedArticles[articleId] || null;
}
