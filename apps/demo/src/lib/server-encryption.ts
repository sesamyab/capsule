/**
 * Server-side encryption utilities.
 * 
 * Pre-encrypts article content using subscription-tier DEKs and article-specific DEKs.
 * 
 * TIER KEYS: Time-bucket based. Content is encrypted with both current and next
 * bucket keys to handle clock drift between CMS and client. When the bucket
 * rotates, old keys become invalid - providing forward secrecy.
 * 
 * ARTICLE KEYS: Static. Once a user has an article key, they can always decrypt.
 */

import { createCipheriv, randomBytes } from "crypto";
import { getSubscriptionKeysForEncryption, getArticleKey, hasArticleKey } from "./encryption-keys";

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
  /** Bucket ID for time-based keys (undefined for static article keys) */
  bucketId?: string;
}

export interface MultiEncryptedArticle {
  /** Tier-based encryption for current bucket (unlocks all articles in tier) */
  tier: EncryptedArticleData;
  /** Tier-based encryption for next bucket (handles clock drift) */
  tierNext: EncryptedArticleData;
  /** Article-specific encryption (unlocks only this article, static key) */
  article: EncryptedArticleData | null;
}

/**
 * Encrypt content with a specific key.
 */
function encryptWithKey(
  content: string,
  dek: Buffer,
  keyType: "tier" | "article",
  keyId: string,
  bucketId?: string
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
    bucketId,
  };
}

/**
 * Encrypt article content using both tier and article-specific keys.
 * 
 * For tier keys: encrypts with both current and next bucket keys.
 * For article keys: encrypts with static key (if available).
 * 
 * Returns all encrypted versions so the client can try them.
 */
export function encryptArticleContent(
  articleId: string,
  content: string,
  tier: string
): MultiEncryptedArticle {
  // Get time-bucket based tier keys
  const tierKeys = getSubscriptionKeysForEncryption(tier);
  
  // Encrypt with current bucket key
  const tierEncrypted = encryptWithKey(
    content, 
    tierKeys.current.dek, 
    "tier", 
    tier, 
    tierKeys.current.bucketId
  );
  
  // Encrypt with next bucket key (for clock drift handling)
  const tierNextEncrypted = encryptWithKey(
    content, 
    tierKeys.next.dek, 
    "tier", 
    tier, 
    tierKeys.next.bucketId
  );
  
  // Article-specific encryption (static key)
  let articleEncrypted: EncryptedArticleData | null = null;
  if (hasArticleKey(articleId)) {
    const articleDek = getArticleKey(articleId);
    articleEncrypted = encryptWithKey(content, articleDek, "article", articleId);
  }
  
  return {
    tier: tierEncrypted,
    tierNext: tierNextEncrypted,
    article: articleEncrypted,
  };
}

/**
 * Get encrypted article content for a specific article.
 * 
 * NOTE: This re-encrypts on every request since bucket keys rotate.
 * In production with longer bucket periods, you'd cache within the bucket window.
 */
export function getEncryptedArticle(articleId: string): MultiEncryptedArticle | null {
  // Import articles here to avoid circular dependency
  const { articles } = require("./articles");
  
  const article = articles[articleId];
  if (!article) {
    return null;
  }
  
  // Re-encrypt with current bucket keys (they rotate)
  return encryptArticleContent(
    articleId,
    article.premiumContent,
    "premium" // All demo articles use premium tier
  );
}
