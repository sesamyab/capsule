/**
 * Server-side encryption using @sesamy/capsule-server.
 * Simplified wrapper for the Astro demo.
 */

import { createCmsServer, createTotpKeyProvider } from "@sesamy/capsule-server";
import type { EncryptedArticle } from "@sesamy/capsule-server";

// Re-export the type for use in pages
export type { EncryptedArticle };

/** Bucket duration in seconds (30s for demo, longer for production) */
const BUCKET_PERIOD_SECONDS = 30;

/**
 * Master secret for key derivation.
 * In production, use KMS (AWS Secrets Manager, etc.)
 */
const MASTER_SECRET = import.meta.env.CAPSULE_MASTER_SECRET || 
  Buffer.from("demo-secret-do-not-use-in-production!!", "utf-8").toString("base64");

/**
 * TOTP key provider for deriving time-bucket keys.
 */
const totp = createTotpKeyProvider({
  masterSecret: MASTER_SECRET,
  bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
});

/**
 * Shared CMS server instance for the Astro demo.
 */
export const cms = createCmsServer({
  getKeys: async (keyIds) => {
    const keys = await totp.getKeys(keyIds.filter(id => !id.startsWith('article:')));
    
    // Handle article keys
    for (const id of keyIds.filter(id => id.startsWith('article:'))) {
      const articleId = id.slice(8);
      keys.push(await totp.getArticleKey(articleId));
    }
    
    return keys;
  },
});

// Legacy alias
export const capsule = cms;

/**
 * Encrypt article content for the Capsule client.
 * 
 * Returns an EncryptedArticle with multiple wrapped keys:
 * - Current tier bucket key
 * - Next tier bucket key (handles clock drift)
 * - Article-specific key (permanent access)
 */
export async function encryptArticleContent(
  articleId: string,
  content: string,
  tier: string = "premium"
): Promise<EncryptedArticle> {
  return cms.encrypt(articleId, content, {
    keyIds: [tier, `article:${articleId}`],
  });
}

/**
 * Re-export BUCKET_PERIOD_SECONDS for the unlock endpoint.
 */
export { BUCKET_PERIOD_SECONDS };
