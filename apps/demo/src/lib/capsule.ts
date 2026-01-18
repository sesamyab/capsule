/**
 * Shared CMS server instance for content encryption.
 * Uses the high-level @sesamy/capsule-server API.
 */

import { createCmsServer, createTotpKeyProvider } from "@sesamy/capsule-server";

/** Bucket period in seconds (30s for demo, longer for production) */
const BUCKET_PERIOD_SECONDS = 30;

/**
 * Master secret for key derivation.
 * In production, use KMS (AWS Secrets Manager, etc.)
 */
const MASTER_SECRET = process.env.CAPSULE_MASTER_SECRET || 
  Buffer.from("demo-secret-do-not-use-in-production!!", "utf-8").toString("base64");

/**
 * TOTP key provider for deriving time-bucket keys.
 */
const totp = createTotpKeyProvider({
  masterSecret: MASTER_SECRET,
  bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
});

/**
 * Shared CMS server instance.
 * 
 * Use this to encrypt article content:
 * ```typescript
 * const encrypted = await cms.encrypt(articleId, content, {
 *   keyIds: ['premium'],
 * });
 * ```
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

// Re-export for convenience
export { BUCKET_PERIOD_SECONDS, MASTER_SECRET, totp };
