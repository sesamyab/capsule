/**
 * Server-side encryption using @sesamy/capsule-server.
 * Simplified wrapper for the Astro demo.
 */

import { CapsuleServer } from "@sesamy/capsule-server";
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
 * Shared CapsuleServer instance for the Astro demo.
 */
export const capsule = new CapsuleServer({
  masterSecret: MASTER_SECRET,
  bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
});

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
  return capsule.encrypt(articleId, content, {
    tiers: [tier],
    includeArticleKey: true,
  });
}

/**
 * Re-export BUCKET_PERIOD_SECONDS for the unlock endpoint.
 */
export { BUCKET_PERIOD_SECONDS };
