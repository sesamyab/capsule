/**
 * Shared CapsuleServer instance for content encryption.
 * Uses the high-level @sesamy/capsule-server API.
 */

import { CapsuleServer } from "@sesamy/capsule-server";

/** Bucket period in seconds (30s for demo, longer for production) */
const BUCKET_PERIOD_SECONDS = 30;

/**
 * Master secret for key derivation.
 * In production, use KMS (AWS Secrets Manager, etc.)
 */
const MASTER_SECRET = process.env.CAPSULE_MASTER_SECRET || 
  Buffer.from("demo-secret-do-not-use-in-production!!", "utf-8").toString("base64");

/**
 * Shared CapsuleServer instance.
 * 
 * Use this to encrypt article content:
 * ```typescript
 * const encrypted = await capsule.encrypt(articleId, content, {
 *   tiers: ['premium'],
 * });
 * ```
 */
export const capsule = new CapsuleServer({
  masterSecret: MASTER_SECRET,
  bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
});

// Re-export for convenience
export { BUCKET_PERIOD_SECONDS, MASTER_SECRET };
