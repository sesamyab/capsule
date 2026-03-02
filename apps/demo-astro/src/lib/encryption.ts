/**
 * Server-side encryption using @sesamy/capsule-server.
 * Simplified wrapper for the Astro demo.
 */

import { createCmsServer, createPeriodKeyProvider } from "@sesamy/capsule-server";
import type { EncryptedArticle } from "@sesamy/capsule-server";

// Re-export the type for use in pages
export type { EncryptedArticle };

/** Period duration in seconds (30s for demo, longer for production) */
const PERIOD_DURATION_SECONDS = 30;

/**
 * Period secret for key derivation.
 * In production, use KMS (AWS Secrets Manager, etc.)
 */
function getPeriodSecret(): string {
  const secret = import.meta.env.CAPSULE_PERIOD_SECRET;
  if (secret) return secret;
  if (import.meta.env.DEV) {
    console.warn("[capsule] CAPSULE_PERIOD_SECRET not set — using insecure demo fallback (dev only)");
    return Buffer.from("demo-secret-do-not-use-in-production!!", "utf-8").toString("base64");
  }
  throw new Error("CAPSULE_PERIOD_SECRET environment variable is required in production");
}
const PERIOD_SECRET = getPeriodSecret();

/**
 * Period key provider for deriving time-period keys.
 */
const keyProvider = createPeriodKeyProvider({
  periodSecret: PERIOD_SECRET,
  periodDurationSeconds: PERIOD_DURATION_SECONDS,
});

/**
 * Shared CMS server instance for the Astro demo.
 */
export const cms = createCmsServer({
  getKeys: async (keyIds) => {
    const keys = await keyProvider.getKeys(
      keyIds.filter((id) => !id.startsWith("article:"))
    );

    // Handle article keys
    for (const id of keyIds.filter((id) => id.startsWith("article:"))) {
      const resourceId = id.slice(8);
      keys.push(await keyProvider.getArticleKey(resourceId));
    }

    return keys;
  },
});

/**
 * Encrypt article content for the Capsule client.
 *
 * Returns an EncryptedArticle with multiple wrapped keys:
 * - Current shared period key
 * - Next shared period key (handles clock drift)
 * - Article-specific key (permanent access)
 */
export async function encryptArticleContent(
  resourceId: string,
  content: string,
  contentName: string = "premium"
): Promise<EncryptedArticle> {
  return cms.encrypt(resourceId, content, {
    keyIds: [contentName, `article:${resourceId}`],
    contentId: contentName,
  });
}

/**
 * Re-export PERIOD_DURATION_SECONDS and keyProvider for the unlock endpoint.
 */
export { PERIOD_DURATION_SECONDS, keyProvider };
