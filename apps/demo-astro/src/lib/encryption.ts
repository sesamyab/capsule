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
const PERIOD_SECRET =
  import.meta.env.CAPSULE_PERIOD_SECRET ||
  Buffer.from("demo-secret-do-not-use-in-production!!", "utf-8").toString(
    "base64"
  );

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
  tier: string = "premium"
): Promise<EncryptedArticle> {
  return cms.encrypt(resourceId, content, {
    keyIds: [tier, `article:${resourceId}`],
    contentId: tier,
  });
}

/**
 * Re-export PERIOD_DURATION_SECONDS and keyProvider for the unlock endpoint.
 */
export { PERIOD_DURATION_SECONDS, keyProvider };
