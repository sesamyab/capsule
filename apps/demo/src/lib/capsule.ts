/**
 * Shared CMS server instance for content encryption.
 * Uses the high-level @sesamy/capsule-server API.
 */

import { createCmsServer, createPeriodKeyProvider } from "@sesamy/capsule-server";

/** Period duration in seconds (30s for demo, longer for production) */
const PERIOD_DURATION_SECONDS = 30;

/**
 * Period secret for key derivation.
 * In production, use KMS (AWS Secrets Manager, etc.)
 */
const PERIOD_SECRET =
  process.env.PERIOD_SECRET ||
  Buffer.from("demo-secret-do-not-use-in-production!!", "utf-8").toString(
    "base64",
  );

/**
 * Secret for signing share tokens.
 * In production, use a separate secret from the period secret.
 */
const TOKEN_SECRET =
  process.env.CAPSULE_TOKEN_SECRET ||
  "demo-token-secret-do-not-use-in-production!!";

/**
 * Period key provider for deriving time-period keys.
 */
const keyProvider = createPeriodKeyProvider({
  periodSecret: PERIOD_SECRET,
  periodDurationSeconds: PERIOD_DURATION_SECONDS,
});

/**
 * Shared CMS server instance.
 *
 * Use this to encrypt article content:
 * ```typescript
 * const encrypted = await cms.encrypt(resourceId, content, {
 *   keyIds: ['premium'],
 *   contentId: 'premium',
 * });
 * ```
 */
export const cms = createCmsServer({
  getKeys: async (keyIds) => {
    const keys = await keyProvider.getKeys(
      keyIds.filter((id) => !id.startsWith("article:")),
    );

    // Handle article keys
    for (const id of keyIds.filter((id) => id.startsWith("article:"))) {
      const resourceId = id.slice(8);
      keys.push(await keyProvider.getArticleKey(resourceId));
    }

    return keys;
  },
});

// Re-export for convenience
export { PERIOD_DURATION_SECONDS, PERIOD_SECRET, TOKEN_SECRET, keyProvider };
