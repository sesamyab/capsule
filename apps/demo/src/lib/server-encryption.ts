/**
 * Server-side DCA content encryption for the demo.
 *
 * Uses createDcaPublisher to encrypt articles with:
 * - Local wrapKey derivation (HKDF from rotationSecret, zero network calls)
 * - ECDH P-256 key wrapping for the issuer
 * - ES256 JWT signing
 * - AAD (Additional Authenticated Data) binding
 */

import {
  getPublisher,
  getIssuerPublicKeyPem,
  DEMO_ISSUER_NAME,
  DEMO_KEY_ID,
} from "./capsule";
import type { DcaRenderResult } from "@sesamy/capsule-server";

// Re-export for consumers
export type { DcaRenderResult };

/**
 * Cache for rendered DCA articles, keyed by resourceId.
 * Each entry includes the hour it was rendered for.
 */
interface CachedRender {
  data: DcaRenderResult;
  tier: string;
  hourBucket: string;
}
const renderCache = new Map<string, CachedRender>();

/**
 * Get the current hour bucket for cache invalidation.
 */
function getCurrentHourBucket(): string {
  const now = new Date();
  return `${now.getUTCFullYear()}-${now.getUTCMonth()}-${now.getUTCDate()}-${now.getUTCHours()}`;
}

/**
 * Render a DCA-encrypted article for display.
 *
 * Uses the DCA publisher to:
 * 1. Generate a random contentKey for this render
 * 2. Encrypt content with AES-256-GCM + AAD
 * 3. Derive wrapKeys and wrap contentKey with them
 * 4. Wrap contentKey and wrapKeys for the demo issuer
 * 5. Sign resourceJWT (ES256)
 *
 * Returns the full DcaRenderResult with HTML strings ready to embed.
 */
export async function renderDcaArticle(
  resourceId: string,
): Promise<{ result: DcaRenderResult; tier: string } | null> {
  const hourBucket = getCurrentHourBucket();

  const cached = renderCache.get(resourceId);
  if (cached && cached.hourBucket === hourBucket) {
    return { result: cached.data, tier: cached.tier };
  }

  const { articles } = await import("./articles");

  const article = articles[resourceId];
  if (!article) {
    return null;
  }

  const publisher = await getPublisher();
  const issuerPublicKeyPem = await getIssuerPublicKeyPem();

  const unlockUrl = "/api/unlock";

  const result = await publisher.render({
    resourceId,
    contentItems: [
      {
        contentName: "bodytext",
        scope: article.tier,
        content: article.premiumContent,
        contentType: "text/html",
      },
    ],
    issuers: [
      {
        issuerName: DEMO_ISSUER_NAME,
        publicKeyPem: issuerPublicKeyPem,
        keyId: DEMO_KEY_ID,
        unlockUrl,
        scopes: [article.tier],
      },
    ],
    resourceData: {
      title: article.title,
      author: article.author,
    },
  });

  renderCache.set(resourceId, {
    data: result,
    tier: article.tier,
    hourBucket,
  });

  return { result, tier: article.tier };
}
