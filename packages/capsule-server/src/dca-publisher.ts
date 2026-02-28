/**
 * DCA Publisher — encrypts content items and produces DCA-compliant output.
 *
 * The publisher:
 *   1. Generates per-content-item contentKeys and IVs
 *   2. Encrypts content with AES-256-GCM + AAD
 *   3. Derives periodKeys and wraps contentKeys with them
 *   4. Seals contentKeys and periodKeys for each issuer
 *   5. Signs resourceJWT and issuerJWTs (ES256)
 *   6. Assembles the DCA data JSON and sealed HTML template
 */

import {
  generateAesKeyBytes,
  generateIv,
  toBase64Url,
  fromBase64,
  encodeUtf8,
  importEcdsaP256PrivateKey,
  type WebCryptoKey,
} from "./web-crypto";

import { encryptContent } from "./encryption";

import { aesGcmEncrypt } from "./web-crypto";

import { generateRenderId, getCurrentTimeBuckets, deriveDcaPeriodKey } from "./dca-time-buckets";

import { seal, importIssuerPublicKey } from "./dca-seal";

import { createResourceJwt, createIssuerJwt } from "./dca-jwt";

import type {
  DcaData,
  DcaResource,
  DcaContentSealData,
  DcaSealedContentKey,
  DcaIssuerEntry,
  DcaIssuerSealed,
  DcaPublisherConfig,
  DcaRenderOptions,
  DcaRenderResult,
  DcaJsonApiResponse,
} from "./dca-types";

// ============================================================================
// Publisher factory
// ============================================================================

/**
 * Create a DCA publisher instance.
 *
 * @example
 * ```typescript
 * const publisher = createDcaPublisher({
 *   domain: "www.news-site.com",
 *   signingKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY!,
 *   periodSecret: process.env.PERIOD_SECRET!,
 * });
 *
 * const result = await publisher.render({
 *   resourceId: "article-123",
 *   contentItems: [
 *     { contentName: "bodytext", content: "<p>Premium article body...</p>" },
 *   ],
 *   issuers: [
 *     {
 *       issuerName: "sesamy",
 *       publicKeyPem: process.env.SESAMY_ECDH_PUBLIC_KEY!,
 *       keyId: "2025-10",
 *       unlockUrl: "https://api.sesamy.com/unlock",
 *       contentNames: ["bodytext"],
 *     },
 *   ],
 * });
 * ```
 */
export function createDcaPublisher(config: DcaPublisherConfig) {
  const periodSecret = typeof config.periodSecret === "string"
    ? fromBase64(config.periodSecret)
    : config.periodSecret;

  const periodDurationHours = config.periodDurationHours ?? 1;

  let signingKeyPromise: Promise<WebCryptoKey> | null = null;

  function getSigningKey(): Promise<WebCryptoKey> {
    if (!signingKeyPromise) {
      signingKeyPromise = importEcdsaP256PrivateKey(config.signingKeyPem);
    }
    return signingKeyPromise;
  }

  return {
    render: (options: DcaRenderOptions) => render(config.domain, periodSecret, periodDurationHours, getSigningKey, options),
  };
}

// ============================================================================
// Core render logic
// ============================================================================

async function render(
  domain: string,
  periodSecret: Uint8Array,
  periodDurationHours: number,
  getSigningKey: () => Promise<WebCryptoKey>,
  options: DcaRenderOptions,
): Promise<DcaRenderResult> {
  const { resourceId, contentItems, issuers, resourceData } = options;

  // 1. Generate renderId
  const renderId = generateRenderId();

  // 2. Get time buckets (current + next)
  const buckets = getCurrentTimeBuckets(periodDurationHours);

  // 3. Per content item: generate contentKey, IV, encrypt
  const contentKeys: Record<string, Uint8Array> = {};
  const contentSealData: Record<string, DcaContentSealData> = {};
  const sealedContent: Record<string, string> = {};

  for (const item of contentItems) {
    const contentName = item.contentName;
    const contentType = item.contentType ?? "text/html";

    // Generate content key and IV
    const contentKey = generateAesKeyBytes();
    const iv = generateIv();

    // Build AAD string: domain|resourceId|contentName|version
    const aadString = `${domain}|${resourceId}|${contentName}|1`;
    const aadBytes = encodeUtf8(aadString);

    // Encrypt content with AAD
    const { encryptedContent } = await encryptContent(item.content, contentKey, iv, aadBytes);

    contentKeys[contentName] = contentKey;
    contentSealData[contentName] = {
      contentType,
      nonce: toBase64Url(iv),
      aad: aadString,
    };
    sealedContent[contentName] = toBase64Url(encryptedContent);
  }

  // 4. Derive periodKeys and wrap contentKeys
  const sealedContentKeys: Record<string, DcaSealedContentKey[]> = {};

  for (const item of contentItems) {
    const contentName = item.contentName;
    const entries: DcaSealedContentKey[] = [];

    for (const bucket of [buckets.current, buckets.next]) {
      const periodKey = await deriveDcaPeriodKey(periodSecret, contentName, bucket.t);

      // Wrap contentKey with periodKey using AES-256-GCM (no AAD for key wrapping)
      const wrapIv = generateIv();
      const { encryptedContent: wrappedKey } = await aesGcmEncrypt(
        contentKeys[contentName],
        periodKey,
        wrapIv,
      );

      entries.push({
        t: bucket.t,
        nonce: toBase64Url(wrapIv),
        key: toBase64Url(wrappedKey),
      });
    }

    sealedContentKeys[contentName] = entries;
  }

  // 5. Import issuer public keys and seal contentKeys + periodKeys for each issuer
  const issuerData: Record<string, DcaIssuerEntry> = {};

  for (const issuerConfig of issuers) {
    const { key: issuerPubKey, algorithm } = await importIssuerPublicKey(
      issuerConfig.publicKeyPem,
      issuerConfig.algorithm,
    );

    const sealed: Record<string, DcaIssuerSealed> = {};

    for (const contentName of issuerConfig.contentNames) {
      const contentKey = contentKeys[contentName];
      if (!contentKey) {
        throw new Error(`Content item "${contentName}" not found for issuer "${issuerConfig.issuerName}"`);
      }

      // Seal contentKey
      const sealedContentKey = await seal(contentKey, issuerPubKey, algorithm);

      // Seal periodKeys
      const sealedPeriodKeys: Record<string, string> = {};
      for (const bucket of [buckets.current, buckets.next]) {
        const periodKey = await deriveDcaPeriodKey(periodSecret, contentName, bucket.t);
        sealedPeriodKeys[bucket.t] = await seal(periodKey, issuerPubKey, algorithm);
      }

      sealed[contentName] = {
        contentKey: sealedContentKey,
        periodKeys: sealedPeriodKeys,
      };
    }

    issuerData[issuerConfig.issuerName] = {
      sealed,
      unlockUrl: issuerConfig.unlockUrl,
      keyId: issuerConfig.keyId,
    };
  }

  // 6. Build resource object
  const resource: DcaResource = {
    renderId,
    domain,
    issuedAt: new Date().toISOString(),
    resourceId,
    data: resourceData ?? {},
  };

  // 7. Sign resourceJWT
  const signingKey = await getSigningKey();
  const resourceJWT = await createResourceJwt(resource, signingKey);

  // 8. Sign issuerJWTs
  const issuerJWT: Record<string, string> = {};
  for (const issuerConfig of issuers) {
    issuerJWT[issuerConfig.issuerName] = await createIssuerJwt(
      renderId,
      issuerConfig.issuerName,
      issuerData[issuerConfig.issuerName].sealed,
      signingKey,
    );
  }

  // 9. Assemble DCA data
  const dcaData: DcaData = {
    version: "1",
    resource,
    resourceJWT,
    issuerJWT,
    contentSealData,
    sealedContentKeys,
    issuerData,
  };

  // 10. Build HTML strings
  // Escape closing script tags to prevent script-breakout XSS when embedding JSON in HTML
  const dcaDataScript = `<script type="application/json" class="dca-data">${JSON.stringify(dcaData).replace(/<\//g, "\\u003c/")}</script>`;

  const sealedContentDivs = Object.entries(sealedContent)
    .map(([name, ct]) => `  <div data-dca-content-name="${escapeHtmlAttr(name)}">${ct}</div>`)
    .join("\n");
  const sealedContentTemplate = `<template class="dca-sealed-content">\n${sealedContentDivs}\n</template>`;

  // 11. Build JSON API response
  const json: DcaJsonApiResponse = {
    ...dcaData,
    sealedContent,
  };

  return {
    dcaData,
    sealedContent,
    html: {
      dcaDataScript,
      sealedContentTemplate,
    },
    json,
  };
}

// ============================================================================
// Helpers
// ============================================================================

function escapeHtmlAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
