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
    getRandomBytes,
    toBase64Url,
    toHex,
    fromBase64,
    encodeUtf8,
    importEcdsaP256PrivateKey,
    type WebCryptoKey,
} from "./web-crypto";

import { encryptContent } from "./encryption";

import { aesGcmEncrypt } from "./web-crypto";

import { generateRenderId, getCurrentTimeBuckets, deriveDcaPeriodKey } from "./dca-time-buckets";

import { seal, importIssuerPublicKey } from "./dca-seal";

import { createResourceJwt, createIssuerJwt, createJwt } from "./dca-jwt";

import type {
    DcaData,
    DcaResource,
    DcaContentSealData,
    DcaSealedContentKey,
    DcaIssuerEntry,
    DcaContentKeys,
    DcaPublisherConfig,
    DcaRenderOptions,
    DcaRenderResult,
    DcaJsonApiResponse,
    DcaShareLinkTokenPayload,
    DcaShareLinkOptions,
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

        /**
         * Create a share link token — a publisher-signed JWT that grants
         * pre-authenticated access to specific content via a URL.
         *
         * DCA-compatible: the periodSecret never leaves the publisher.
         * The token is purely an authorization grant. Key material flows
         * through the normal DCA seal/unseal channel — the issuer receives
         * sealed keys from the client and unseals them as usual.
         *
         * @example
         * ```typescript
         * const token = await publisher.createShareLinkToken({
         *   resourceId: "article-123",
         *   contentNames: ["bodytext"],
         *   expiresIn: 7 * 24 * 3600, // 7 days
         * });
         *
         * const shareUrl = `https://example.com/article/123?share=${token}`;
         * ```
         */
        createShareLinkToken: async (options: DcaShareLinkOptions): Promise<string> => {
            const now = Math.floor(Date.now() / 1000);

            // Require at least one of contentNames or keyNames
            const contentNames = options.contentNames ?? options.keyNames ?? [];
            if (contentNames.length === 0 && !options.keyNames?.length) {
                throw new Error("createShareLinkToken requires contentNames or keyNames");
            }

            const payload: DcaShareLinkTokenPayload = {
                type: "dca-share",
                domain: config.domain,
                resourceId: options.resourceId,
                contentNames,
                iat: now,
                exp: now + (options.expiresIn ?? 7 * 24 * 3600), // default: 7 days
                ...(options.maxUses !== undefined ? { maxUses: options.maxUses } : {}),
                jti: options.jti ?? toHex(getRandomBytes(16)),
                ...(options.data !== undefined ? { data: options.data } : {}),
                ...(options.keyNames !== undefined ? { keyNames: options.keyNames } : {}),
            };

            const signingKey = await getSigningKey();
            return createJwt(payload, signingKey);
        },
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

    // 2b. Resolve keyName for each content item (defaults to contentName)
    const resolvedKeyNames: Record<string, string> = {};
    let hasExplicitKeyNames = false;
    for (const item of contentItems) {
        const keyName = item.keyName ?? item.contentName;
        resolvedKeyNames[item.contentName] = keyName;
        if (item.keyName !== undefined && item.keyName !== item.contentName) {
            hasExplicitKeyNames = true;
        }
    }

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
        // v2: when keyName differs from contentName, include it for cryptographic binding
        const keyName = resolvedKeyNames[contentName];
        const aadString = keyName !== contentName
            ? `${domain}|${resourceId}|${contentName}|${keyName}|2`
            : `${domain}|${resourceId}|${contentName}|1`;
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
    //    periodKey derivation uses keyName (not contentName) as HKDF salt.
    //    Content items sharing a keyName get the same periodKey.
    const sealedContentKeys: Record<string, DcaSealedContentKey[]> = {};

    for (const item of contentItems) {
        const contentName = item.contentName;
        const keyName = resolvedKeyNames[contentName];
        const entries: DcaSealedContentKey[] = [];

        for (const bucket of [buckets.current, buckets.next]) {
            const periodKey = await deriveDcaPeriodKey(periodSecret, keyName, bucket.t);

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

        const issuerContentKeys: Record<string, DcaContentKeys> = {};

        // Resolve which content items to seal for this issuer.
        // keyNames takes precedence: seal all items whose keyName is in the list.
        // contentNames: seal those specific items by name.
        let contentNamesToSeal: string[];
        if (issuerConfig.keyNames && issuerConfig.keyNames.length > 0) {
            const keyNameSet = new Set(issuerConfig.keyNames);
            contentNamesToSeal = contentItems
                .filter(item => keyNameSet.has(resolvedKeyNames[item.contentName]))
                .map(item => item.contentName);
        } else if (issuerConfig.contentNames && issuerConfig.contentNames.length > 0) {
            contentNamesToSeal = issuerConfig.contentNames;
        } else {
            throw new Error(`Issuer "${issuerConfig.issuerName}" must specify contentNames or keyNames`);
        }

        for (const contentName of contentNamesToSeal) {
            const contentKey = contentKeys[contentName];
            if (!contentKey) {
                throw new Error(`Content item "${contentName}" not found for issuer "${issuerConfig.issuerName}"`);
            }

            const keyName = resolvedKeyNames[contentName];

            // Seal contentKey
            const sealedContentKey = await seal(contentKey, issuerPubKey, algorithm);

            // Seal periodKeys (using keyName, not contentName, for derivation)
            const sealedPeriodKeys: Record<string, string> = {};
            for (const bucket of [buckets.current, buckets.next]) {
                const periodKey = await deriveDcaPeriodKey(periodSecret, keyName, bucket.t);
                sealedPeriodKeys[bucket.t] = await seal(periodKey, issuerPubKey, algorithm);
            }

            issuerContentKeys[contentName] = {
                contentKey: sealedContentKey,
                periodKeys: sealedPeriodKeys,
            };
        }

        issuerData[issuerConfig.issuerName] = {
            contentKeys: issuerContentKeys,
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

    // 8. Sign issuerJWTs (include keyId for v2 unlock format)
    const issuerJWT: Record<string, string> = {};
    for (const issuerConfig of issuers) {
        issuerJWT[issuerConfig.issuerName] = await createIssuerJwt(
            renderId,
            issuerConfig.issuerName,
            issuerData[issuerConfig.issuerName].contentKeys,
            signingKey,
            issuerConfig.keyId,
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
        // Include contentKeyMap only when keyNames differ from contentNames
        ...(hasExplicitKeyNames ? { contentKeyMap: resolvedKeyNames } : {}),
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
