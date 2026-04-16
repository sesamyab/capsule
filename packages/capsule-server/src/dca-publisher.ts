/**
 * DCA Publisher — encrypts content items and produces DCA-compliant output.
 *
 * The publisher:
 *   1. Generates per-content-item contentKeys and IVs
 *   2. Encrypts content with AES-256-GCM + AAD
 *   3. Derives wrapKeys and wraps contentKeys with them (per rotation version)
 *   4. Wraps contentKeys and wrapKeys for each issuer's public key
 *   5. Signs resourceJWT (ES256)
 *   6. Assembles the manifest JSON and HTML script tag
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

import { generateRenderId, getCurrentRotationVersions, deriveWrapKey } from "./dca-rotation";

import { wrap, importIssuerPublicKey } from "./dca-wrap";

import { createResourceJwt, createJwt } from "./dca-jwt";

import type {
    DcaManifest,
    DcaResource,
    DcaContentEntry,
    DcaWrappedContentKeyEntry,
    DcaIssuerEntry,
    DcaIssuerKey,
    DcaWrappedIssuerWrapKey,
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
 *   rotationSecret: process.env.ROTATION_SECRET!,
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
    const rotationSecret = typeof config.rotationSecret === "string"
        ? fromBase64(config.rotationSecret)
        : config.rotationSecret;

    const rotationIntervalHours = config.rotationIntervalHours ?? 1;

    let signingKeyPromise: Promise<WebCryptoKey> | null = null;

    function getSigningKey(): Promise<WebCryptoKey> {
        if (!signingKeyPromise) {
            signingKeyPromise = importEcdsaP256PrivateKey(config.signingKeyPem);
        }
        return signingKeyPromise;
    }

    return {
        render: (options: DcaRenderOptions) => render(config.domain, rotationSecret, rotationIntervalHours, getSigningKey, options),

        /**
         * Create a share link token — a publisher-signed JWT that grants
         * pre-authenticated access to specific content via a URL.
         *
         * DCA-compatible: the rotationSecret never leaves the publisher.
         * The token is purely an authorization grant. Key material flows
         * through the normal DCA wrap/unwrap channel — the issuer receives
         * wrapped keys from the client and unwraps them as usual.
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

            if (!options.contentNames?.length && !options.scopes?.length) {
                throw new Error("createShareLinkToken requires contentNames or scopes");
            }
            if (options.contentNames?.length && options.scopes?.length) {
                throw new Error("createShareLinkToken: contentNames and scopes are mutually exclusive");
            }

            const payload: DcaShareLinkTokenPayload = {
                type: "dca-share",
                domain: config.domain,
                resourceId: options.resourceId,
                contentNames: options.contentNames ?? [],
                iat: now,
                exp: now + (options.expiresIn ?? 7 * 24 * 3600),
                ...(options.maxUses !== undefined ? { maxUses: options.maxUses } : {}),
                jti: options.jti ?? toHex(getRandomBytes(16)),
                ...(options.data !== undefined ? { data: options.data } : {}),
                ...(options.scopes !== undefined ? { scopes: options.scopes } : {}),
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
    rotationSecret: Uint8Array,
    rotationIntervalHours: number,
    getSigningKey: () => Promise<WebCryptoKey>,
    options: DcaRenderOptions,
): Promise<DcaRenderResult> {
    const { resourceId, contentItems, issuers, resourceData } = options;

    // 1. Generate renderId
    const renderId = generateRenderId();

    // 2. Get current + next rotation kids
    const rotation = getCurrentRotationVersions(rotationIntervalHours);

    // 2b. Resolve scope for each content item (defaults to contentName)
    const resolvedScopes: Record<string, string> = {};
    for (const item of contentItems) {
        resolvedScopes[item.contentName] = item.scope ?? item.contentName;
    }

    // 3. Per content item: generate contentKey, IV, encrypt content, build manifest entry
    const contentKeys: Record<string, Uint8Array> = {};
    const content: Record<string, DcaContentEntry> = {};

    for (const item of contentItems) {
        const contentName = item.contentName;
        const contentType = item.contentType ?? "text/html";
        const scope = resolvedScopes[contentName];

        const contentKey = generateAesKeyBytes();
        const iv = generateIv();

        // AAD binds ciphertext to domain|resourceId|contentName|scope
        const aadString = `${domain}|${resourceId}|${contentName}|${scope}`;
        const aadBytes = encodeUtf8(aadString);

        const { encryptedContent } = await encryptContent(item.content, contentKey, iv, aadBytes);

        contentKeys[contentName] = contentKey;

        // 4. Wrap contentKey with each rotation-version wrapKey
        //    scope (not contentName) is the HKDF salt — items sharing a scope share wrapKeys
        const wrappedContentKey: DcaWrappedContentKeyEntry[] = [];
        for (const version of [rotation.current, rotation.next]) {
            const wrapKey = await deriveWrapKey(rotationSecret, scope, version.kid);

            const wrapIv = generateIv();
            const { encryptedContent: wrappedKey } = await aesGcmEncrypt(
                contentKey,
                wrapKey,
                wrapIv,
            );

            wrappedContentKey.push({
                kid: version.kid,
                iv: toBase64Url(wrapIv),
                ciphertext: toBase64Url(wrappedKey),
            });
        }

        content[contentName] = {
            contentType,
            iv: toBase64Url(iv),
            aad: aadString,
            ciphertext: toBase64Url(encryptedContent),
            wrappedContentKey,
        };
    }

    // 5. For each issuer: wrap contentKeys and wrapKeys with the issuer's public key
    const issuerData: Record<string, DcaIssuerEntry> = {};

    for (const issuerConfig of issuers) {
        const { key: issuerPubKey, algorithm } = await importIssuerPublicKey(
            issuerConfig.publicKeyPem,
            issuerConfig.algorithm,
        );

        const issuerKeys: DcaIssuerKey[] = [];

        // Resolve which content items to wrap for this issuer.
        // scopes takes precedence: wrap all items whose scope is in the list.
        // contentNames: wrap those specific items by name.
        let contentNamesToWrap: string[];
        if (issuerConfig.scopes && issuerConfig.scopes.length > 0) {
            const scopeSet = new Set(issuerConfig.scopes);
            contentNamesToWrap = [
                ...new Set(
                    contentItems
                        .filter(item => scopeSet.has(resolvedScopes[item.contentName]))
                        .map(item => item.contentName),
                ),
            ];
        } else if (issuerConfig.contentNames && issuerConfig.contentNames.length > 0) {
            contentNamesToWrap = [...new Set(issuerConfig.contentNames)];
        } else {
            throw new Error(`Issuer "${issuerConfig.issuerName}" must specify contentNames or scopes`);
        }

        if (contentNamesToWrap.length === 0) {
            throw new Error(
                `Issuer "${issuerConfig.issuerName}" resolved to zero content items — check that its scopes match at least one content item`,
            );
        }

        for (const contentName of contentNamesToWrap) {
            const contentKey = contentKeys[contentName];
            if (!contentKey) {
                throw new Error(`Content item "${contentName}" not found for issuer "${issuerConfig.issuerName}"`);
            }

            const scope = resolvedScopes[contentName];

            // AAD binds wrapped blobs to this scope — tampering with scope causes unwrap failure
            const wrapAad = encodeUtf8(scope);

            // Wrap contentKey for issuer
            const wrappedContentKey = await wrap(contentKey, issuerPubKey, algorithm, wrapAad);

            // Wrap each rotation-version wrapKey for issuer
            const wrappedWrapKeys: DcaWrappedIssuerWrapKey[] = [];
            for (const version of [rotation.current, rotation.next]) {
                const wrapKey = await deriveWrapKey(rotationSecret, scope, version.kid);
                wrappedWrapKeys.push({
                    kid: version.kid,
                    key: await wrap(wrapKey, issuerPubKey, algorithm, wrapAad),
                });
            }

            issuerKeys.push({
                contentName,
                scope,
                contentKey: wrappedContentKey,
                wrapKeys: wrappedWrapKeys,
            });
        }

        issuerData[issuerConfig.issuerName] = {
            unlockUrl: issuerConfig.unlockUrl,
            keyId: issuerConfig.keyId,
            keys: issuerKeys,
        };
    }

    // 6. Build resource object
    // Compute unique scopes (deduplicated, in order of first appearance)
    const uniqueScopes = [...new Set(Object.values(resolvedScopes))];

    const resource: DcaResource = {
        renderId,
        domain,
        issuedAt: new Date().toISOString(),
        resourceId,
        scopes: uniqueScopes,
        data: resourceData ?? {},
    };

    // 7. Sign resourceJWT
    const signingKey = await getSigningKey();
    const resourceJWT = await createResourceJwt(resource, signingKey);

    // 8. Assemble manifest
    const manifest: DcaManifest = {
        version: "0.10",
        resourceJWT,
        content,
        issuers: issuerData,
    };

    // 9. Build HTML strings.
    // Escape closing script tags to prevent script-breakout XSS when embedding JSON in HTML.
    const manifestScript = `<script type="application/json" class="dca-manifest">${JSON.stringify(manifest).replace(/<\//g, "\\u003c/")}</script>`;

    // 10. JSON API response is just the manifest (ciphertext is already inline)
    const json: DcaJsonApiResponse = manifest;

    return {
        manifest,
        html: {
            manifestScript,
        },
        json,
    };
}
