/**
 * DCA Issuer — server-side handler for unlock requests.
 *
 * The issuer:
 *   1. Looks up the publisher's signing key from resource.domain
 *   2. Verifies resourceJWT (ES256) — binds request to the publisher
 *   3. Verifies issuerJWT integrity proofs — confirms sealed blobs weren't tampered with
 *   4. Makes an access decision (application-specific)
 *   5. Unseals and returns contentKeys or periodKeys to the client
 */

import { verifyJwt, verifyIssuerProof } from "./dca-jwt";
import { unseal, importIssuerPrivateKey, type DcaSealAlgorithm } from "./dca-seal";
import {
    toBase64Url,
    fromBase64Url,
    importRsaPublicKey,
    rsaOaepEncrypt,
    type WebCryptoKey,
} from "./web-crypto";

import type {
    DcaResource,
    DcaIssuerJwtPayload,
    DcaIssuerServerConfig,
    DcaUnlockRequest,
    DcaUnlockResponse,
    DcaUnlockedKeys,
} from "./dca-types";

// ============================================================================
// Issuer factory
// ============================================================================

/**
 * Create a DCA issuer instance.
 *
 * @example
 * ```typescript
 * const issuer = createDcaIssuer({
 *   issuerName: "sesamy",
 *   privateKeyPem: process.env.SESAMY_ECDH_PRIVATE_KEY!,
 *   keyId: "2025-10",
 *   trustedPublisherKeys: {
 *     "www.news-site.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
 *   },
 * });
 *
 * // In your unlock endpoint handler:
 * const response = await issuer.unlock(request, {
 *   grantedContentNames: ["bodytext"],
 *   deliveryMode: "periodKey",
 * });
 * ```
 */
export function createDcaIssuer(config: DcaIssuerServerConfig) {
    let privateKeyPromise: Promise<{ key: WebCryptoKey; algorithm: DcaSealAlgorithm }> | null = null;

    function getPrivateKey() {
        if (!privateKeyPromise) {
            privateKeyPromise = importIssuerPrivateKey(config.privateKeyPem);
        }
        return privateKeyPromise;
    }

    return {
        /**
         * Process an unlock request.
         *
         * @param request - The unlock request from the client
         * @param accessDecision - Which content to grant and how to deliver keys
         * @returns Unlock response with decrypted key material
         */
        unlock: async (
            request: DcaUnlockRequest,
            accessDecision: DcaAccessDecision,
        ): Promise<DcaUnlockResponse> => {
            return processUnlock(config, getPrivateKey, request, accessDecision);
        },

        /**
         * Verify the request JWTs without unsealing.
         * Useful for pre-flight checks before making access decisions.
         */
        verify: async (request: DcaUnlockRequest): Promise<DcaVerifiedRequest> => {
            return verifyRequest(config, request);
        },
    };
}

// ============================================================================
// Types
// ============================================================================

/**
 * Access decision — determines what the issuer returns.
 */
export interface DcaAccessDecision {
    /** Which content items to grant access to */
    grantedContentNames: string[];
    /**
     * Key delivery mode:
     *   - "contentKey": return raw contentKeys (client decrypts directly)
     *   - "periodKey": return periodKeys (client unwraps contentKey from sealedContentKeys, enables caching)
     */
    deliveryMode: "contentKey" | "periodKey";
}

/**
 * Verified request — result of JWT verification (before unsealing).
 */
export interface DcaVerifiedRequest {
    /** Verified resource payload from resourceJWT */
    resource: DcaResource;
    /** Verified issuer JWT payload */
    issuerPayload: DcaIssuerJwtPayload;
}

// ============================================================================
// Core logic
// ============================================================================

async function verifyRequest(
    config: DcaIssuerServerConfig,
    request: DcaUnlockRequest,
): Promise<DcaVerifiedRequest> {
    // 1. Look up publisher signing key from domain
    const domain = request.resource.domain;
    const publisherKeyPem = config.trustedPublisherKeys[domain];
    if (!publisherKeyPem) {
        throw new Error(`Unknown publisher domain: ${domain}`);
    }

    // 2. Verify resourceJWT
    const resource = await verifyJwt<DcaResource>(request.resourceJWT, publisherKeyPem);

    // 2b. Bind unsigned request.resource to the signed resourceJWT payload.
    //     Upstream access logic may read unsigned metadata, so reject mismatches.
    if (request.resource.domain !== resource.domain) {
        throw new Error(
            `resource.domain mismatch: unsigned "${request.resource.domain}" vs signed "${resource.domain}"`,
        );
    }
    if (request.resource.resourceId !== resource.resourceId) {
        throw new Error(
            `resource.resourceId mismatch: unsigned "${request.resource.resourceId}" vs signed "${resource.resourceId}"`,
        );
    }
    if (request.resource.renderId !== resource.renderId) {
        throw new Error(
            `resource.renderId mismatch: unsigned "${request.resource.renderId}" vs signed "${resource.renderId}"`,
        );
    }
    if (request.resource.issuedAt !== resource.issuedAt) {
        throw new Error(
            `resource.issuedAt mismatch: unsigned "${request.resource.issuedAt}" vs signed "${resource.issuedAt}"`,
        );
    }

    // 3. Verify issuerJWT
    const issuerPayload = await verifyJwt<DcaIssuerJwtPayload>(request.issuerJWT, publisherKeyPem);

    // 4. Check renderId binding
    if (issuerPayload.renderId !== resource.renderId) {
        throw new Error("renderId mismatch between resourceJWT and issuerJWT");
    }

    // 5. Check issuerName binding
    if (issuerPayload.issuerName !== config.issuerName) {
        throw new Error(`issuerName mismatch: expected "${config.issuerName}", got "${issuerPayload.issuerName}"`);
    }

    if (request.issuerName !== config.issuerName) {
        throw new Error(`Request issuerName mismatch: expected "${config.issuerName}", got "${request.issuerName}"`);
    }

    // 6. Verify integrity proofs
    await verifyIssuerProof(issuerPayload, request.sealed);

    return { resource, issuerPayload };
}

async function processUnlock(
    config: DcaIssuerServerConfig,
    getPrivateKey: () => Promise<{ key: WebCryptoKey; algorithm: DcaSealAlgorithm }>,
    request: DcaUnlockRequest,
    accessDecision: DcaAccessDecision,
): Promise<DcaUnlockResponse> {
    // Verify everything first
    await verifyRequest(config, request);

    // Verify keyId matches
    if (request.keyId !== config.keyId) {
        throw new Error(`keyId mismatch: expected "${config.keyId}", got "${request.keyId}"`);
    }

    // Get private key
    const { key: privateKey, algorithm } = await getPrivateKey();

    // Import client public key for client-bound transport (if provided)
    const clientBound = !!request.clientPublicKey;
    let clientRsaPubKey: WebCryptoKey | null = null;
    if (clientBound) {
        clientRsaPubKey = await importRsaPublicKey(fromBase64Url(request.clientPublicKey!));
    }

    // Unseal granted content items
    const keys: Record<string, DcaUnlockedKeys> = {};

    for (const contentName of accessDecision.grantedContentNames) {
        const sealedEntry = request.sealed[contentName];
        if (!sealedEntry) {
            throw new Error(`No sealed data for content item "${contentName}"`);
        }

        if (accessDecision.deliveryMode === "contentKey") {
            // Direct path: unseal and return contentKey
            const contentKeyBytes = await unseal(sealedEntry.contentKey, privateKey, algorithm);
            keys[contentName] = {
                contentKey: clientBound
                    ? toBase64Url(await rsaOaepEncrypt(clientRsaPubKey!, contentKeyBytes))
                    : toBase64Url(contentKeyBytes),
            };
        } else {
            // Cacheable path: unseal and return periodKeys
            const periodKeys: Record<string, string> = {};
            for (const [t, sealedPeriodKey] of Object.entries(sealedEntry.periodKeys)) {
                const periodKeyBytes = await unseal(sealedPeriodKey, privateKey, algorithm);
                periodKeys[t] = clientBound
                    ? toBase64Url(await rsaOaepEncrypt(clientRsaPubKey!, periodKeyBytes))
                    : toBase64Url(periodKeyBytes);
            }
            keys[contentName] = { periodKeys };
        }
    }

    return {
        keys,
        ...(clientBound ? { transport: "client-bound" as const } : {}),
    };
}
