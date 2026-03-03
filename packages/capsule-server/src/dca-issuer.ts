/**
 * DCA Issuer — server-side handler for unlock requests.
 *
 * The issuer:
 *   1. Normalises and validates the request domain against a trusted-publisher allowlist
 *   2. Looks up the publisher's signing key from the allowlist
 *   3. Verifies resourceJWT (ES256) — binds request to the publisher
 *   4. Re-verifies the signed domain against the allowlist (defence-in-depth)
 *   5. Checks optional per-publisher resource constraints (allowedResourceIds)
 *   6. Verifies issuerJWT integrity proofs — confirms sealed blobs weren't tampered with
 *   7. Makes an access decision (application-specific)
 *   8. Unseals and returns contentKeys or periodKeys to the client
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
    DcaTrustedPublisher,
    DcaUnlockRequest,
    DcaUnlockResponse,
    DcaUnlockedKeys,
    DcaShareLinkTokenPayload,
} from "./dca-types";

// ============================================================================
// Domain normalisation & validation helpers
// ============================================================================

/** Loose check: hostname chars (letters, digits, hyphens, dots). */
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/**
 * Normalise a domain: lowercase, strip trailing dots.
 * Returns the normalised string or throws on clearly invalid input.
 */
function normalizeDomain(raw: string): string {
    if (!raw || typeof raw !== "string") {
        throw new Error("Domain must be a non-empty string");
    }
    // Lowercase and strip trailing dots (DNS root label)
    const d = raw.toLowerCase().replace(/\.+$/, "");
    if (!DOMAIN_RE.test(d)) {
        throw new Error(`Invalid domain: "${raw}"`);
    }
    return d;
}

/**
 * Resolve a trustedPublisherKeys entry (string | DcaTrustedPublisher)
 * into a canonical `DcaTrustedPublisher` object.
 */
function resolvePublisherEntry(entry: string | DcaTrustedPublisher): DcaTrustedPublisher {
    if (typeof entry === "string") {
        return { signingKeyPem: entry };
    }
    return entry;
}

// ============================================================================
// Internal: normalised publisher map (built once at construction time)
// ============================================================================

interface NormalisedPublisherMap {
    /** Normalised domain → resolved publisher config */
    entries: Map<string, DcaTrustedPublisher>;
    /** Look up a publisher by (potentially un-normalised) domain. */
    lookup(domain: string): DcaTrustedPublisher | undefined;
}

/**
 * Build a validated, normalised publisher map from config.
 * Throws eagerly on invalid domains or missing signing keys.
 */
function buildPublisherMap(
    raw: Record<string, string | DcaTrustedPublisher>,
): NormalisedPublisherMap {
    const entries = new Map<string, DcaTrustedPublisher>();

    for (const [rawDomain, value] of Object.entries(raw)) {
        const domain = normalizeDomain(rawDomain);
        const publisher = resolvePublisherEntry(value);

        if (!publisher.signingKeyPem || typeof publisher.signingKeyPem !== "string") {
            throw new Error(
                `trustedPublisherKeys["${rawDomain}"]: signingKeyPem must be a non-empty PEM string`,
            );
        }

        if (entries.has(domain)) {
            throw new Error(
                `trustedPublisherKeys: duplicate domain "${domain}" (after normalisation of "${rawDomain}")`,
            );
        }

        entries.set(domain, publisher);
    }

    if (entries.size === 0) {
        throw new Error("trustedPublisherKeys must contain at least one entry");
    }

    return {
        entries,
        lookup(domain: string) {
            try {
                return entries.get(normalizeDomain(domain));
            } catch {
                // Malformed domain from the request → no match
                return undefined;
            }
        },
    };
}

/**
 * Check per-publisher resource constraints (if configured).
 */
function checkResourceConstraints(
    publisher: DcaTrustedPublisher,
    domain: string,
    resourceId: string,
): void {
    if (!publisher.allowedResourceIds || publisher.allowedResourceIds.length === 0) {
        return; // no constraint configured — allow all
    }

    const allowed = publisher.allowedResourceIds.some((pattern) => {
        if (typeof pattern === "string") return pattern === resourceId;
        return pattern.test(resourceId);
    });

    if (!allowed) {
        throw new Error(
            `Publisher "${domain}" is not allowed to claim resourceId "${resourceId}"`,
        );
    }
}

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
    // Validate and normalise the trusted-publisher allowlist eagerly.
    // This surfaces configuration errors at startup rather than at request time.
    const publisherMap = buildPublisherMap(config.trustedPublisherKeys);

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
            return processUnlock(config, publisherMap, getPrivateKey, request, accessDecision);
        },

        /**
         * Process an unlock request authorized by a share link token.
         *
         * The share link token is a publisher-signed JWT that grants
         * pre-authenticated access to specific content. The issuer:
         *   1. Verifies the request JWTs (same as normal unlock)
         *   2. Verifies the share link token signature (publisher-signed)
         *   3. Validates token claims (type, domain, resourceId, expiry)
         *   4. Grants access to the content names specified in the token
         *
         * DCA-compatible: no periodSecret required. Key material flows
         * through the normal seal/unseal channel.
         *
         * @param request - The unlock request from the client (must include shareToken)
         * @param options - Optional overrides (deliveryMode, onShareToken callback)
         * @returns Unlock response with decrypted key material
         */
        unlockWithShareToken: async (
            request: DcaUnlockRequest,
            options?: DcaShareLinkUnlockOptions,
        ): Promise<DcaUnlockResponse> => {
            return processShareLinkUnlock(config, publisherMap, getPrivateKey, request, options);
        },

        /**
         * Verify a share link token and return its payload.
         * Useful for pre-flight checks or custom access logic.
         *
         * @param shareToken - The share link token JWT
         * @param expectedDomain - Expected publisher domain (from the request)
         * @returns Verified share link token payload
         */
        verifyShareToken: async (
            shareToken: string,
            expectedDomain: string,
        ): Promise<DcaShareLinkTokenPayload> => {
            return verifyShareLinkToken(publisherMap, shareToken, expectedDomain);
        },

        /**
         * Verify the request JWTs without unsealing.
         * Useful for pre-flight checks before making access decisions.
         */
        verify: async (request: DcaUnlockRequest): Promise<DcaVerifiedRequest> => {
            return verifyRequest(config, publisherMap, request);
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
 * Options for share-link-token-authorized unlock.
 */
export interface DcaShareLinkUnlockOptions {
    /**
     * Key delivery mode (default: "contentKey").
     * Share link unlocks default to contentKey for simplicity,
     * but periodKey is also supported for cache-friendly flows.
     */
    deliveryMode?: "contentKey" | "periodKey";
    /**
     * Optional callback invoked after the share token is verified
     * but before keys are unsealed. Use for:
     *   - Use-count tracking (increment a counter, reject if maxUses exceeded)
     *   - Audit logging
     *   - Custom authorization checks
     *
     * Throw an error to reject the request.
     *
     * @param payload - The verified share link token payload
     * @param resource - The verified resource from the request
     */
    onShareToken?: (
        payload: DcaShareLinkTokenPayload,
        resource: DcaResource,
    ) => Promise<void> | void;
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
    publisherMap: NormalisedPublisherMap,
    request: DcaUnlockRequest,
): Promise<DcaVerifiedRequest> {
    // 1. Normalise and look up publisher from the trusted-publisher allowlist.
    //    The unsigned request.resource.domain is used ONLY for key selection;
    //    the signed domain is verified independently in step 2b/2c below.
    const rawDomain = request.resource.domain;
    const publisher = publisherMap.lookup(rawDomain);
    if (!publisher) {
        throw new Error(`Untrusted publisher domain: "${rawDomain}"`);
    }

    // 2. Verify resourceJWT with the publisher's signing key
    const resource = await verifyJwt<DcaResource>(request.resourceJWT, publisher.signingKeyPem);

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

    // 2c. Defence-in-depth: re-verify the *signed* domain against the allowlist.
    //     This prevents an attacker from using one trusted publisher's key to
    //     forge a JWT claiming a different (also trusted) publisher's domain.
    const signedPublisher = publisherMap.lookup(resource.domain);
    if (!signedPublisher || signedPublisher.signingKeyPem !== publisher.signingKeyPem) {
        throw new Error(
            `Signed domain "${resource.domain}" does not resolve to the same trusted publisher key`,
        );
    }

    // 2d. Per-publisher resource constraints (optional allowedResourceIds).
    checkResourceConstraints(publisher, rawDomain, resource.resourceId);

    // 3. Verify issuerJWT
    const issuerPayload = await verifyJwt<DcaIssuerJwtPayload>(request.issuerJWT, publisher.signingKeyPem);

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

/**
 * Shared unseal-and-respond helper used by both the normal unlock path and the
 * share-link unlock path.  Centralising this logic avoids drift when
 * transport/security behaviour changes.
 */
async function unsealAndRespond(
    config: DcaIssuerServerConfig,
    getPrivateKey: () => Promise<{ key: WebCryptoKey; algorithm: DcaSealAlgorithm }>,
    request: DcaUnlockRequest,
    grantedContentNames: string[],
    deliveryMode: "contentKey" | "periodKey",
): Promise<DcaUnlockResponse> {
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

    for (const contentName of grantedContentNames) {
        const sealedEntry = request.sealed[contentName];
        if (!sealedEntry) {
            throw new Error(`No sealed data for content item "${contentName}"`);
        }

        if (deliveryMode === "contentKey") {
            // Direct path: unseal and return contentKey
            if (!sealedEntry.contentKey) {
                throw new Error(`Missing sealed contentKey for content item "${contentName}"`);
            }
            const contentKeyBytes = await unseal(sealedEntry.contentKey, privateKey, algorithm);
            keys[contentName] = {
                contentKey: clientBound
                    ? toBase64Url(await rsaOaepEncrypt(clientRsaPubKey!, contentKeyBytes))
                    : toBase64Url(contentKeyBytes),
            };
        } else {
            // Cacheable path: unseal and return periodKeys
            if (!sealedEntry.periodKeys || typeof sealedEntry.periodKeys !== "object") {
                throw new Error(`Missing or invalid sealed periodKeys for content item "${contentName}"`);
            }
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

async function processUnlock(
    config: DcaIssuerServerConfig,
    publisherMap: NormalisedPublisherMap,
    getPrivateKey: () => Promise<{ key: WebCryptoKey; algorithm: DcaSealAlgorithm }>,
    request: DcaUnlockRequest,
    accessDecision: DcaAccessDecision,
): Promise<DcaUnlockResponse> {
    // Verify everything first
    await verifyRequest(config, publisherMap, request);

    return unsealAndRespond(
        config,
        getPrivateKey,
        request,
        accessDecision.grantedContentNames,
        accessDecision.deliveryMode,
    );
}

// ============================================================================
// Share Link Token verification & unlock
// ============================================================================

/**
 * Verify a share link token (publisher-signed JWT).
 *
 * @param publisherMap - Trusted publisher map
 * @param shareToken - The share link token JWT string
 * @param expectedDomain - The domain from the request (used for key lookup)
 * @returns Verified share link token payload
 * @throws Error if token is invalid, expired, or from an untrusted publisher
 */
async function verifyShareLinkToken(
    publisherMap: NormalisedPublisherMap,
    shareToken: string,
    expectedDomain: string,
): Promise<DcaShareLinkTokenPayload> {
    // Look up the publisher's signing key from the domain
    const publisher = publisherMap.lookup(expectedDomain);
    if (!publisher) {
        throw new Error(`Share token: untrusted publisher domain "${expectedDomain}"`);
    }

    // Verify JWT signature with the publisher's signing key
    const payload = await verifyJwt<DcaShareLinkTokenPayload>(shareToken, publisher.signingKeyPem);

    // Validate type discriminator
    if (payload.type !== "dca-share") {
        throw new Error(`Share token: invalid type "${payload.type}", expected "dca-share"`);
    }

    // Validate domain binding
    if (payload.domain !== expectedDomain) {
        throw new Error(
            `Share token: domain mismatch — token domain "${payload.domain}" vs request domain "${expectedDomain}"`,
        );
    }

    // Validate expiry
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) {
        throw new Error(`Share token: expired at ${new Date(payload.exp * 1000).toISOString()}`);
    }

    // Validate iat is not in the future (with 60s clock skew tolerance)
    if (payload.iat > now + 60) {
        throw new Error(`Share token: issued in the future (iat: ${payload.iat})`);
    }

    // Validate contentNames is a non-empty array
    if (!Array.isArray(payload.contentNames) || payload.contentNames.length === 0) {
        throw new Error("Share token: contentNames must be a non-empty array");
    }

    return payload;
}

/**
 * Process an unlock request authorized by a share link token.
 */
async function processShareLinkUnlock(
    config: DcaIssuerServerConfig,
    publisherMap: NormalisedPublisherMap,
    getPrivateKey: () => Promise<{ key: WebCryptoKey; algorithm: DcaSealAlgorithm }>,
    request: DcaUnlockRequest,
    options?: DcaShareLinkUnlockOptions,
): Promise<DcaUnlockResponse> {
    // 1. Verify the share token exists
    if (!request.shareToken) {
        throw new Error("Share link unlock requires a shareToken in the request");
    }

    // 2. Verify the request JWTs (same as normal unlock)
    const { resource } = await verifyRequest(config, publisherMap, request);

    // 3. Verify the share link token
    const sharePayload = await verifyShareLinkToken(
        publisherMap,
        request.shareToken,
        resource.domain,
    );

    // 4. Validate resource binding: the share token must be for this resource
    if (sharePayload.resourceId !== resource.resourceId) {
        throw new Error(
            `Share token: resourceId mismatch — token "${sharePayload.resourceId}" vs request "${resource.resourceId}"`,
        );
    }

    // 5. Invoke optional callback (use-count tracking, audit logging, etc.)
    if (options?.onShareToken) {
        await options.onShareToken(sharePayload, resource);
    }

    // 6. Build access decision from the share token's claims.
    //    Only grant content names that exist in both the token AND the sealed data.
    const availableContentNames = Object.keys(request.sealed);
    const grantedContentNames = sharePayload.contentNames.filter(
        (name) => availableContentNames.includes(name),
    );

    if (grantedContentNames.length === 0) {
        throw new Error(
            "Share token: no matching content items — token grants " +
            `[${sharePayload.contentNames.join(", ")}] but sealed data contains [${availableContentNames.join(", ")}]`,
        );
    }

    // 7. Delegate to the shared unseal-and-respond helper
    const deliveryMode = options?.deliveryMode ?? "contentKey";

    return unsealAndRespond(
        config,
        getPrivateKey,
        request,
        grantedContentNames,
        deliveryMode,
    );
}
