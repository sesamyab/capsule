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

async function processUnlock(
    config: DcaIssuerServerConfig,
    publisherMap: NormalisedPublisherMap,
    getPrivateKey: () => Promise<{ key: WebCryptoKey; algorithm: DcaSealAlgorithm }>,
    request: DcaUnlockRequest,
    accessDecision: DcaAccessDecision,
): Promise<DcaUnlockResponse> {
    // Verify everything first
    await verifyRequest(config, publisherMap, request);

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
