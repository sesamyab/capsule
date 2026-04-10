/**
 * DCA Issuer — server-side handler for unlock requests.
 *
 * The issuer:
 *   1. Normalises and validates the request domain against a trusted-publisher allowlist
 *   2. Looks up the publisher's signing key from the allowlist
 *   3. Verifies resourceJWT (ES256) — binds request to the publisher
 *   4. Re-verifies the signed domain against the allowlist (defence-in-depth)
 *   5. Checks optional per-publisher resource constraints (allowedResourceIds)
 *   6. Makes an access decision (application-specific)
 *   7. Unseals and returns contentKeys or periodKeys to the client
 */

import { verifyJwt, decodeJwtPayload, resourceJwtPayloadToResource } from "./dca-jwt";
import { unseal, importIssuerPrivateKey, type DcaSealAlgorithm } from "./dca-seal";
import {
    toBase64Url,
    fromBase64Url,
    encodeUtf8,
    importRsaPublicKey,
    rsaOaepEncrypt,
    type WebCryptoKey,
} from "./web-crypto";

import type {
    DcaResource,
    DcaResourceJwtPayload,
    DcaIssuerServerConfig,
    DcaTrustedPublisher,
    DcaUnlockRequest,
    DcaUnlockResponse,
    DcaContentEncryptionKey,
    DcaSealedContentEncryptionKey,
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
            return processUnlock(publisherMap, getPrivateKey, request, accessDecision);
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
            return processShareLinkUnlock(publisherMap, getPrivateKey, request, options);
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
            return verifyRequest(publisherMap, request);
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
    /**
     * Which content items to grant access to (by contentName).
     * Mutually exclusive with `grantedKeyNames`.
     */
    grantedContentNames?: string[];
    /**
     * Which key domains to grant access to (keyName-based).
     * The issuer resolves keyNames → contentNames using the request's
     * `contentKeyMap`. If no contentKeyMap is present, keyNames are
     * treated as contentNames (backward compatible).
     *
     * Mutually exclusive with `grantedContentNames`.
     */
    grantedKeyNames?: string[];
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
}

// ============================================================================
// Core logic
// ============================================================================

async function verifyRequest(
    publisherMap: NormalisedPublisherMap,
    request: DcaUnlockRequest,
): Promise<DcaVerifiedRequest> {
    if (!Array.isArray(request.contentEncryptionKeys)) {
        throw new Error("contentEncryptionKeys must be an array");
    }

    if (request.contentEncryptionKeys.length === 0) {
        throw new Error("contentEncryptionKeys must not be empty");
    }

    const seenContentNames = new Set<string>();
    for (const entry of request.contentEncryptionKeys) {
        if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
            throw new Error("Each contentEncryptionKeys entry must be a plain object");
        }

        if ("contentName" in entry && typeof entry.contentName !== "string") {
            throw new Error("contentEncryptionKeys entry contentName must be a string");
        }

        const effectiveName = (entry as DcaSealedContentEncryptionKey).contentName ?? "default";
        if (effectiveName === "") {
            throw new Error("contentEncryptionKeys entry contentName must not be empty");
        }

        if (seenContentNames.has(effectiveName)) {
            throw new Error(
                `Duplicate contentName "${effectiveName}" in contentEncryptionKeys`,
            );
        }
        seenContentNames.add(effectiveName);
    }

    // 1. Decode (unverified) resourceJWT to get domain for publisher key lookup.
    const decoded = decodeJwtPayload<DcaResourceJwtPayload>(request.resourceJWT);
    const rawDomain = decoded.iss;

    const publisher = publisherMap.lookup(rawDomain);
    if (!publisher) {
        throw new Error(`Untrusted publisher domain: "${rawDomain}"`);
    }

    // 2. Verify resourceJWT with the publisher's signing key.
    const jwtPayload = await verifyJwt<DcaResourceJwtPayload>(request.resourceJWT, publisher.signingKeyPem);
    const resource = resourceJwtPayloadToResource(jwtPayload);

    // 3. Defence-in-depth: re-verify the *signed* domain against the allowlist.
    const signedPublisher = publisherMap.lookup(resource.domain);
    if (!signedPublisher || signedPublisher.signingKeyPem !== publisher.signingKeyPem) {
        throw new Error(
            `Signed domain "${resource.domain}" does not resolve to the same trusted publisher key`,
        );
    }

    // 4. Per-publisher resource constraints (optional allowedResourceIds).
    checkResourceConstraints(publisher, rawDomain, resource.resourceId);

    // Sealed blobs are bound to this render via AAD (renderId).
    // Cross-resource key substitution fails at unseal time.
    return { resource };
}

/**
 * Shared unseal-and-respond helper used by both the normal unlock path and the
 * share-link unlock path.  Centralising this logic avoids drift when
 * transport/security behaviour changes.
 */
async function unsealAndRespond(
    getPrivateKey: () => Promise<{ key: WebCryptoKey; algorithm: DcaSealAlgorithm }>,
    request: DcaUnlockRequest,
    resource: DcaResource,
    grantedContentNames: string[],
    deliveryMode: "contentKey" | "periodKey",
): Promise<DcaUnlockResponse> {

    // Get private key
    const { key: privateKey, algorithm } = await getPrivateKey();

    // Import client public key for client-bound transport (if provided)
    const clientBound = !!request.clientPublicKey;
    let clientRsaPubKey: WebCryptoKey | null = null;
    if (clientBound) {
        clientRsaPubKey = await importRsaPublicKey(fromBase64Url(request.clientPublicKey!));
    }

    // Build lookup map from flat array
    const keysByName = new Map<string, DcaSealedContentEncryptionKey>();
    for (const entry of request.contentEncryptionKeys) {
        keysByName.set(entry.contentName ?? "default", entry);
    }

    // AAD binds sealed blobs to this render — prevents cross-resource key substitution.
    const sealAad = encodeUtf8(resource.renderId);

    // Unseal granted content items
    const contentEncryptionKeys: DcaContentEncryptionKey[] = [];

    for (const contentName of grantedContentNames) {
        const keysEntry = keysByName.get(contentName);
        if (!keysEntry) {
            throw new Error(`No contentEncryptionKeys data for content item "${contentName}"`);
        }

        if (deliveryMode === "contentKey") {
            // Direct path: unseal and return contentKey
            if (!keysEntry.contentKey) {
                throw new Error(`Missing contentKey for content item "${contentName}"`);
            }
            const contentKeyBytes = await unseal(keysEntry.contentKey, privateKey, algorithm, sealAad);
            contentEncryptionKeys.push({
                contentName,
                contentKey: clientBound
                    ? toBase64Url(await rsaOaepEncrypt(clientRsaPubKey!, contentKeyBytes))
                    : toBase64Url(contentKeyBytes),
            });
        } else {
            // Cacheable path: unseal and return periodKeys
            if (!keysEntry.periodKeys || !Array.isArray(keysEntry.periodKeys)) {
                throw new Error(`Missing or invalid periodKeys for content item "${contentName}"`);
            }
            const periodKeys = [];
            for (const pk of keysEntry.periodKeys) {
                const periodKeyBytes = await unseal(pk.key, privateKey, algorithm, sealAad);
                periodKeys.push({
                    bucket: pk.bucket,
                    key: clientBound
                        ? toBase64Url(await rsaOaepEncrypt(clientRsaPubKey!, periodKeyBytes))
                        : toBase64Url(periodKeyBytes),
                });
            }
            contentEncryptionKeys.push({ contentName, periodKeys });
        }
    }

    return {
        contentEncryptionKeys,
        ...(clientBound ? { transport: "client-bound" as const } : {}),
    };
}

async function processUnlock(
    publisherMap: NormalisedPublisherMap,
    getPrivateKey: () => Promise<{ key: WebCryptoKey; algorithm: DcaSealAlgorithm }>,
    request: DcaUnlockRequest,
    accessDecision: DcaAccessDecision,
): Promise<DcaUnlockResponse> {
    // Verify everything first
    const { resource } = await verifyRequest(publisherMap, request);

    // Resolve grantedContentNames from the access decision
    const grantedContentNames = resolveGrantedContentNames(accessDecision, request);

    return unsealAndRespond(
        getPrivateKey,
        request,
        resource,
        grantedContentNames,
        accessDecision.deliveryMode,
    );
}

/**
 * Resolve the final list of contentNames to grant from an access decision.
 *
 * - If `grantedContentNames` is provided, use those directly.
 * - If `grantedKeyNames` is provided, resolve via contentKeyMap → contentNames.
 * - If neither is provided, throws.
 */
function resolveGrantedContentNames(
    accessDecision: DcaAccessDecision,
    request: DcaUnlockRequest,
): string[] {
    // Build a set of available content names from the flat array
    const availableNames = new Set(
        request.contentEncryptionKeys.map(k => k.contentName ?? "default"),
    );

    if (accessDecision.grantedContentNames && accessDecision.grantedContentNames.length > 0) {
        return accessDecision.grantedContentNames;
    }

    if (accessDecision.grantedKeyNames && accessDecision.grantedKeyNames.length > 0) {
        const keyNameSet = new Set(accessDecision.grantedKeyNames);
        const contentKeyMap = request.contentKeyMap;

        if (contentKeyMap && Object.keys(contentKeyMap).length > 0) {
            // Resolve keyNames → contentNames via the contentKeyMap
            return Object.entries(contentKeyMap)
                .filter(([, keyName]) => keyNameSet.has(keyName))
                .map(([contentName]) => contentName)
                .filter(contentName => availableNames.has(contentName));
        }

        // No contentKeyMap: treat keyNames as contentNames (backward compat)
        return accessDecision.grantedKeyNames.filter(name => availableNames.has(name));
    }

    throw new Error("Access decision must specify grantedContentNames or grantedKeyNames");
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

    // Runtime type guards for timestamp claims.
    // Without these, missing or non-numeric values (undefined, NaN, strings)
    // silently pass the numeric comparisons (e.g. `undefined <= number` → false).
    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
        throw new Error("Share token: exp must be a finite number");
    }
    if (typeof payload.iat !== "number" || !Number.isFinite(payload.iat)) {
        throw new Error("Share token: iat must be a finite number");
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
        // keyNames can substitute for contentNames
        if (!payload.keyNames || !Array.isArray(payload.keyNames) || payload.keyNames.length === 0) {
            throw new Error("Share token: contentNames (or keyNames) must be a non-empty array");
        }
    }

    return payload;
}

/**
 * Process an unlock request authorized by a share link token.
 */
async function processShareLinkUnlock(
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
    const { resource } = await verifyRequest(publisherMap, request);

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
    //    Resolve keyNames → contentNames if the token uses keyNames.
    //    Only grant content names that exist in both the token/keyNames AND the contentEncryptionKeys.
    const availableContentNames = new Set(
        request.contentEncryptionKeys.map(k => k.contentName ?? "default"),
    );
    let grantedContentNames: string[];

    if (sharePayload.keyNames && sharePayload.keyNames.length > 0) {
        // keyName-based share token: resolve keyNames → contentNames
        const keyNameSet = new Set(sharePayload.keyNames);
        const contentKeyMap = request.contentKeyMap;

        if (contentKeyMap && Object.keys(contentKeyMap).length > 0) {
            grantedContentNames = Object.entries(contentKeyMap)
                .filter(([, keyName]) => keyNameSet.has(keyName))
                .map(([contentName]) => contentName)
                .filter(name => availableContentNames.has(name));
        } else {
            // No contentKeyMap: treat keyNames as contentNames
            grantedContentNames = sharePayload.keyNames.filter(
                name => availableContentNames.has(name),
            );
        }
    } else {
        grantedContentNames = sharePayload.contentNames.filter(
            (name) => availableContentNames.has(name),
        );
    }

    if (grantedContentNames.length === 0) {
        throw new Error(
            "Share token: no matching content items — token grants " +
            `[${sharePayload.contentNames.join(", ")}] but contentKeys contains [${[...availableContentNames].join(", ")}]`,
        );
    }

    // 7. Delegate to the shared unseal-and-respond helper
    const deliveryMode = options?.deliveryMode ?? "contentKey";

    return unsealAndRespond(
        getPrivateKey,
        request,
        resource,
        grantedContentNames,
        deliveryMode,
    );
}
