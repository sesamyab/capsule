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
 *   7. Unwraps and returns contentKeys or wrapKeys to the client
 */

import { verifyJwt, decodeJwtPayload, resourceJwtPayloadToResource } from "./dca-jwt";
import { unwrap, importIssuerPrivateKey, type DcaWrapAlgorithm } from "./dca-wrap";
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
    DcaUnlockedKey,
    DcaIssuerKey,
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
    entries: Map<string, DcaTrustedPublisher>;
    lookup(domain: string): DcaTrustedPublisher | undefined;
}

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
                return undefined;
            }
        },
    };
}

function checkResourceConstraints(
    publisher: DcaTrustedPublisher,
    domain: string,
    resourceId: string,
): void {
    if (!publisher.allowedResourceIds || publisher.allowedResourceIds.length === 0) {
        return;
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
 * const response = await issuer.unlock(request, {
 *   grantedContentNames: ["bodytext"],
 *   deliveryMode: "wrapKey",
 * });
 * ```
 */
export function createDcaIssuer(config: DcaIssuerServerConfig) {
    const publisherMap = buildPublisherMap(config.trustedPublisherKeys);

    let privateKeyPromise: Promise<{ key: WebCryptoKey; algorithm: DcaWrapAlgorithm }> | null = null;

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
         * If `resourceJWT` is present, verifies the publisher's signature
         * and trust chain before unwrapping. If absent, proceeds directly
         * to unwrapping — the scope AAD binding provides integrity.
         *
         * @param request - The unlock request from the client
         * @param accessDecision - Which content to grant and how to deliver keys
         * @returns Unlock response with unwrapped key material
         */
        unlock: async (
            request: DcaUnlockRequest,
            accessDecision: DcaAccessDecision,
        ): Promise<DcaUnlockResponse> => {
            return processUnlock(publisherMap, config.keyId, getPrivateKey, request, accessDecision);
        },

        /**
         * Process an unlock request authorized by a share link token.
         *
         * Requires `resourceJWT` — the share token is verified against the
         * publisher's signing key and bound to the resource.
         */
        unlockWithShareToken: async (
            request: DcaUnlockRequest,
            options?: DcaShareLinkUnlockOptions,
        ): Promise<DcaUnlockResponse> => {
            return processShareLinkUnlock(publisherMap, config.keyId, getPrivateKey, request, options);
        },

        /**
         * Verify a share link token and return its payload.
         */
        verifyShareToken: async (
            shareToken: string,
            expectedDomain: string,
        ): Promise<DcaShareLinkTokenPayload> => {
            return verifyShareLinkToken(publisherMap, shareToken, expectedDomain);
        },

        /**
         * Verify the publisher's resourceJWT without unwrapping.
         *
         * Not needed for the core unwrap flow (scope AAD binding handles integrity),
         * but useful when you need the verified resource payload.
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
     * Mutually exclusive with `grantedScopes`.
     */
    grantedContentNames?: string[];
    /**
     * Which scopes to grant access to.
     * The issuer resolves scopes → contentNames using the scope
     * field on each key entry.
     *
     * Mutually exclusive with `grantedContentNames`.
     */
    grantedScopes?: string[];
    /**
     * Key delivery mode:
     *   - "direct": return raw contentKeys (client decrypts directly, no caching)
     *   - "wrapKey": return wrapKeys (client unwraps contentKeys from the manifest, enables caching)
     */
    deliveryMode: "direct" | "wrapKey";
}

export interface DcaShareLinkUnlockOptions {
    /**
     * Key delivery mode (default: "direct").
     * Share link unlocks default to direct for simplicity,
     * but wrapKey is also supported for cache-friendly flows.
     */
    deliveryMode?: "direct" | "wrapKey";
    /**
     * Optional callback invoked after the share token is verified
     * but before keys are unwrapped. Use for use-count tracking,
     * audit logging, or custom authorization checks.
     *
     * Throw an error to reject the request.
     */
    onShareToken?: (
        payload: DcaShareLinkTokenPayload,
        resource: DcaResource,
    ) => Promise<void> | void;
}

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
    if (!Array.isArray(request.keys)) {
        throw new Error("keys must be an array");
    }

    if (request.keys.length === 0) {
        throw new Error("keys must not be empty");
    }

    const seenPairs = new Set<string>();
    for (const entry of request.keys) {
        if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
            throw new Error("Each keys entry must be a plain object");
        }

        if ("contentName" in entry && typeof entry.contentName !== "string") {
            throw new Error("keys entry contentName must be a string");
        }

        const entryObj = entry as DcaIssuerKey;
        if (typeof entryObj.scope !== "string" || entryObj.scope === "") {
            throw new Error("keys entry must have a non-empty scope string");
        }

        const effectiveName = entryObj.contentName ?? "default";
        if (effectiveName === "") {
            throw new Error("keys entry contentName must not be empty");
        }

        // Multiple entries with the same contentName are allowed when each
        // carries a distinct `kid` (rotation overlap). Without `kid`, the
        // legacy single-entry-per-contentName rule still holds.
        const pairKey = `${effectiveName}\x00${entryObj.kid ?? ""}`;
        if (seenPairs.has(pairKey)) {
            throw new Error(
                entryObj.kid
                    ? `Duplicate keys entry for contentName "${effectiveName}" kid "${entryObj.kid}"`
                    : `Duplicate contentName "${effectiveName}" in keys`,
            );
        }
        seenPairs.add(pairKey);
    }

    if (!request.resourceJWT) {
        throw new Error("resourceJWT is required for publisher trust verification");
    }
    const decoded = decodeJwtPayload<DcaResourceJwtPayload>(request.resourceJWT);
    const rawDomain = decoded.iss;

    const publisher = publisherMap.lookup(rawDomain);
    if (!publisher) {
        throw new Error(`Untrusted publisher domain: "${rawDomain}"`);
    }

    const jwtPayload = await verifyJwt<DcaResourceJwtPayload>(request.resourceJWT, publisher.signingKeyPem);
    const resource = resourceJwtPayloadToResource(jwtPayload);

    const signedPublisher = publisherMap.lookup(resource.domain);
    if (!signedPublisher || signedPublisher.signingKeyPem !== publisher.signingKeyPem) {
        throw new Error(
            `Signed domain "${resource.domain}" does not resolve to the same trusted publisher key`,
        );
    }

    checkResourceConstraints(publisher, rawDomain, resource.resourceId);

    return { resource };
}

/**
 * Pick the DcaIssuerKey entry for a given contentName from the request.
 *
 * When the publisher wraps for multiple issuer kids (JWKS rotation overlap),
 * there can be multiple entries per contentName. We prefer the entry tagged
 * with this issuer's own `keyId`. When no entry carries a kid (legacy
 * single-key manifests), we fall back to the sole entry.
 */
function pickEntryForIssuer(
    entries: DcaIssuerKey[],
    contentName: string,
    issuerKeyId: string,
): DcaIssuerKey | undefined {
    const matches = entries.filter(
        (e) => (e.contentName ?? "default") === contentName,
    );
    if (matches.length === 0) return undefined;
    if (matches.length === 1) return matches[0];

    const byKid = matches.find((e) => e.kid === issuerKeyId);
    if (byKid) return byKid;

    // Multiple kid-tagged entries but none match — fall through to the first
    // untagged entry if any, otherwise return undefined so the caller raises.
    const untagged = matches.find((e) => e.kid === undefined);
    return untagged;
}

/**
 * Shared unwrap-and-respond helper used by both the normal unlock path and the
 * share-link unlock path.
 */
async function unwrapAndRespond(
    issuerKeyId: string,
    getPrivateKey: () => Promise<{ key: WebCryptoKey; algorithm: DcaWrapAlgorithm }>,
    request: DcaUnlockRequest,
    grantedContentNames: string[],
    deliveryMode: "direct" | "wrapKey",
): Promise<DcaUnlockResponse> {

    const { key: privateKey, algorithm } = await getPrivateKey();

    const clientBound = !!request.clientPublicKey;
    let clientRsaPubKey: WebCryptoKey | null = null;
    if (clientBound) {
        clientRsaPubKey = await importRsaPublicKey(fromBase64Url(request.clientPublicKey!));
    }

    const keys: DcaUnlockedKey[] = [];

    for (const contentName of grantedContentNames) {
        const keysEntry = pickEntryForIssuer(request.keys, contentName, issuerKeyId);
        if (!keysEntry) {
            throw new Error(
                `No keys data for content item "${contentName}" matching issuer kid "${issuerKeyId}"`,
            );
        }

        // AAD is bound to the scope — tampering with scope causes unwrap failure
        const wrapAad = encodeUtf8(keysEntry.scope);

        if (deliveryMode === "direct") {
            if (typeof keysEntry.contentKey !== "string" || !keysEntry.contentKey) {
                throw new Error(`Missing or invalid contentKey for content item "${contentName}"`);
            }
            const contentKeyBytes = await unwrap(keysEntry.contentKey, privateKey, algorithm, wrapAad);
            keys.push({
                contentName,
                scope: keysEntry.scope,
                contentKey: clientBound
                    ? toBase64Url(await rsaOaepEncrypt(clientRsaPubKey!, contentKeyBytes))
                    : toBase64Url(contentKeyBytes),
            });
        } else {
            if (!keysEntry.wrapKeys || !Array.isArray(keysEntry.wrapKeys)) {
                throw new Error(`Missing or invalid wrapKeys for content item "${contentName}"`);
            }
            const wrapKeys = [];
            for (const wk of keysEntry.wrapKeys) {
                if (
                    typeof wk !== "object" || wk === null ||
                    typeof wk.key !== "string" || !wk.key ||
                    typeof wk.kid !== "string" || !wk.kid
                ) {
                    throw new Error(
                        `Invalid wrapKeys: missing key/kid for contentName "${contentName}"`,
                    );
                }
                const wrapKeyBytes = await unwrap(wk.key, privateKey, algorithm, wrapAad);
                wrapKeys.push({
                    kid: wk.kid,
                    key: clientBound
                        ? toBase64Url(await rsaOaepEncrypt(clientRsaPubKey!, wrapKeyBytes))
                        : toBase64Url(wrapKeyBytes),
                });
            }
            keys.push({ contentName, scope: keysEntry.scope, wrapKeys });
        }
    }

    return {
        keys,
        ...(clientBound ? { transport: "client-bound" as const } : {}),
    };
}

async function processUnlock(
    publisherMap: NormalisedPublisherMap,
    issuerKeyId: string,
    getPrivateKey: () => Promise<{ key: WebCryptoKey; algorithm: DcaWrapAlgorithm }>,
    request: DcaUnlockRequest,
    accessDecision: DcaAccessDecision,
): Promise<DcaUnlockResponse> {
    if (request.resourceJWT) {
        await verifyRequest(publisherMap, request);
    }

    const grantedContentNames = resolveGrantedContentNames(accessDecision, request);

    return unwrapAndRespond(
        issuerKeyId,
        getPrivateKey,
        request,
        grantedContentNames,
        accessDecision.deliveryMode,
    );
}

/**
 * Resolve the final list of contentNames to grant from an access decision.
 */
function resolveGrantedContentNames(
    accessDecision: DcaAccessDecision,
    request: DcaUnlockRequest,
): string[] {
    const hasNames = !!(accessDecision.grantedContentNames && accessDecision.grantedContentNames.length > 0);
    const hasScopes = !!(accessDecision.grantedScopes && accessDecision.grantedScopes.length > 0);

    // Fail closed: passing both would silently prefer one and could expand a
    // narrow content-name grant into a broader scope grant (or vice versa).
    if (hasNames && hasScopes) {
        throw new Error("Access decision: grantedContentNames and grantedScopes are mutually exclusive");
    }

    if (hasNames) {
        return accessDecision.grantedContentNames!;
    }

    if (hasScopes) {
        const scopeSet = new Set(accessDecision.grantedScopes);

        // Dedup: multi-kid manifests have one entry per (contentName × kid).
        return [
            ...new Set(
                request.keys
                    .filter(entry => scopeSet.has(entry.scope))
                    .map(entry => entry.contentName ?? "default"),
            ),
        ];
    }

    throw new Error("Access decision must specify grantedContentNames or grantedScopes");
}

// ============================================================================
// Share Link Token verification & unlock
// ============================================================================

async function verifyShareLinkToken(
    publisherMap: NormalisedPublisherMap,
    shareToken: string,
    expectedDomain: string,
): Promise<DcaShareLinkTokenPayload> {
    const publisher = publisherMap.lookup(expectedDomain);
    if (!publisher) {
        throw new Error(`Share token: untrusted publisher domain "${expectedDomain}"`);
    }

    const payload = await verifyJwt<DcaShareLinkTokenPayload>(shareToken, publisher.signingKeyPem);

    if (payload.type !== "dca-share") {
        throw new Error(`Share token: invalid type "${payload.type}", expected "dca-share"`);
    }

    if (payload.domain !== expectedDomain) {
        throw new Error(
            `Share token: domain mismatch — token domain "${payload.domain}" vs request domain "${expectedDomain}"`,
        );
    }

    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
        throw new Error("Share token: exp must be a finite number");
    }
    if (typeof payload.iat !== "number" || !Number.isFinite(payload.iat)) {
        throw new Error("Share token: iat must be a finite number");
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) {
        throw new Error(`Share token: expired at ${new Date(payload.exp * 1000).toISOString()}`);
    }

    if (payload.iat > now + 60) {
        throw new Error(`Share token: issued in the future (iat: ${payload.iat})`);
    }

    const hasContentNames = Array.isArray(payload.contentNames) && payload.contentNames.length > 0;
    const hasScopes = Array.isArray(payload.scopes) && payload.scopes.length > 0;
    if (!hasContentNames && !hasScopes) {
        throw new Error("Share token: contentNames (or scopes) must be a non-empty array");
    }
    if (hasContentNames && hasScopes) {
        throw new Error("Share token: contentNames and scopes are mutually exclusive");
    }

    return payload;
}

async function processShareLinkUnlock(
    publisherMap: NormalisedPublisherMap,
    issuerKeyId: string,
    getPrivateKey: () => Promise<{ key: WebCryptoKey; algorithm: DcaWrapAlgorithm }>,
    request: DcaUnlockRequest,
    options?: DcaShareLinkUnlockOptions,
): Promise<DcaUnlockResponse> {
    if (!request.shareToken) {
        throw new Error("Share link unlock requires a shareToken in the request");
    }

    const { resource } = await verifyRequest(publisherMap, request);

    const sharePayload = await verifyShareLinkToken(
        publisherMap,
        request.shareToken,
        resource.domain,
    );

    if (sharePayload.resourceId !== resource.resourceId) {
        throw new Error(
            `Share token: resourceId mismatch — token "${sharePayload.resourceId}" vs request "${resource.resourceId}"`,
        );
    }

    if (options?.onShareToken) {
        await options.onShareToken(sharePayload, resource);
    }

    // Build access decision from the share token's claims.
    // Deduplicate contentNames — multi-kid manifests have one entry per kid.
    const availableContentNames = new Set(
        request.keys.map(k => k.contentName ?? "default"),
    );
    let grantedContentNames: string[];

    if (sharePayload.scopes && sharePayload.scopes.length > 0) {
        const scopeSet = new Set(sharePayload.scopes);
        grantedContentNames = [
            ...new Set(
                request.keys
                    .filter(entry => scopeSet.has(entry.scope))
                    .map(entry => entry.contentName ?? "default")
                    .filter(name => availableContentNames.has(name)),
            ),
        ];
    } else {
        grantedContentNames = sharePayload.contentNames.filter(
            (name) => availableContentNames.has(name),
        );
    }

    if (grantedContentNames.length === 0) {
        const availableList = [...availableContentNames].join(", ");
        const tokenDetail =
            sharePayload.scopes && sharePayload.scopes.length > 0
                ? `scopes [${sharePayload.scopes.join(", ")}]`
                : `contentNames [${sharePayload.contentNames.join(", ")}]`;
        throw new Error(
            `Share token: no matching content items — token grants ${tokenDetail} but keys contains [${availableList}]`,
        );
    }

    const deliveryMode = options?.deliveryMode ?? "direct";

    return unwrapAndRespond(
        issuerKeyId,
        getPrivateKey,
        request,
        grantedContentNames,
        deliveryMode,
    );
}
