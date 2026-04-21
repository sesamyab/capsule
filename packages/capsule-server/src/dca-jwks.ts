/**
 * DCA JWKS — fetch, cache, and select issuer public keys from a JWKS URL.
 *
 * Supports RFC 7517 JWKS documents with kty=EC (crv=P-256) and kty=RSA keys.
 * Keys are filtered to those suitable for encryption wrapping:
 *   - use === "enc" OR use claim absent
 *   - status !== "retired" (custom, honored if present)
 *   - kid is required
 *
 * Results are cached in-memory per URL. Cache-Control: max-age is honored,
 * with a 1-hour fallback when no directive is present. When a refresh fails
 * but a cached copy exists, the cache is returned and a warning is logged —
 * availability is prioritised over freshness.
 */

import {
    importEcdhP256PublicKeyFromJwk,
    importRsaPublicKeyFromJwk,
    type WebCryptoKey,
} from "./web-crypto";

import type { DcaWrapAlgorithm } from "./dca-wrap";

export interface Jwk {
    kty: string;
    kid?: string;
    use?: string;
    alg?: string;
    crv?: string;
    x?: string;
    y?: string;
    n?: string;
    e?: string;
    /** Non-standard but honored: "retired" excludes the key from selection. */
    status?: string;
    [extra: string]: unknown;
}

export interface JwksDocument {
    keys: Jwk[];
}

/** A key resolved from the JWKS — imported and ready for wrap(). */
export interface ResolvedIssuerKey {
    kid: string;
    key: WebCryptoKey;
    algorithm: DcaWrapAlgorithm;
}

interface CacheEntry {
    jwks: JwksDocument;
    /** Unix ms — when the cache entry is no longer fresh */
    expiresAt: number;
}

const FALLBACK_MAX_AGE_SECONDS = 3600;

const cache = new Map<string, CacheEntry>();

/**
 * Parse Cache-Control max-age from a Response header.
 * Returns undefined when not present / not parseable.
 */
function parseMaxAge(cacheControl: string | null): number | undefined {
    if (!cacheControl) return undefined;
    const match = /(?:^|[,\s])max-age\s*=\s*(\d+)/i.exec(cacheControl);
    if (!match) return undefined;
    const n = Number(match[1]);
    return Number.isFinite(n) && n >= 0 ? n : undefined;
}

/**
 * Select JWKS keys suitable for wrapping: must carry a kid, must not be
 * flagged retired, must have use="enc" or an absent use claim.
 */
export function selectActiveKeys(jwks: JwksDocument): Jwk[] {
    if (!Array.isArray(jwks.keys)) return [];
    return jwks.keys.filter((k) => {
        if (!k || typeof k !== "object") return false;
        if (typeof k.kid !== "string" || k.kid === "") return false;
        if (k.status === "retired") return false;
        if (k.use !== undefined && k.use !== "enc") return false;
        if (k.kty === "EC") {
            return k.crv === "P-256";
        }
        if (k.kty === "RSA") {
            return true;
        }
        return false;
    });
}

async function importJwkToCryptoKey(jwk: Jwk): Promise<ResolvedIssuerKey> {
    if (jwk.kty === "EC" && jwk.crv === "P-256") {
        const key = await importEcdhP256PublicKeyFromJwk(jwk);
        return { kid: jwk.kid!, key, algorithm: "ECDH-P256" };
    }
    if (jwk.kty === "RSA") {
        const key = await importRsaPublicKeyFromJwk(jwk);
        return { kid: jwk.kid!, key, algorithm: "RSA-OAEP" };
    }
    throw new Error(`Unsupported JWK kty="${jwk.kty}" crv="${jwk.crv ?? ""}"`);
}

async function doFetchJwks(url: string): Promise<{ jwks: JwksDocument; maxAgeSeconds: number }> {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`JWKS fetch failed for ${url}: HTTP ${response.status}`);
    }
    const body = (await response.json()) as JwksDocument;
    if (!body || !Array.isArray(body.keys)) {
        throw new Error(`JWKS fetch failed for ${url}: response has no "keys" array`);
    }
    const maxAge = parseMaxAge(response.headers.get("Cache-Control")) ?? FALLBACK_MAX_AGE_SECONDS;
    return { jwks: body, maxAgeSeconds: maxAge };
}

/**
 * Fetch a JWKS document, honoring the in-memory cache. Returns the cached
 * copy when still fresh. Falls back to a stale cached copy if the refresh
 * fails (with a console warning); throws if no cache is available.
 */
export async function fetchJwks(url: string): Promise<JwksDocument> {
    const now = Date.now();
    const cached = cache.get(url);
    if (cached && cached.expiresAt > now) {
        return cached.jwks;
    }

    try {
        const { jwks, maxAgeSeconds } = await doFetchJwks(url);
        cache.set(url, { jwks, expiresAt: now + maxAgeSeconds * 1000 });
        return jwks;
    } catch (err) {
        if (cached) {
            console.warn(
                `JWKS fetch failed for ${url}; using cached copy. Error: ${(err as Error).message}`,
            );
            return cached.jwks;
        }
        throw new Error(
            `JWKS fetch failed for ${url} and no cached copy is available: ${(err as Error).message}`,
        );
    }
}

/**
 * Force-refresh a cached JWKS entry (or populate the cache on first call).
 * Useful when a "key not found" error from the issuer suggests a rotation
 * happened after the last cache fetch.
 */
export async function refreshJwks(url: string): Promise<JwksDocument> {
    cache.delete(url);
    return fetchJwks(url);
}

/**
 * Fetch (or reuse cached) JWKS and return the active keys, imported as
 * CryptoKey instances.
 */
export async function getActiveIssuerKeys(url: string): Promise<ResolvedIssuerKey[]> {
    const jwks = await fetchJwks(url);
    const active = selectActiveKeys(jwks);
    if (active.length === 0) {
        throw new Error(`JWKS at ${url} contains no usable active keys`);
    }
    return Promise.all(active.map(importJwkToCryptoKey));
}

/**
 * Test hook — clear all cached JWKS entries (or a single url).
 */
export function clearJwksCache(url?: string): void {
    if (url) {
        cache.delete(url);
    } else {
        cache.clear();
    }
}
