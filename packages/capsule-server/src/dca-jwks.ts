/**
 * DCA JWKS — fetch, cache, and select issuer public keys from a JWKS URL.
 *
 * Supports RFC 7517 JWKS documents with kty=EC (crv=P-256) and kty=RSA keys.
 * Keys are filtered to those suitable for encryption wrapping:
 *   - use === "enc" OR use claim absent
 *   - status !== "retired" (custom, honored if present)
 *   - kid is required
 *
 * Caching
 * -------
 * Freshness is driven by the response's `Cache-Control: max-age` directive
 * (1 hour fallback). A fresh entry is served straight from cache with no
 * network hop. When an entry is past its freshness window, we attempt a
 * refresh. If the refresh fails but a cached copy exists and is still within
 * the stale window (default 30 days past freshness), we serve it with a
 * console warning — availability beats freshness for wrap operations, since
 * issuer private-key rotation is rare.
 *
 * The cache backend is pluggable via {@link DcaJwksCache} so deployments on
 * Cloudflare Workers, Redis, or similar can persist across process restarts.
 * The default is an in-memory Map scoped to this module.
 */

import {
    importEcdhP256PublicKeyFromJwk,
    importEcdsaP256PublicKeyFromJwk,
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

/** A publisher signing key resolved from a JWKS — imported and ready for verify(). */
export interface ResolvedPublisherKey {
    kid: string;
    key: WebCryptoKey;
}

/**
 * A cached JWKS document plus its lifetime bounds.
 * Cache backends store and return this verbatim; all timestamps are unix ms.
 */
export interface DcaJwksCacheEntry {
    jwks: JwksDocument;
    /** Unix ms — upstream `Cache-Control` says the document is fresh until this time. */
    freshUntil: number;
    /**
     * Unix ms — hard cutoff after which the entry must not be served even on
     * upstream failure. Set to `freshUntil + staleWindowSeconds * 1000` at
     * write time.
     */
    staleUntil: number;
}

/**
 * Pluggable cache backend for JWKS documents.
 *
 * Methods may be sync or async. `delete` is optional — when absent,
 * {@link refreshJwks} just overwrites via `set` instead of deleting first.
 */
export interface DcaJwksCache {
    get(url: string): Promise<DcaJwksCacheEntry | undefined | null> | DcaJwksCacheEntry | undefined | null;
    set(url: string, entry: DcaJwksCacheEntry): Promise<void> | void;
    delete?(url: string): Promise<void> | void;
}

export interface DcaJwksOptions {
    /** Cache backend. Defaults to an in-memory Map scoped to this module. */
    cache?: DcaJwksCache;
    /**
     * Seconds past freshness that a cached entry may be served when the
     * upstream fetch fails. Default: 30 days.
     */
    staleWindowSeconds?: number;
    /**
     * Milliseconds to wait for the JWKS HTTP response before aborting.
     * Bounds publisher.render() latency when the issuer is unreachable.
     * Default: 5000.
     */
    fetchTimeoutMs?: number;
}

const FALLBACK_MAX_AGE_SECONDS = 3600;
/** 30 days — the default stale-if-error window. */
const DEFAULT_STALE_WINDOW_SECONDS = 30 * 24 * 3600;
const DEFAULT_FETCH_TIMEOUT_MS = 5000;

class InMemoryJwksCache implements DcaJwksCache {
    private readonly map = new Map<string, DcaJwksCacheEntry>();
    get(url: string): DcaJwksCacheEntry | undefined {
        return this.map.get(url);
    }
    set(url: string, entry: DcaJwksCacheEntry): void {
        this.map.set(url, entry);
    }
    delete(url: string): void {
        this.map.delete(url);
    }
    clear(): void {
        this.map.clear();
    }
}

const defaultCache = new InMemoryJwksCache();

function resolveOptions(opts?: DcaJwksOptions): {
    cache: DcaJwksCache;
    staleWindowSeconds: number;
    fetchTimeoutMs: number;
} {
    return {
        cache: opts?.cache ?? defaultCache,
        staleWindowSeconds: opts?.staleWindowSeconds ?? DEFAULT_STALE_WINDOW_SECONDS,
        fetchTimeoutMs: opts?.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS,
    };
}

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
            if (k.crv !== "P-256") return false;
            if (typeof k.x !== "string" || k.x === "") return false;
            if (typeof k.y !== "string" || k.y === "") return false;
            return true;
        }
        if (k.kty === "RSA") {
            if (typeof k.n !== "string" || k.n === "") return false;
            if (typeof k.e !== "string" || k.e === "") return false;
            return true;
        }
        return false;
    });
}

/**
 * Select JWKS keys suitable for publisher JWT verification: must carry a kid,
 * must not be flagged retired, must have use="sig" or an absent use claim,
 * and must be EC P-256 (ES256). RSA signing keys are not supported.
 */
export function selectActivePublisherKeys(jwks: JwksDocument): Jwk[] {
    if (!Array.isArray(jwks.keys)) return [];
    return jwks.keys.filter((k) => {
        if (!k || typeof k !== "object") return false;
        if (typeof k.kid !== "string" || k.kid === "") return false;
        if (k.status === "retired") return false;
        if (k.use !== undefined && k.use !== "sig") return false;
        if (k.kty !== "EC" || k.crv !== "P-256") return false;
        return true;
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

async function importPublisherJwk(jwk: Jwk): Promise<ResolvedPublisherKey> {
    if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
        throw new Error(
            `Unsupported publisher JWK kty="${jwk.kty}" crv="${jwk.crv ?? ""}" (expected EC P-256)`,
        );
    }
    const key = await importEcdsaP256PublicKeyFromJwk(jwk);
    return { kid: jwk.kid!, key };
}

async function doFetchJwks(
    url: string,
    timeoutMs: number,
): Promise<{ jwks: JwksDocument; maxAgeSeconds: number }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response: Response;
    try {
        response = await fetch(url, { signal: controller.signal });
    } catch (err) {
        if ((err as Error)?.name === "AbortError") {
            throw new Error(`JWKS fetch for ${url} timed out after ${timeoutMs}ms`);
        }
        throw err;
    } finally {
        clearTimeout(timer);
    }
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

async function readCache(cache: DcaJwksCache, url: string): Promise<DcaJwksCacheEntry | undefined> {
    try {
        const entry = await cache.get(url);
        return entry ?? undefined;
    } catch (err) {
        console.warn(`JWKS cache read failed for ${url}: ${(err as Error).message}`);
        return undefined;
    }
}

async function writeCache(
    cache: DcaJwksCache,
    url: string,
    entry: DcaJwksCacheEntry,
): Promise<void> {
    try {
        await cache.set(url, entry);
    } catch (err) {
        console.warn(`JWKS cache write failed for ${url}: ${(err as Error).message}`);
    }
}

/**
 * Fetch, then write to cache. On fetch failure, fall back to a stale cached
 * copy if it exists and is within the stale window.
 */
async function refreshAndCache(
    url: string,
    cache: DcaJwksCache,
    staleWindowSeconds: number,
    fetchTimeoutMs: number,
    previouslyCached: DcaJwksCacheEntry | undefined,
): Promise<JwksDocument> {
    const now = Date.now();
    try {
        const { jwks, maxAgeSeconds } = await doFetchJwks(url, fetchTimeoutMs);
        const freshUntil = now + maxAgeSeconds * 1000;
        const staleUntil = freshUntil + staleWindowSeconds * 1000;
        await writeCache(cache, url, { jwks, freshUntil, staleUntil });
        return jwks;
    } catch (err) {
        if (previouslyCached && previouslyCached.staleUntil > now) {
            console.warn(
                `JWKS fetch failed for ${url}; serving stale cached copy (fresh until ${new Date(previouslyCached.freshUntil).toISOString()}, stale until ${new Date(previouslyCached.staleUntil).toISOString()}). Error: ${(err as Error).message}`,
            );
            return previouslyCached.jwks;
        }
        throw new Error(
            `JWKS fetch failed for ${url} and no cached copy is available: ${(err as Error).message}`,
        );
    }
}

/**
 * Fetch a JWKS document, honoring the cache. Returns the cached copy when
 * still fresh. When stale, attempts a refresh; on failure, falls back to
 * the stale cached copy if it's within the configured stale window.
 */
export async function fetchJwks(url: string, opts?: DcaJwksOptions): Promise<JwksDocument> {
    const { cache, staleWindowSeconds, fetchTimeoutMs } = resolveOptions(opts);
    const now = Date.now();

    const cached = await readCache(cache, url);
    if (cached && cached.freshUntil > now) {
        return cached.jwks;
    }

    return refreshAndCache(url, cache, staleWindowSeconds, fetchTimeoutMs, cached);
}

/**
 * Force a re-fetch, bypassing the freshness check. Still honors the stale
 * fallback — a refresh failure with a valid stale entry returns that entry.
 * Useful when a "key not found" error from the issuer suggests a rotation
 * happened after the last cache fetch.
 */
export async function refreshJwks(url: string, opts?: DcaJwksOptions): Promise<JwksDocument> {
    const { cache, staleWindowSeconds, fetchTimeoutMs } = resolveOptions(opts);

    const previouslyCached = await readCache(cache, url);
    return refreshAndCache(url, cache, staleWindowSeconds, fetchTimeoutMs, previouslyCached);
}

/**
 * Fetch (or reuse cached) JWKS and return the active keys, imported as
 * CryptoKey instances.
 */
export async function getActiveIssuerKeys(
    url: string,
    opts?: DcaJwksOptions,
): Promise<ResolvedIssuerKey[]> {
    const jwks = await fetchJwks(url, opts);
    const active = selectActiveKeys(jwks);
    if (active.length === 0) {
        throw new Error(`JWKS at ${url} contains no usable active keys`);
    }
    return Promise.all(active.map(importJwkToCryptoKey));
}

/**
 * Resolve a publisher signing key from a JWKS by kid. Fetches (or reuses
 * cached) the JWKS; if the requested kid is not in the active set, a force
 * refresh is attempted once before failing — this handles the case where
 * the publisher rotated after the last fetch.
 *
 * Pass `kid === undefined` to require that the JWKS contains exactly one
 * active key (convenience for JWTs without a `kid` header).
 */
export async function resolvePublisherKey(
    url: string,
    kid: string | undefined,
    opts?: DcaJwksOptions,
): Promise<ResolvedPublisherKey> {
    const pick = (jwks: JwksDocument): Jwk | undefined => {
        const active = selectActivePublisherKeys(jwks);
        if (active.length === 0) return undefined;
        if (kid === undefined) {
            return active.length === 1 ? active[0] : undefined;
        }
        return active.find((k) => k.kid === kid);
    };

    let jwks = await fetchJwks(url, opts);
    let match = pick(jwks);
    if (!match) {
        jwks = await refreshJwks(url, opts);
        match = pick(jwks);
    }
    if (!match) {
        if (kid === undefined) {
            throw new Error(
                `JWKS at ${url}: expected exactly one active signing key but found ${selectActivePublisherKeys(jwks).length}`,
            );
        }
        throw new Error(`JWKS at ${url}: no active signing key with kid="${kid}"`);
    }
    return importPublisherJwk(match);
}

/**
 * Test hook — clear the default in-memory cache (or a single url).
 * Does nothing to user-supplied {@link DcaJwksCache} instances; those own
 * their lifetime.
 */
export function clearJwksCache(url?: string): void {
    if (url) {
        defaultCache.delete(url);
    } else {
        defaultCache.clear();
    }
}
