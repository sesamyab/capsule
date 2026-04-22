/**
 * DCA JWKS tests — issuer public keys resolved via a JWKS URL.
 *
 * These tests stub globalThis.fetch so JWKS documents can be served
 * deterministically, without network I/O.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { createDcaPublisher } from "../dca-publisher";
import { createDcaIssuer } from "../dca-issuer";
import {
    clearJwksCache,
    fetchJwks,
    refreshJwks,
    selectActiveKeys,
    type DcaJwksCache,
    type DcaJwksCacheEntry,
    type Jwk,
    type JwksDocument,
} from "../dca-jwks";
import {
    generateEcdhP256KeyPair,
    generateEcdsaP256KeyPair,
    exportP256KeyPairPem,
    exportEcdhP256PublicKeyAsJwk,
    generateAesKeyBytes,
    fromBase64Url,
    encodeUtf8,
    decodeUtf8,
} from "../web-crypto";
import { decryptContent } from "../encryption";

interface IssuerJwkBundle {
    kid: string;
    privateKeyPem: string;
    jwk: Jwk;
}

async function makeIssuerJwkBundle(kid: string, extras?: Partial<Jwk>): Promise<IssuerJwkBundle> {
    const pair = await generateEcdhP256KeyPair();
    const { privateKeyPem } = await exportP256KeyPairPem(pair.privateKey, pair.publicKey);
    const jwk = await exportEcdhP256PublicKeyAsJwk(pair.publicKey);
    return {
        kid,
        privateKeyPem,
        jwk: { ...jwk, kid, use: "enc", ...extras } as Jwk,
    };
}

function stubJwksFetch(
    url: string,
    jwks: JwksDocument | (() => JwksDocument | Promise<JwksDocument>),
    init?: { cacheControl?: string; status?: number },
): void {
    globalThis.fetch = vi.fn(async (input: string | URL) => {
        const requested = typeof input === "string" ? input : input.toString();
        if (requested !== url) {
            throw new Error(`Unexpected fetch(${requested}) — test only stubs ${url}`);
        }
        const body = typeof jwks === "function" ? await jwks() : jwks;
        return new Response(JSON.stringify(body), {
            status: init?.status ?? 200,
            headers: init?.cacheControl
                ? { "Cache-Control": init.cacheControl, "Content-Type": "application/json" }
                : { "Content-Type": "application/json" },
        }) as unknown as Response;
    }) as typeof globalThis.fetch;
}

function stubJwksFetchFailure(url: string, error = "network down"): void {
    globalThis.fetch = vi.fn(async (input: string | URL) => {
        const requested = typeof input === "string" ? input : input.toString();
        if (requested !== url) {
            throw new Error(`Unexpected fetch(${requested})`);
        }
        throw new Error(error);
    }) as typeof globalThis.fetch;
}

const realFetch = globalThis.fetch;

beforeEach(() => {
    clearJwksCache();
});

afterEach(() => {
    globalThis.fetch = realFetch;
    vi.restoreAllMocks();
});

// ============================================================================
// selectActiveKeys — key filtering rules
// ============================================================================

describe("selectActiveKeys", () => {
    it("includes keys with use=enc", async () => {
        const b = await makeIssuerJwkBundle("k1", { use: "enc" });
        expect(selectActiveKeys({ keys: [b.jwk] })).toHaveLength(1);
    });

    it("includes keys with no use claim", async () => {
        const b = await makeIssuerJwkBundle("k1");
        const noUse = { ...b.jwk };
        delete noUse.use;
        expect(selectActiveKeys({ keys: [noUse] })).toHaveLength(1);
    });

    it("excludes keys with use=sig", async () => {
        const b = await makeIssuerJwkBundle("k1", { use: "sig" });
        expect(selectActiveKeys({ keys: [b.jwk] })).toHaveLength(0);
    });

    it("excludes keys flagged status=retired", async () => {
        const b = await makeIssuerJwkBundle("k1", { status: "retired" });
        expect(selectActiveKeys({ keys: [b.jwk] })).toHaveLength(0);
    });

    it("excludes keys without a kid", async () => {
        const b = await makeIssuerJwkBundle("k1");
        const noKid = { ...b.jwk };
        delete noKid.kid;
        expect(selectActiveKeys({ keys: [noKid] })).toHaveLength(0);
    });

    it("excludes unsupported key types", () => {
        const result = selectActiveKeys({
            keys: [{ kty: "OKP", crv: "Ed25519", kid: "x", x: "aaaa" } as Jwk],
        });
        expect(result).toHaveLength(0);
    });
});

// ============================================================================
// Publisher render with JWKS
// ============================================================================

describe("Publisher render with jwksUri", () => {
    async function setupPublisherKeys() {
        const signingPair = await generateEcdsaP256KeyPair();
        const signingPems = await exportP256KeyPairPem(signingPair.privateKey, signingPair.publicKey);
        const rotationSecret = generateAesKeyBytes();
        return { signingPems, rotationSecret };
    }

    it("with 1 active key, produces 1 entry per contentName (same behavior as PEM)", async () => {
        const { signingPems, rotationSecret } = await setupPublisherKeys();
        const issuerKey = await makeIssuerJwkBundle("k-2026-04");

        const jwksUri = "https://issuer.test/.well-known/jwks.json";
        stubJwksFetch(jwksUri, { keys: [issuerKey.jwk] });

        const publisher = createDcaPublisher({
            domain: "example.com",
            signingKeyPem: signingPems.privateKeyPem,
            rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "a-1",
            contentItems: [{ contentName: "bodytext", content: "<p>One key</p>" }],
            issuers: [
                {
                    issuerName: "sesamy",
                    jwksUri,
                    unlockUrl: "https://issuer.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const entry = result.manifest.issuers["sesamy"];
        expect(entry.keys).toHaveLength(1);
        expect(entry.keys[0].kid).toBe("k-2026-04");
        expect(entry.keyId).toBeUndefined();
    });

    it("with 2 active keys, produces 2 wrapped entries per contentName; each is unwrappable by its matching private key", async () => {
        const { signingPems, rotationSecret } = await setupPublisherKeys();
        const keyOld = await makeIssuerJwkBundle("k-old");
        const keyNew = await makeIssuerJwkBundle("k-new");

        const jwksUri = "https://issuer.test/.well-known/jwks.json";
        stubJwksFetch(jwksUri, { keys: [keyOld.jwk, keyNew.jwk] });

        const publisher = createDcaPublisher({
            domain: "rot.example.com",
            signingKeyPem: signingPems.privateKeyPem,
            rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "a-2",
            contentItems: [{ contentName: "bodytext", content: "<p>Two keys</p>" }],
            issuers: [
                {
                    issuerName: "sesamy",
                    jwksUri,
                    unlockUrl: "https://issuer.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const entry = result.manifest.issuers["sesamy"];
        expect(entry.keys).toHaveLength(2);
        const kids = entry.keys.map(k => k.kid);
        expect(kids).toEqual(expect.arrayContaining(["k-old", "k-new"]));

        // Each private key must be able to unwrap its matching entry.
        for (const bundle of [keyOld, keyNew]) {
            const issuer = createDcaIssuer({
                issuerName: "sesamy",
                privateKeyPem: bundle.privateKeyPem,
                keyId: bundle.kid,
                trustedPublisherKeys: {
                    "rot.example.com": signingPems.publicKeyPem,
                },
            });

            const response = await issuer.unlock(
                {
                    resourceJWT: result.manifest.resourceJWT,
                    keys: entry.keys,
                },
                { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
            );

            const keyEntry = response.keys[0];
            expect(keyEntry.contentKey).toBeDefined();

            const contentKeyBytes = fromBase64Url(keyEntry.contentKey!);
            const c = result.manifest.content["bodytext"];
            const decrypted = await decryptContent(
                fromBase64Url(c.ciphertext),
                contentKeyBytes,
                fromBase64Url(c.iv),
                encodeUtf8(c.aad),
            );
            expect(decodeUtf8(decrypted)).toBe("<p>Two keys</p>");
        }
    });

    it("skips keys flagged status=retired", async () => {
        const { signingPems, rotationSecret } = await setupPublisherKeys();
        const keyActive = await makeIssuerJwkBundle("k-active");
        const keyRetired = await makeIssuerJwkBundle("k-retired", { status: "retired" });

        const jwksUri = "https://issuer.test/.well-known/jwks.json";
        stubJwksFetch(jwksUri, { keys: [keyActive.jwk, keyRetired.jwk] });

        const publisher = createDcaPublisher({
            domain: "ret.example.com",
            signingKeyPem: signingPems.privateKeyPem,
            rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "a-3",
            contentItems: [{ contentName: "bodytext", content: "<p>Retired excluded</p>" }],
            issuers: [
                {
                    issuerName: "sesamy",
                    jwksUri,
                    unlockUrl: "https://issuer.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const entry = result.manifest.issuers["sesamy"];
        expect(entry.keys).toHaveLength(1);
        expect(entry.keys[0].kid).toBe("k-active");
    });

    it("throws with the URL in the message when JWKS fetch fails and no cache is available", async () => {
        const { signingPems, rotationSecret } = await setupPublisherKeys();
        const jwksUri = "https://issuer.test/.well-known/jwks.json";
        stubJwksFetchFailure(jwksUri, "DNS failure");

        const publisher = createDcaPublisher({
            domain: "fail.example.com",
            signingKeyPem: signingPems.privateKeyPem,
            rotationSecret,
        });

        await expect(
            publisher.render({
                resourceId: "a-4",
                contentItems: [{ contentName: "bodytext", content: "x" }],
                issuers: [
                    {
                        issuerName: "sesamy",
                        jwksUri,
                        unlockUrl: "https://issuer.test/unlock",
                        contentNames: ["bodytext"],
                    },
                ],
            }),
        ).rejects.toThrow(jwksUri);
    });

    it("uses cached copy and warns when JWKS fetch fails after a prior successful fetch", async () => {
        const { signingPems, rotationSecret } = await setupPublisherKeys();
        const key = await makeIssuerJwkBundle("k1");
        const jwksUri = "https://issuer.test/.well-known/jwks.json";

        // 1) Populate the cache with a successful fetch (max-age=0 so it expires immediately).
        stubJwksFetch(jwksUri, { keys: [key.jwk] }, { cacheControl: "max-age=0" });

        const publisher = createDcaPublisher({
            domain: "cache.example.com",
            signingKeyPem: signingPems.privateKeyPem,
            rotationSecret,
        });

        const first = await publisher.render({
            resourceId: "a-5",
            contentItems: [{ contentName: "bodytext", content: "<p>primed</p>" }],
            issuers: [
                {
                    issuerName: "sesamy",
                    jwksUri,
                    unlockUrl: "https://issuer.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });
        expect(first.manifest.issuers["sesamy"].keys).toHaveLength(1);

        // 2) Break the network; next render should reuse the stale cache and warn.
        stubJwksFetchFailure(jwksUri, "upstream 503");
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

        const second = await publisher.render({
            resourceId: "a-5b",
            contentItems: [{ contentName: "bodytext", content: "<p>cached</p>" }],
            issuers: [
                {
                    issuerName: "sesamy",
                    jwksUri,
                    unlockUrl: "https://issuer.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        expect(second.manifest.issuers["sesamy"].keys).toHaveLength(1);
        expect(warn).toHaveBeenCalledTimes(1);
        expect(warn.mock.calls[0][0]).toContain(jwksUri);
    });

    it("throws when both publicKeyPem and jwksUri are set", async () => {
        const { signingPems, rotationSecret } = await setupPublisherKeys();
        const pair = await generateEcdhP256KeyPair();
        const { publicKeyPem } = await exportP256KeyPairPem(pair.privateKey, pair.publicKey);

        const publisher = createDcaPublisher({
            domain: "both.example.com",
            signingKeyPem: signingPems.privateKeyPem,
            rotationSecret,
        });

        await expect(
            publisher.render({
                resourceId: "a-6",
                contentItems: [{ contentName: "bodytext", content: "x" }],
                issuers: [
                    {
                        issuerName: "sesamy",
                        publicKeyPem,
                        jwksUri: "https://issuer.test/.well-known/jwks.json",
                        keyId: "k",
                        unlockUrl: "https://issuer.test/unlock",
                        contentNames: ["bodytext"],
                    },
                ],
            }),
        ).rejects.toThrow(/mutually exclusive/);
    });

    it("throws when neither publicKeyPem nor jwksUri is set", async () => {
        const { signingPems, rotationSecret } = await setupPublisherKeys();

        const publisher = createDcaPublisher({
            domain: "none.example.com",
            signingKeyPem: signingPems.privateKeyPem,
            rotationSecret,
        });

        await expect(
            publisher.render({
                resourceId: "a-7",
                contentItems: [{ contentName: "bodytext", content: "x" }],
                issuers: [
                    {
                        issuerName: "sesamy",
                        unlockUrl: "https://issuer.test/unlock",
                        contentNames: ["bodytext"],
                    },
                ],
            }),
        ).rejects.toThrow(/publicKeyPem or jwksUri/);
    });
});

// ============================================================================
// refreshJwks
// ============================================================================

describe("refreshJwks", () => {
    it("forces a re-fetch, bypassing the cache", async () => {
        const k1 = await makeIssuerJwkBundle("k1");
        const k2 = await makeIssuerJwkBundle("k2");

        const jwksUri = "https://issuer.test/.well-known/jwks.json";

        let call = 0;
        globalThis.fetch = vi.fn(async () => {
            call += 1;
            const body: JwksDocument = call === 1 ? { keys: [k1.jwk] } : { keys: [k2.jwk] };
            return new Response(JSON.stringify(body), {
                status: 200,
                headers: { "Cache-Control": "max-age=3600", "Content-Type": "application/json" },
            }) as unknown as Response;
        }) as typeof globalThis.fetch;

        const firstBody = await refreshJwks(jwksUri);
        expect(firstBody.keys[0].kid).toBe("k1");

        const secondBody = await refreshJwks(jwksUri);
        expect(secondBody.keys[0].kid).toBe("k2");
        expect(call).toBe(2);
    });
});

// ============================================================================
// Cache-Control freshness
// ============================================================================

describe("Cache-Control freshness", () => {
    function createCountingCache(): DcaJwksCache & { map: Map<string, DcaJwksCacheEntry>; gets: number; sets: number; deletes: number } {
        const map = new Map<string, DcaJwksCacheEntry>();
        const cache = {
            map,
            gets: 0,
            sets: 0,
            deletes: 0,
            get(url: string) { cache.gets += 1; return map.get(url); },
            set(url: string, entry: DcaJwksCacheEntry) { cache.sets += 1; map.set(url, entry); },
            delete(url: string) { cache.deletes += 1; map.delete(url); },
        };
        return cache;
    }

    it("honors Cache-Control max-age — fresh entries avoid network", async () => {
        const k = await makeIssuerJwkBundle("k");
        const jwksUri = "https://issuer.test/.well-known/jwks.json";

        let call = 0;
        globalThis.fetch = vi.fn(async () => {
            call += 1;
            return new Response(JSON.stringify({ keys: [k.jwk] }), {
                status: 200,
                headers: { "Cache-Control": "max-age=3600", "Content-Type": "application/json" },
            }) as unknown as Response;
        }) as typeof globalThis.fetch;

        const cache = createCountingCache();

        await fetchJwks(jwksUri, { cache });
        await fetchJwks(jwksUri, { cache });
        await fetchJwks(jwksUri, { cache });

        // Single network call — subsequent fetches hit the cache.
        expect(call).toBe(1);
        expect(cache.sets).toBe(1);
        expect(cache.gets).toBe(3);
    });

    it("defaults to 1h freshness when no Cache-Control header is present", async () => {
        const k = await makeIssuerJwkBundle("k");
        const jwksUri = "https://issuer.test/.well-known/jwks.json";

        stubJwksFetch(jwksUri, { keys: [k.jwk] }); // no cache-control

        const cache = createCountingCache();
        const before = Date.now();
        await fetchJwks(jwksUri, { cache });
        const entry = cache.map.get(jwksUri)!;

        // freshUntil ≈ now + 3600s
        const minutesFresh = (entry.freshUntil - before) / 1000 / 60;
        expect(minutesFresh).toBeGreaterThan(55);
        expect(minutesFresh).toBeLessThanOrEqual(60);
    });
});

// ============================================================================
// Pluggable cache backend
// ============================================================================

describe("Pluggable DcaJwksCache", () => {
    it("routes get/set through the user-supplied cache", async () => {
        const k = await makeIssuerJwkBundle("k");
        const jwksUri = "https://issuer.test/.well-known/jwks.json";
        stubJwksFetch(jwksUri, { keys: [k.jwk] }, { cacheControl: "max-age=600" });

        const map = new Map<string, DcaJwksCacheEntry>();
        const gets: string[] = [];
        const sets: string[] = [];
        const cache: DcaJwksCache = {
            get(url) { gets.push(url); return map.get(url); },
            set(url, entry) { sets.push(url); map.set(url, entry); },
        };

        await fetchJwks(jwksUri, { cache });

        expect(sets).toEqual([jwksUri]);
        const entry = map.get(jwksUri)!;
        expect(entry.jwks.keys).toHaveLength(1);
        expect(entry.freshUntil).toBeGreaterThan(Date.now());
        expect(entry.staleUntil).toBeGreaterThan(entry.freshUntil);

        // Second call should short-circuit on the cache get.
        await fetchJwks(jwksUri, { cache });
        expect(gets.length).toBeGreaterThanOrEqual(2);
    });

    it("defaults the stale window to 30 days", async () => {
        const k = await makeIssuerJwkBundle("k");
        const jwksUri = "https://issuer.test/.well-known/jwks.json";
        stubJwksFetch(jwksUri, { keys: [k.jwk] }, { cacheControl: "max-age=3600" });

        const map = new Map<string, DcaJwksCacheEntry>();
        const cache: DcaJwksCache = {
            get(url) { return map.get(url); },
            set(url, entry) { map.set(url, entry); },
        };

        await fetchJwks(jwksUri, { cache });

        const entry = map.get(jwksUri)!;
        const staleAfterFresh = entry.staleUntil - entry.freshUntil;
        const thirtyDaysMs = 30 * 24 * 3600 * 1000;
        // Allow a tiny fudge factor for measurement jitter.
        expect(staleAfterFresh).toBeGreaterThanOrEqual(thirtyDaysMs - 10);
        expect(staleAfterFresh).toBeLessThanOrEqual(thirtyDaysMs + 10);
    });

    it("serves stale cache on fetch failure within the stale window", async () => {
        const k = await makeIssuerJwkBundle("k");
        const jwksUri = "https://issuer.test/.well-known/jwks.json";

        // Pre-populate cache as if written 1 hour ago with max-age=60
        // (so freshUntil is in the past but staleUntil is far in the future).
        const now = Date.now();
        const map = new Map<string, DcaJwksCacheEntry>();
        map.set(jwksUri, {
            jwks: { keys: [k.jwk] },
            freshUntil: now - 60 * 1000,
            staleUntil: now + 30 * 24 * 3600 * 1000,
        });

        stubJwksFetchFailure(jwksUri);
        const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

        const cache: DcaJwksCache = {
            get(url) { return map.get(url); },
            set(url, entry) { map.set(url, entry); },
        };

        const body = await fetchJwks(jwksUri, { cache });
        expect(body.keys).toHaveLength(1);
        expect(warn).toHaveBeenCalledOnce();
        expect(warn.mock.calls[0][0]).toMatch(/stale cached copy/);
    });

    it("throws when fetch fails and the cache entry is past the stale window", async () => {
        const k = await makeIssuerJwkBundle("k");
        const jwksUri = "https://issuer.test/.well-known/jwks.json";

        const now = Date.now();
        const map = new Map<string, DcaJwksCacheEntry>();
        map.set(jwksUri, {
            jwks: { keys: [k.jwk] },
            freshUntil: now - 40 * 24 * 3600 * 1000, // 40 days ago
            staleUntil: now - 10 * 24 * 3600 * 1000, // staleness expired 10 days ago
        });

        stubJwksFetchFailure(jwksUri);

        const cache: DcaJwksCache = {
            get(url) { return map.get(url); },
            set(url, entry) { map.set(url, entry); },
        };

        await expect(fetchJwks(jwksUri, { cache })).rejects.toThrow(/no cached copy is available/);
    });

    it("accepts a custom staleWindowSeconds", async () => {
        const k = await makeIssuerJwkBundle("k");
        const jwksUri = "https://issuer.test/.well-known/jwks.json";
        stubJwksFetch(jwksUri, { keys: [k.jwk] }, { cacheControl: "max-age=60" });

        const map = new Map<string, DcaJwksCacheEntry>();
        const cache: DcaJwksCache = {
            get(url) { return map.get(url); },
            set(url, entry) { map.set(url, entry); },
        };

        await fetchJwks(jwksUri, { cache, staleWindowSeconds: 120 });

        const entry = map.get(jwksUri)!;
        const staleAfterFresh = entry.staleUntil - entry.freshUntil;
        expect(staleAfterFresh).toBeGreaterThanOrEqual(120 * 1000 - 10);
        expect(staleAfterFresh).toBeLessThanOrEqual(120 * 1000 + 10);
    });

    it("publisher config threads jwksCache and jwksStaleWindowSeconds to fetchJwks", async () => {
        const signingPair = await generateEcdsaP256KeyPair();
        const signingPems = await exportP256KeyPairPem(signingPair.privateKey, signingPair.publicKey);
        const rotationSecret = generateAesKeyBytes();

        const k = await makeIssuerJwkBundle("k");
        const jwksUri = "https://issuer.test/.well-known/jwks.json";
        stubJwksFetch(jwksUri, { keys: [k.jwk] }, { cacheControl: "max-age=300" });

        const map = new Map<string, DcaJwksCacheEntry>();
        const cache: DcaJwksCache = {
            get(url) { return map.get(url); },
            set(url, entry) { map.set(url, entry); },
        };

        const publisher = createDcaPublisher({
            domain: "cfg.example.com",
            signingKeyPem: signingPems.privateKeyPem,
            rotationSecret,
            jwksCache: cache,
            jwksStaleWindowSeconds: 7 * 24 * 3600, // 7 days
        });

        await publisher.render({
            resourceId: "a",
            contentItems: [{ contentName: "bodytext", content: "x" }],
            issuers: [
                {
                    issuerName: "sesamy",
                    jwksUri,
                    unlockUrl: "https://issuer.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const entry = map.get(jwksUri)!;
        expect(entry).toBeDefined();
        const staleAfterFresh = entry.staleUntil - entry.freshUntil;
        expect(staleAfterFresh).toBeGreaterThanOrEqual(7 * 24 * 3600 * 1000 - 10);
        expect(staleAfterFresh).toBeLessThanOrEqual(7 * 24 * 3600 * 1000 + 10);
    });
});
