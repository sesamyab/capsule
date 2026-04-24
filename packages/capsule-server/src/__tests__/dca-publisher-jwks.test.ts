/**
 * DCA publisher-JWKS tests — issuers resolve publisher signing keys via JWKS.
 *
 * These tests stub globalThis.fetch so JWKS documents can be served
 * deterministically, without network I/O.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { createDcaPublisher } from "../dca-publisher";
import { createDcaIssuer } from "../dca-issuer";
import {
    buildPublisherJwk,
    buildPublisherJwksDocument,
} from "../dca-publisher-jwks";
import {
    clearJwksCache,
    selectActivePublisherKeys,
    resolvePublisherKey,
    type JwksDocument,
} from "../dca-jwks";
import {
    generateEcdhP256KeyPair,
    generateEcdsaP256KeyPair,
    exportP256KeyPairPem,
    generateAesKeyBytes,
    toBase64,
} from "../web-crypto";
import { decodeJwtHeader, decodeJwtPayload } from "../dca-jwt";

const PUBLISHER_DOMAIN = "news.example.com";
const PUBLISHER_JWKS_URL = "https://news.example.com/.well-known/dca-publishers.json";
const ISSUER_UNLOCK_URL = "https://issuer.example.com/unlock";

interface PublisherBundle {
    kid: string;
    privateKeyPem: string;
    publicKeyPem: string;
}

async function makePublisherBundle(kid: string): Promise<PublisherBundle> {
    const pair = await generateEcdsaP256KeyPair();
    const { privateKeyPem, publicKeyPem } = await exportP256KeyPairPem(
        pair.privateKey,
        pair.publicKey,
    );
    return { kid, privateKeyPem, publicKeyPem };
}

interface IssuerBundle {
    keyId: string;
    privateKeyPem: string;
    publicKeyPem: string;
}

async function makeIssuerBundle(keyId: string): Promise<IssuerBundle> {
    const pair = await generateEcdhP256KeyPair();
    const { privateKeyPem, publicKeyPem } = await exportP256KeyPairPem(
        pair.privateKey,
        pair.publicKey,
    );
    return { keyId, privateKeyPem, publicKeyPem };
}

function stubJwksFetch(
    url: string,
    jwks: JwksDocument | (() => JwksDocument | Promise<JwksDocument>),
    init?: { cacheControl?: string; status?: number },
): { calls: () => number } {
    let calls = 0;
    globalThis.fetch = vi.fn(async (input: string | URL) => {
        const requested = typeof input === "string" ? input : input.toString();
        if (requested !== url) {
            throw new Error(`Unexpected fetch(${requested}) — test only stubs ${url}`);
        }
        calls += 1;
        const body = typeof jwks === "function" ? await jwks() : jwks;
        return new Response(JSON.stringify(body), {
            status: init?.status ?? 200,
            headers: init?.cacheControl
                ? { "Cache-Control": init.cacheControl, "Content-Type": "application/json" }
                : { "Content-Type": "application/json" },
        }) as unknown as Response;
    }) as typeof globalThis.fetch;
    return { calls: () => calls };
}

let origFetch: typeof globalThis.fetch;

beforeEach(() => {
    origFetch = globalThis.fetch;
    clearJwksCache();
});

afterEach(() => {
    globalThis.fetch = origFetch;
    vi.restoreAllMocks();
});

// ============================================================================
// buildPublisherJwk / buildPublisherJwksDocument
// ============================================================================

describe("buildPublisherJwk", () => {
    it("produces a JWK with ES256 metadata from a publisher public key", async () => {
        const pub = await makePublisherBundle("sig-1");
        const jwk = await buildPublisherJwk({
            publicKeyPem: pub.publicKeyPem,
            kid: pub.kid,
        });

        expect(jwk).toMatchObject({
            kty: "EC",
            crv: "P-256",
            use: "sig",
            alg: "ES256",
            kid: "sig-1",
        });
        expect(typeof jwk.x).toBe("string");
        expect(typeof jwk.y).toBe("string");
        // Must not contain private components
        expect((jwk as Record<string, unknown>).d).toBeUndefined();
    });

    it("honors status=retired", async () => {
        const pub = await makePublisherBundle("sig-old");
        const jwk = await buildPublisherJwk({
            publicKeyPem: pub.publicKeyPem,
            kid: pub.kid,
            status: "retired",
        });
        expect(jwk.status).toBe("retired");
    });

    it("rejects empty kid or PEM", async () => {
        const pub = await makePublisherBundle("sig-1");
        await expect(buildPublisherJwk({ publicKeyPem: "", kid: pub.kid })).rejects.toThrow();
        await expect(buildPublisherJwk({ publicKeyPem: pub.publicKeyPem, kid: "" })).rejects.toThrow();
    });
});

describe("buildPublisherJwksDocument", () => {
    it("assembles multiple JWKs into a standard JWKS document", async () => {
        const a = await makePublisherBundle("sig-a");
        const b = await makePublisherBundle("sig-b");
        const doc = await buildPublisherJwksDocument([
            { publicKeyPem: a.publicKeyPem, kid: a.kid },
            { publicKeyPem: b.publicKeyPem, kid: b.kid, status: "retired" },
        ]);

        expect(doc.keys).toHaveLength(2);
        expect(doc.keys[0].kid).toBe("sig-a");
        expect(doc.keys[1].kid).toBe("sig-b");
        expect(doc.keys[1].status).toBe("retired");
    });

    it("rejects empty input", async () => {
        await expect(buildPublisherJwksDocument([])).rejects.toThrow();
    });

    it("rejects duplicate kids", async () => {
        const a = await makePublisherBundle("sig-a");
        await expect(
            buildPublisherJwksDocument([
                { publicKeyPem: a.publicKeyPem, kid: "dup" },
                { publicKeyPem: a.publicKeyPem, kid: "dup" },
            ]),
        ).rejects.toThrow(/duplicate kid/i);
    });
});

// ============================================================================
// selectActivePublisherKeys
// ============================================================================

describe("selectActivePublisherKeys", () => {
    it("accepts sig-use EC P-256 keys", async () => {
        const a = await makePublisherBundle("sig-a");
        const doc = await buildPublisherJwksDocument([
            { publicKeyPem: a.publicKeyPem, kid: a.kid },
        ]);
        expect(selectActivePublisherKeys(doc)).toHaveLength(1);
    });

    it("excludes retired, enc-use, and non-EC keys", async () => {
        const a = await makePublisherBundle("sig-a");
        const base = await buildPublisherJwk({ publicKeyPem: a.publicKeyPem, kid: "active" });
        const retired = await buildPublisherJwk({
            publicKeyPem: a.publicKeyPem,
            kid: "retired",
            status: "retired",
        });
        const encUse = { ...base, kid: "enc-use", use: "enc" };
        const rsa = { kty: "RSA", kid: "rsa", n: "x", e: "AQAB", use: "sig" } as const;
        const active = selectActivePublisherKeys({
            keys: [base, retired, encUse, rsa],
        });
        expect(active.map((k) => k.kid)).toEqual(["active"]);
    });
});

// ============================================================================
// resolvePublisherKey
// ============================================================================

describe("resolvePublisherKey", () => {
    it("returns the key matching the requested kid", async () => {
        const a = await makePublisherBundle("sig-a");
        const b = await makePublisherBundle("sig-b");
        const doc = await buildPublisherJwksDocument([
            { publicKeyPem: a.publicKeyPem, kid: a.kid },
            { publicKeyPem: b.publicKeyPem, kid: b.kid },
        ]);
        stubJwksFetch(PUBLISHER_JWKS_URL, doc);

        const resolved = await resolvePublisherKey(PUBLISHER_JWKS_URL, "sig-b");
        expect(resolved.kid).toBe("sig-b");
    });

    it("force-refreshes on unknown kid before failing", async () => {
        const a = await makePublisherBundle("sig-a");
        const b = await makePublisherBundle("sig-b");
        let current: JwksDocument = await buildPublisherJwksDocument([
            { publicKeyPem: a.publicKeyPem, kid: a.kid },
        ]);
        const { calls } = stubJwksFetch(PUBLISHER_JWKS_URL, () => current, {
            cacheControl: "max-age=3600",
        });

        // First fetch populates cache.
        const first = await resolvePublisherKey(PUBLISHER_JWKS_URL, "sig-a");
        expect(first.kid).toBe("sig-a");
        expect(calls()).toBe(1);

        // Rotate: cache still has old doc, but upstream now has the new key.
        current = await buildPublisherJwksDocument([
            { publicKeyPem: a.publicKeyPem, kid: a.kid },
            { publicKeyPem: b.publicKeyPem, kid: b.kid },
        ]);

        const second = await resolvePublisherKey(PUBLISHER_JWKS_URL, "sig-b");
        expect(second.kid).toBe("sig-b");
        // One extra fetch: the force-refresh after the initial cache-miss-on-kid.
        expect(calls()).toBe(2);
    });

    it("throws when the kid is not in the JWKS even after refresh", async () => {
        const a = await makePublisherBundle("sig-a");
        const doc = await buildPublisherJwksDocument([
            { publicKeyPem: a.publicKeyPem, kid: a.kid },
        ]);
        stubJwksFetch(PUBLISHER_JWKS_URL, doc);
        await expect(
            resolvePublisherKey(PUBLISHER_JWKS_URL, "missing"),
        ).rejects.toThrow(/no active signing key with kid="missing"/);
    });
});

// ============================================================================
// End-to-end: publisher JWKS → issuer verify
// ============================================================================

async function renderAndUnlock(
    signingKeyId: string | undefined,
    trustedEntry: Record<string, unknown>,
    publisher: PublisherBundle,
    issuer: IssuerBundle,
    rotationSecret: string,
): Promise<{ verified: boolean }> {
    const pub = createDcaPublisher({
        domain: PUBLISHER_DOMAIN,
        signingKeyPem: publisher.privateKeyPem,
        rotationSecret,
        ...(signingKeyId ? { signingKeyId } : {}),
    });

    const rendered = await pub.render({
        resourceId: "article-1",
        contentItems: [{ contentName: "bodytext", content: "<p>secret</p>" }],
        issuers: [
            {
                issuerName: "sesamy",
                publicKeyPem: issuer.publicKeyPem,
                keyId: issuer.keyId,
                unlockUrl: ISSUER_UNLOCK_URL,
                contentNames: ["bodytext"],
            },
        ],
    });

    const iss = createDcaIssuer({
        issuerName: "sesamy",
        privateKeyPem: issuer.privateKeyPem,
        keyId: issuer.keyId,
        trustedPublisherKeys: {
            [PUBLISHER_DOMAIN]: trustedEntry as never,
        },
    });

    const res = await iss.unlock(
        {
            resourceJWT: rendered.manifest.resourceJWT,
            keys: rendered.manifest.issuers["sesamy"].keys,
        },
        { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
    );

    return { verified: res.keys.length === 1 && res.keys[0].contentName === "bodytext" };
}

describe("publisher JWKS end-to-end", () => {
    it("signed JWT includes kid when signingKeyId is set", async () => {
        const pub = await makePublisherBundle("sig-1");
        const issuer = await makeIssuerBundle("iss-1");
        const rotationSecret = toBase64(generateAesKeyBytes());

        const publisher = createDcaPublisher({
            domain: PUBLISHER_DOMAIN,
            signingKeyPem: pub.privateKeyPem,
            rotationSecret,
            signingKeyId: pub.kid,
        });
        const rendered = await publisher.render({
            resourceId: "a",
            contentItems: [{ contentName: "b", content: "x" }],
            issuers: [
                {
                    issuerName: "i",
                    publicKeyPem: issuer.publicKeyPem,
                    keyId: issuer.keyId,
                    unlockUrl: ISSUER_UNLOCK_URL,
                    contentNames: ["b"],
                },
            ],
        });

        const header = decodeJwtHeader(rendered.manifest.resourceJWT);
        expect(header).toEqual({ alg: "ES256", typ: "JWT", kid: "sig-1" });
        expect(decodeJwtPayload<{ iss: string }>(rendered.manifest.resourceJWT).iss).toBe(
            PUBLISHER_DOMAIN,
        );
    });

    it("omits kid from the header when signingKeyId is not configured", async () => {
        const pub = await makePublisherBundle("unused");
        const issuer = await makeIssuerBundle("iss-1");
        const rotationSecret = toBase64(generateAesKeyBytes());

        const publisher = createDcaPublisher({
            domain: PUBLISHER_DOMAIN,
            signingKeyPem: pub.privateKeyPem,
            rotationSecret,
        });
        const rendered = await publisher.render({
            resourceId: "a",
            contentItems: [{ contentName: "b", content: "x" }],
            issuers: [
                {
                    issuerName: "i",
                    publicKeyPem: issuer.publicKeyPem,
                    keyId: issuer.keyId,
                    unlockUrl: ISSUER_UNLOCK_URL,
                    contentNames: ["b"],
                },
            ],
        });

        const header = decodeJwtHeader(rendered.manifest.resourceJWT);
        expect(header.kid).toBeUndefined();
    });

    it("issuer verifies resourceJWT via publisher JWKS", async () => {
        const pub = await makePublisherBundle("sig-1");
        const issuer = await makeIssuerBundle("iss-1");
        const rotationSecret = toBase64(generateAesKeyBytes());

        const jwks = await buildPublisherJwksDocument([
            { publicKeyPem: pub.publicKeyPem, kid: pub.kid },
        ]);
        stubJwksFetch(PUBLISHER_JWKS_URL, jwks);

        const { verified } = await renderAndUnlock(
            pub.kid,
            { jwksUri: PUBLISHER_JWKS_URL },
            pub,
            issuer,
            rotationSecret,
        );
        expect(verified).toBe(true);
    });

    it("issuer picks the right key when the JWKS has two active keys", async () => {
        const oldKey = await makePublisherBundle("sig-old");
        const newKey = await makePublisherBundle("sig-new");
        const issuer = await makeIssuerBundle("iss-1");
        const rotationSecret = toBase64(generateAesKeyBytes());

        // JWKS has both — publisher signs with the new one.
        const jwks = await buildPublisherJwksDocument([
            { publicKeyPem: oldKey.publicKeyPem, kid: oldKey.kid },
            { publicKeyPem: newKey.publicKeyPem, kid: newKey.kid },
        ]);
        stubJwksFetch(PUBLISHER_JWKS_URL, jwks);

        const { verified } = await renderAndUnlock(
            newKey.kid,
            { jwksUri: PUBLISHER_JWKS_URL },
            newKey,
            issuer,
            rotationSecret,
        );
        expect(verified).toBe(true);
    });

    it("issuer force-refreshes JWKS on unknown kid (publisher rotated)", async () => {
        const oldKey = await makePublisherBundle("sig-old");
        const newKey = await makePublisherBundle("sig-new");
        const issuer = await makeIssuerBundle("iss-1");
        const rotationSecret = toBase64(generateAesKeyBytes());

        // Initial JWKS has only the old key; after rotation, only the new key.
        let current = await buildPublisherJwksDocument([
            { publicKeyPem: oldKey.publicKeyPem, kid: oldKey.kid },
        ]);
        const { calls } = stubJwksFetch(PUBLISHER_JWKS_URL, () => current, {
            cacheControl: "max-age=3600",
        });

        // Warm the cache.
        await resolvePublisherKey(PUBLISHER_JWKS_URL, oldKey.kid);
        expect(calls()).toBe(1);

        // Publisher rotates; JWKS updated upstream but our cache is stale.
        current = await buildPublisherJwksDocument([
            { publicKeyPem: newKey.publicKeyPem, kid: newKey.kid },
        ]);

        // A render signed with the NEW key triggers an unknown-kid miss on first
        // lookup, force-refresh, and successful verify on the retry.
        const { verified } = await renderAndUnlock(
            newKey.kid,
            { jwksUri: PUBLISHER_JWKS_URL },
            newKey,
            issuer,
            rotationSecret,
        );
        expect(verified).toBe(true);
        expect(calls()).toBeGreaterThanOrEqual(2);
    });

    it("issuer rejects when JWKS-resolved key fails to verify the signature", async () => {
        const signerA = await makePublisherBundle("sig-1");
        const signerB = await makePublisherBundle("sig-1"); // same kid, different key
        const issuer = await makeIssuerBundle("iss-1");
        const rotationSecret = toBase64(generateAesKeyBytes());

        // JWKS advertises signerB's public key under kid=sig-1, but the publisher
        // actually signs with signerA's private key. Verification must fail.
        const jwks = await buildPublisherJwksDocument([
            { publicKeyPem: signerB.publicKeyPem, kid: "sig-1" },
        ]);
        stubJwksFetch(PUBLISHER_JWKS_URL, jwks);

        await expect(
            renderAndUnlock(
                "sig-1",
                { jwksUri: PUBLISHER_JWKS_URL },
                signerA,
                issuer,
                rotationSecret,
            ),
        ).rejects.toThrow(/signature verification failed/i);
    });

    it("still accepts pinned signingKeyPem (no regression)", async () => {
        const pub = await makePublisherBundle("pinned");
        const issuer = await makeIssuerBundle("iss-1");
        const rotationSecret = toBase64(generateAesKeyBytes());

        // No stubbed fetch — pinned PEM must not reach the network.
        globalThis.fetch = vi.fn(async () => {
            throw new Error("unexpected fetch — pinned PEM path should not fetch");
        }) as typeof globalThis.fetch;

        const { verified } = await renderAndUnlock(
            undefined,
            { signingKeyPem: pub.publicKeyPem },
            pub,
            issuer,
            rotationSecret,
        );
        expect(verified).toBe(true);
    });

    it("rejects trustedPublisherKeys entry with both signingKeyPem and jwksUri", async () => {
        const pub = await makePublisherBundle("sig-1");
        const issuer = await makeIssuerBundle("iss-1");

        expect(() =>
            createDcaIssuer({
                issuerName: "i",
                privateKeyPem: issuer.privateKeyPem,
                keyId: issuer.keyId,
                trustedPublisherKeys: {
                    [PUBLISHER_DOMAIN]: {
                        signingKeyPem: pub.publicKeyPem,
                        jwksUri: PUBLISHER_JWKS_URL,
                    } as never,
                },
            }),
        ).toThrow(/mutually exclusive/);
    });

    it("rejects trustedPublisherKeys entry with neither signingKeyPem nor jwksUri", async () => {
        const issuer = await makeIssuerBundle("iss-1");

        expect(() =>
            createDcaIssuer({
                issuerName: "i",
                privateKeyPem: issuer.privateKeyPem,
                keyId: issuer.keyId,
                trustedPublisherKeys: {
                    [PUBLISHER_DOMAIN]: {} as never,
                },
            }),
        ).toThrow(/must provide signingKeyPem or jwksUri/);
    });
});
