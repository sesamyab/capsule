/**
 * DCA End-to-End Tests
 *
 * Tests the full DCA chain: Publisher → Issuer → Client (decryption).
 * Covers all four implemented DCA changes:
 *   1. AAD in AES-GCM content encryption
 *   2. Issuer abstraction & ECDH P-256 sealing
 *   3. Multiple named content items per page
 *   4. ES256 JWT signing & SHA-256 integrity proofs
 */

import { describe, it, expect } from "vitest";
import { createDcaPublisher } from "../dca-publisher";
import { createDcaIssuer } from "../dca-issuer";
import {
    createJwt,
    verifyJwt,
    decodeJwtPayload,
    computeProofHash,
} from "../dca-jwt";
import {
    wrapEcdhP256,
    unwrapEcdhP256,
    importIssuerPublicKey,
    importIssuerPrivateKey,
} from "../dca-wrap";
import {
    formatTimeKid,
    getCurrentRotationVersions,
    deriveWrapKey,
    generateRenderId,
} from "../dca-rotation";
import {
    generateEcdhP256KeyPair,
    generateEcdsaP256KeyPair,
    exportP256KeyPairPem,
    aesGcmEncrypt,
    aesGcmDecrypt,
    generateAesKeyBytes,
    toBase64Url,
    fromBase64Url,
    encodeUtf8,
    decodeUtf8,
    sha256,
    type WebCryptoKey,
} from "../web-crypto";
import { encryptContent, decryptContent, generateContentKey } from "../encryption";

// ============================================================================
// Helpers
// ============================================================================

import type { DcaUnlockResponse, DcaUnlockedKey } from "../dca-types";

/** Look up a content encryption key by name from a flat response array. */
function findKey(response: DcaUnlockResponse, name: string): DcaUnlockedKey {
    const entry = response.keys.find(k => (k.contentName ?? "default") === name);
    if (!entry) throw new Error(`No key for "${name}" in response`);
    return entry;
}

/** Convert flat wrapKeys array to Record for tests that need kid-keyed access. */
function wrapKeysToRecord(entry: DcaUnlockedKey): Record<string, string> {
    return Object.fromEntries((entry.wrapKeys ?? []).map(wk => [wk.kid, wk.key]));
}

// ============================================================================
// Key generation helper — generates all keys for a test scenario
// ============================================================================

async function generateTestKeys() {
    // Publisher signing key (ES256)
    const signingPair = await generateEcdsaP256KeyPair();
    const signingPems = await exportP256KeyPairPem(signingPair.privateKey, signingPair.publicKey);

    // Issuer ECDH key (for sealing)
    const issuerEcdhPair = await generateEcdhP256KeyPair();
    const issuerEcdhPems = await exportP256KeyPairPem(issuerEcdhPair.privateKey, issuerEcdhPair.publicKey);

    // Rotation secret
    const rotationSecret = generateAesKeyBytes();

    return {
        signingPems,
        issuerEcdhPems,
        rotationSecret,
    };
}

// ============================================================================
// 1. AAD in AES-GCM
// ============================================================================

describe("AAD in AES-GCM", () => {
    it("encrypts and decrypts with AAD", async () => {
        const key = generateContentKey();
        const plaintext = "Hello, DCA with AAD!";
        const aad = encodeUtf8("example.com|article-1|bodytext|bodytext");

        const { encryptedContent, iv } = await encryptContent(plaintext, key, undefined, aad);
        const decrypted = await decryptContent(encryptedContent, key, iv, aad);

        expect(decodeUtf8(decrypted)).toBe(plaintext);
    });

    it("decryption fails with wrong AAD", async () => {
        const key = generateContentKey();
        const plaintext = "Secret content";
        const aad = encodeUtf8("example.com|article-1|bodytext|bodytext");
        const wrongAad = encodeUtf8("evil.com|article-1|bodytext|1");

        const { encryptedContent, iv } = await encryptContent(plaintext, key, undefined, aad);

        await expect(decryptContent(encryptedContent, key, iv, wrongAad)).rejects.toThrow();
    });

    it("decryption fails without AAD when AAD was used", async () => {
        const key = generateContentKey();
        const plaintext = "Secret content";
        const aad = encodeUtf8("example.com|article-1|bodytext|bodytext");

        const { encryptedContent, iv } = await encryptContent(plaintext, key, undefined, aad);

        // Decrypt WITHOUT AAD should fail
        await expect(decryptContent(encryptedContent, key, iv)).rejects.toThrow();
    });

    it("is backward compatible — works without AAD", async () => {
        const key = generateContentKey();
        const plaintext = "No AAD used";

        const { encryptedContent, iv } = await encryptContent(plaintext, key);
        const decrypted = await decryptContent(encryptedContent, key, iv);

        expect(decodeUtf8(decrypted)).toBe(plaintext);
    });

    it("low-level aesGcmEncrypt/Decrypt with AAD", async () => {
        const key = generateAesKeyBytes();
        const data = encodeUtf8("test data");
        const aad = encodeUtf8("authenticated context");

        const { encryptedContent, iv } = await aesGcmEncrypt(data, key, undefined, aad);
        const decrypted = await aesGcmDecrypt(encryptedContent, key, iv, aad);

        expect(decrypted).toEqual(data);
    });
});

// ============================================================================
// 2. ECDH P-256 sealing
// ============================================================================

describe("ECDH P-256 sealing", () => {
    it("seals and unseals key material", async () => {
        const keyPair = await generateEcdhP256KeyPair();
        const pems = await exportP256KeyPairPem(keyPair.privateKey, keyPair.publicKey);

        const { key: pubKey } = await importIssuerPublicKey(pems.publicKeyPem, "ECDH-P256");
        const { key: privKey } = await importIssuerPrivateKey(pems.privateKeyPem, "ECDH-P256");

        const originalKey = generateAesKeyBytes(); // 32 random bytes
        const sealed = await wrapEcdhP256(originalKey, pubKey);

        // Sealed blob should be a non-empty base64url string
        expect(sealed.length).toBeGreaterThan(0);
        expect(sealed).toMatch(/^[A-Za-z0-9_-]+$/);

        const unsealed = await unwrapEcdhP256(sealed, privKey);
        expect(unsealed).toEqual(originalKey);
    });

    it("different seals produce different ciphertexts (ephemeral keys)", async () => {
        const keyPair = await generateEcdhP256KeyPair();
        const pems = await exportP256KeyPairPem(keyPair.privateKey, keyPair.publicKey);
        const { key: pubKey } = await importIssuerPublicKey(pems.publicKeyPem, "ECDH-P256");

        const originalKey = generateAesKeyBytes();
        const sealed1 = await wrapEcdhP256(originalKey, pubKey);
        const sealed2 = await wrapEcdhP256(originalKey, pubKey);

        // Different ephemeral keys → different ciphertext
        expect(sealed1).not.toBe(sealed2);
    });

    it("auto-detects key algorithm from PEM", async () => {
        const keyPair = await generateEcdhP256KeyPair();
        const pems = await exportP256KeyPairPem(keyPair.privateKey, keyPair.publicKey);

        // Import without algorithm hint — should auto-detect ECDH-P256
        const { algorithm } = await importIssuerPublicKey(pems.publicKeyPem);
        expect(algorithm).toBe("ECDH-P256");
    });

    it("rejects truncated sealed blobs with a deterministic error", async () => {
        const keyPair = await generateEcdhP256KeyPair();
        const pems = await exportP256KeyPairPem(keyPair.privateKey, keyPair.publicKey);
        const { key: privKey } = await importIssuerPrivateKey(pems.privateKeyPem, "ECDH-P256");

        // Minimum valid blob is 65 (ephemeral pub) + 12 (IV) + 16 (GCM tag) = 93 bytes
        const tooShort = toBase64Url(new Uint8Array(92));
        await expect(unwrapEcdhP256(tooShort, privKey)).rejects.toThrow(
            /Invalid ECDH-P256 wrapped blob: expected at least 93 bytes, got 92/,
        );

        // Empty blob
        const empty = toBase64Url(new Uint8Array(0));
        await expect(unwrapEcdhP256(empty, privKey)).rejects.toThrow(
            /Invalid ECDH-P256 wrapped blob: expected at least 93 bytes, got 0/,
        );

        // Just below threshold (header only)
        const headerOnly = toBase64Url(new Uint8Array(65));
        await expect(unwrapEcdhP256(headerOnly, privKey)).rejects.toThrow(
            /Invalid ECDH-P256 wrapped blob: expected at least 93 bytes, got 65/,
        );
    });
});

// ============================================================================
// 3. ES256 JWT
// ============================================================================

describe("ES256 JWT", () => {
    it("creates and verifies a JWT", async () => {
        const keyPair = await generateEcdsaP256KeyPair();
        const pems = await exportP256KeyPairPem(keyPair.privateKey, keyPair.publicKey);

        const payload = { foo: "bar", num: 42 };
        const jwt = await createJwt(payload, pems.privateKeyPem);

        // JWT has 3 parts
        expect(jwt.split(".").length).toBe(3);

        // Verify and decode
        const decoded = await verifyJwt(jwt, pems.publicKeyPem);
        expect(decoded).toEqual(payload);
    });

    it("verification fails with wrong key", async () => {
        const keyPair1 = await generateEcdsaP256KeyPair();
        const keyPair2 = await generateEcdsaP256KeyPair();
        const pems1 = await exportP256KeyPairPem(keyPair1.privateKey, keyPair1.publicKey);
        const pems2 = await exportP256KeyPairPem(keyPair2.privateKey, keyPair2.publicKey);

        const jwt = await createJwt({ test: true }, pems1.privateKeyPem);
        await expect(verifyJwt(jwt, pems2.publicKeyPem)).rejects.toThrow("verification failed");
    });

    it("decodes JWT payload without verification", async () => {
        const keyPair = await generateEcdsaP256KeyPair();
        const pems = await exportP256KeyPairPem(keyPair.privateKey, keyPair.publicKey);

        const payload = { resourceId: "article-123" };
        const jwt = await createJwt(payload, pems.privateKeyPem);

        const decoded = decodeJwtPayload<typeof payload>(jwt);
        expect(decoded).toEqual(payload);
    });
});

// ============================================================================
// 4. SHA-256 integrity proofs
// ============================================================================

describe("SHA-256 integrity proofs", () => {
    it("computes deterministic proof hashes", async () => {
        const input = "dGVzdA"; // base64url of "test"
        const hash1 = await computeProofHash(input);
        const hash2 = await computeProofHash(input);
        expect(hash1).toBe(hash2);
    });

    it("different inputs produce different hashes", async () => {
        const hash1 = await computeProofHash("aGVsbG8");
        const hash2 = await computeProofHash("d29ybGQ");
        expect(hash1).not.toBe(hash2);
    });

    it("proof hash is base64url(SHA-256(UTF-8 bytes))", async () => {
        const input = "testblob";
        const hash = await computeProofHash(input);
        // Manual verification
        const expected = toBase64Url(await sha256(encodeUtf8(input)));
        expect(hash).toBe(expected);
    });
});

// ============================================================================
// 5. Time buckets
// ============================================================================

describe("Time buckets", () => {
    it("formats hourly buckets as YYMMDDTHH", () => {
        const date = new Date("2025-10-23T13:45:00Z");
        expect(formatTimeKid(date)).toBe("251023T13");
    });

    it("formats sub-hour buckets as YYMMDDTHHMM", () => {
        const date = new Date("2025-10-23T14:30:00Z");
        expect(formatTimeKid(date, true)).toBe("251023T1430");
    });

    it("returns current and next bucket", () => {
        const now = new Date("2025-10-23T13:45:00Z");
        const buckets = getCurrentRotationVersions(1, now);

        expect(buckets.current.kid).toBe("251023T13");
        expect(buckets.next.kid).toBe("251023T14");
    });

    it("derives content-specific period keys", async () => {
        const secret = generateAesKeyBytes();

        const key1 = await deriveWrapKey(secret, "bodytext", "251023T13");
        const key2 = await deriveWrapKey(secret, "sidebar", "251023T13");
        const key3 = await deriveWrapKey(secret, "bodytext", "251023T14");

        // Same content name + same time bucket → same key
        const key1b = await deriveWrapKey(secret, "bodytext", "251023T13");
        expect(key1).toEqual(key1b);

        // Different content name → different key
        expect(key1).not.toEqual(key2);

        // Different time bucket → different key
        expect(key1).not.toEqual(key3);
    });

    it("generates unique renderIds", () => {
        const id1 = generateRenderId();
        const id2 = generateRenderId();
        expect(id1).not.toBe(id2);
        expect(id1.length).toBeGreaterThanOrEqual(11); // ≥8 bytes → ≥11 base64url chars
    });
});

// ============================================================================
// 6. Full DCA Publisher → Issuer → Decrypt chain
// ============================================================================

describe("DCA end-to-end", () => {
    it("publishes, issues, and decrypts single content item", async () => {
        const keys = await generateTestKeys();

        // --- Publisher side ---
        const publisher = createDcaPublisher({
            domain: "example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "article-1",
            contentItems: [
                { contentName: "bodytext", content: "<p>Premium content</p>" },
            ],
            issuers: [
                {
                    issuerName: "test-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "key-1",
                    unlockUrl: "https://issuer.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
            resourceData: { section: "politics" },
        });

        // Verify DCA data structure
        expect(result.manifest.version).toBe("0.10");
        expect(result.manifest.content["bodytext"]).toBeDefined();
        expect(result.manifest.content["bodytext"].wrappedContentKey).toHaveLength(2); // current + next period
        expect(result.manifest.issuers["test-issuer"]).toBeDefined();
        expect(result.manifest.content["bodytext"].ciphertext).toBeDefined();

        // Verify HTML output
        expect(result.html.manifestScript).toContain('<script type="application/json" class="dca-manifest">');

        // --- Issuer side (contentKey mode) ---
        const issuer = createDcaIssuer({
            issuerName: "test-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "key-1",
            trustedPublisherKeys: {
                "example.com": keys.signingPems.publicKeyPem,
            },
        });

        const unlockResponse = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["test-issuer"].keys,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
        );

        expect(findKey(unlockResponse, "bodytext")).toBeDefined();
        expect(findKey(unlockResponse, "bodytext").contentKey).toBeDefined();

        // --- Client-side decryption ---
        const contentKeyBytes = fromBase64Url(findKey(unlockResponse, "bodytext").contentKey!);
        const contentEntry = result.manifest.content["bodytext"];
        const iv = fromBase64Url(contentEntry.iv);
        const aad = encodeUtf8(contentEntry.aad);
        const ciphertext = fromBase64Url(contentEntry.ciphertext);

        const decrypted = await decryptContent(ciphertext, contentKeyBytes, iv, aad);
        expect(decodeUtf8(decrypted)).toBe("<p>Premium content</p>");
    });

    it("publishes and decrypts multiple content items", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "multi.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "page-42",
            contentItems: [
                { contentName: "body", content: "Main article body" },
                { contentName: "sidebar", content: "Premium sidebar content" },
                { contentName: "data", content: '{"key":"value"}', contentType: "application/json" },
            ],
            issuers: [
                {
                    issuerName: "multi-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "mk-1",
                    unlockUrl: "https://multi.test/unlock",
                    contentNames: ["body", "sidebar", "data"],
                },
            ],
        });

        // Verify multiple content items
        expect(Object.keys(result.manifest.content)).toEqual(["body", "sidebar", "data"]);
        expect(result.manifest.content["data"].contentType).toBe("application/json");

        // Check that each content item has its own iv
        const bodyIv = result.manifest.content["body"].iv;
        const sidebarIv = result.manifest.content["sidebar"].iv;
        expect(bodyIv).not.toBe(sidebarIv);

        // Issuer unlock with contentKey mode
        const issuer = createDcaIssuer({
            issuerName: "multi-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "mk-1",
            trustedPublisherKeys: {
                "multi.example.com": keys.signingPems.publicKeyPem,
            },
        });

        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["multi-issuer"].keys,
            },
            { grantedContentNames: ["body", "sidebar", "data"], deliveryMode: "direct" },
        );

        // Decrypt each content item
        for (const [name, expectedContent] of [
            ["body", "Main article body"],
            ["sidebar", "Premium sidebar content"],
            ["data", '{"key":"value"}'],
        ]) {
            const contentKey = fromBase64Url(findKey(response, name).contentKey!);
            const entry = result.manifest.content[name];
            const decrypted = await decryptContent(
                fromBase64Url(entry.ciphertext),
                contentKey,
                fromBase64Url(entry.iv),
                encodeUtf8(entry.aad),
            );
            expect(decodeUtf8(decrypted)).toBe(expectedContent);
        }
    });

    it("supports wrapKey delivery mode", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "period.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "article-pk",
            contentItems: [{ contentName: "bodytext", content: "Period key content" }],
            issuers: [
                {
                    issuerName: "pk-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "pk-1",
                    unlockUrl: "https://pk.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const issuer = createDcaIssuer({
            issuerName: "pk-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "pk-1",
            trustedPublisherKeys: {
                "period.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Request wrapKeys instead of contentKey
        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["pk-issuer"].keys,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "wrapKey" },
        );

        expect(findKey(response, "bodytext").wrapKeys).toBeDefined();
        const wrapKeys = wrapKeysToRecord(findKey(response, "bodytext"));
        expect(Object.keys(wrapKeys).length).toBe(2); // current + next

        // Unwrap contentKey from wrappedContentKey using a wrapKey
        const wrappedEntries = result.manifest.content["bodytext"].wrappedContentKey;
        let contentKeyBytes: Uint8Array | null = null;

        for (const entry of wrappedEntries) {
            const wrapKeyB64 = wrapKeys[entry.kid];
            if (!wrapKeyB64) continue;

            const wrapKeyBytes = fromBase64Url(wrapKeyB64);
            const iv = fromBase64Url(entry.iv);
            const wrappedKey = fromBase64Url(entry.ciphertext);

            contentKeyBytes = await aesGcmDecrypt(wrappedKey, wrapKeyBytes, iv);
            break;
        }

        expect(contentKeyBytes).not.toBeNull();

        // Decrypt content
        const contentEntry = result.manifest.content["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(contentEntry.ciphertext),
            contentKeyBytes!,
            fromBase64Url(contentEntry.iv),
            encodeUtf8(contentEntry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("Period key content");
    });

    it("issuer rejects tampered sealed blobs", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "tamper.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "tamper-test",
            contentItems: [{ contentName: "bodytext", content: "Original" }],
            issuers: [
                {
                    issuerName: "tamper-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "t-1",
                    unlockUrl: "https://tamper.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const issuer = createDcaIssuer({
            issuerName: "tamper-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "t-1",
            trustedPublisherKeys: {
                "tamper.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Tamper with the sealed contentKey
        const tamperedKeys = result.manifest.issuers["tamper-issuer"].keys.map(
            (entry) => entry.contentName === "bodytext"
                ? { ...entry, contentKey: toBase64Url(generateAesKeyBytes()) }
                : entry,
        );

        await expect(
            issuer.unlock(
                {
                    resourceJWT: result.manifest.resourceJWT,
                    keys: tamperedKeys,
                },
                { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
            ),
        ).rejects.toThrow();
    });

    it("issuer rejects unknown publisher domain", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "unknown.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "domain-test",
            contentItems: [{ contentName: "bodytext", content: "Content" }],
            issuers: [
                {
                    issuerName: "domain-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "d-1",
                    unlockUrl: "https://domain.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        // Issuer only trusts "known.example.com"
        const issuer = createDcaIssuer({
            issuerName: "domain-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "d-1",
            trustedPublisherKeys: {
                "known.example.com": keys.signingPems.publicKeyPem,
            },
        });

        await expect(
            issuer.unlock(
                {
                    resourceJWT: result.manifest.resourceJWT,
                    keys: result.manifest.issuers["domain-issuer"].keys,
                },
                { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
            ),
        ).rejects.toThrow("Untrusted publisher domain");
    });

    it("issuer verify returns verified resource data", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "verify.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "verify-test",
            contentItems: [{ contentName: "bodytext", content: "Content" }],
            issuers: [
                {
                    issuerName: "verify-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "v-1",
                    unlockUrl: "https://verify.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
            resourceData: { section: "politics" },
        });

        const issuer = createDcaIssuer({
            issuerName: "verify-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "v-1",
            trustedPublisherKeys: {
                "verify.example.com": keys.signingPems.publicKeyPem,
            },
        });

        const verified = await issuer.verify({
            resourceJWT: result.manifest.resourceJWT,
            keys: result.manifest.issuers["verify-issuer"].keys,
        });

        expect(verified.resource.resourceId).toBe("verify-test");
        expect(verified.resource.domain).toBe("verify.example.com");
        expect(verified.resource.data).toEqual({ section: "politics" });
    });

    it("JSON API response includes all fields", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "json.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "json-test",
            contentItems: [{ contentName: "bodytext", content: "JSON content" }],
            issuers: [
                {
                    issuerName: "json-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "j-1",
                    unlockUrl: "https://json.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        // JSON response should have all manifest fields
        const json = result.json;
        expect(json.version).toBe("0.10");
        expect(json.content["bodytext"].ciphertext).toBeDefined();
        expect(json.resourceJWT).toBeDefined();
        expect(json.content).toBeDefined();
        expect(json.content["bodytext"].wrappedContentKey).toBeDefined();
        expect(json.issuers).toBeDefined();
    });

    it("AAD string follows the convention domain|resourceId|contentName|version", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "aad.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "aad-article",
            contentItems: [{ contentName: "bodytext", content: "AAD test" }],
            issuers: [
                {
                    issuerName: "aad-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "a-1",
                    unlockUrl: "https://aad.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        expect(result.manifest.content["bodytext"].aad).toBe("aad.example.com|aad-article|bodytext|bodytext");
    });

    it("cross-resource substitution with same scope unseals but returns wrong key (harmless)", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "aad.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        // Render two different resources with the same scope
        const resultA = await publisher.render({
            resourceId: "article-A",
            contentItems: [{ contentName: "bodytext", content: "Content A" }],
            issuers: [{
                issuerName: "aad-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "aad-1",
                unlockUrl: "https://aad.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const resultB = await publisher.render({
            resourceId: "article-B",
            contentItems: [{ contentName: "bodytext", content: "Content B" }],
            issuers: [{
                issuerName: "aad-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "aad-1",
                unlockUrl: "https://aad.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const issuer = createDcaIssuer({
            issuerName: "aad-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "aad-1",
            trustedPublisherKeys: {
                "aad.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Normal unlock for A
        const responseA = await issuer.unlock(
            {
                resourceJWT: resultA.manifest.resourceJWT,
                keys: resultA.manifest.issuers["aad-issuer"].keys,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
        );
        const keyA = findKey(responseA, "bodytext").contentKey!;

        // Cross-resource substitution: resourceJWT from A, keys from B
        // This now succeeds at unseal (same scope = same AAD), but returns B's contentKey
        const responseSubst = await issuer.unlock(
            {
                resourceJWT: resultA.manifest.resourceJWT,
                keys: resultB.manifest.issuers["aad-issuer"].keys,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
        );
        const keySubst = findKey(responseSubst, "bodytext").contentKey!;

        // The substituted key is different (B's contentKey) and can't decrypt A's content
        expect(keySubst).not.toBe(keyA);
    });

    it("wrap AAD: unwrap with matching scope succeeds", async () => {
        const keyPair = await generateEcdhP256KeyPair();
        const pems = await exportP256KeyPairPem(keyPair.privateKey, keyPair.publicKey);

        const { key: pubKey } = await importIssuerPublicKey(pems.publicKeyPem, "ECDH-P256");
        const { key: privKey } = await importIssuerPrivateKey(pems.privateKeyPem, "ECDH-P256");

        const originalKey = generateAesKeyBytes();
        const aad = encodeUtf8("premium");

        const sealed = await wrapEcdhP256(originalKey, pubKey, aad);
        const unsealed = await unwrapEcdhP256(sealed, privKey, aad);
        expect(unsealed).toEqual(originalKey);
    });

    it("seal AAD: unseal with wrong AAD fails", async () => {
        const keyPair = await generateEcdhP256KeyPair();
        const pems = await exportP256KeyPairPem(keyPair.privateKey, keyPair.publicKey);

        const { key: pubKey } = await importIssuerPublicKey(pems.publicKeyPem, "ECDH-P256");
        const { key: privKey } = await importIssuerPrivateKey(pems.privateKeyPem, "ECDH-P256");

        const originalKey = generateAesKeyBytes();
        const aad = encodeUtf8("premium");
        const wrongAad = encodeUtf8("free");

        const sealed = await wrapEcdhP256(originalKey, pubKey, aad);
        await expect(unwrapEcdhP256(sealed, privKey, wrongAad)).rejects.toThrow();
    });

    it("seal AAD: unseal without AAD fails when AAD was used", async () => {
        const keyPair = await generateEcdhP256KeyPair();
        const pems = await exportP256KeyPairPem(keyPair.privateKey, keyPair.publicKey);

        const { key: pubKey } = await importIssuerPublicKey(pems.publicKeyPem, "ECDH-P256");
        const { key: privKey } = await importIssuerPrivateKey(pems.privateKeyPem, "ECDH-P256");

        const originalKey = generateAesKeyBytes();
        const aad = encodeUtf8("premium");

        const sealed = await wrapEcdhP256(originalKey, pubKey, aad);
        await expect(unwrapEcdhP256(sealed, privKey)).rejects.toThrow();
    });
});

// ============================================================================
// 7. Trusted-publisher allowlist hardening
// ============================================================================

describe("Trusted-publisher allowlist", () => {
    it("rejects empty trustedPublisherKeys", () => {
        expect(() =>
            createDcaIssuer({
                issuerName: "test",
                privateKeyPem: "unused",
                keyId: "k-1",
                trustedPublisherKeys: {},
            }),
        ).toThrow("trustedPublisherKeys must contain at least one entry");
    });

    it("rejects invalid domain names in config", () => {
        expect(() =>
            createDcaIssuer({
                issuerName: "test",
                privateKeyPem: "unused",
                keyId: "k-1",
                trustedPublisherKeys: { "https://evil.com/path": "-----BEGIN PUBLIC KEY-----\ntest" },
            }),
        ).toThrow("Invalid domain");
    });

    it("rejects domains with spaces", () => {
        expect(() =>
            createDcaIssuer({
                issuerName: "test",
                privateKeyPem: "unused",
                keyId: "k-1",
                trustedPublisherKeys: { "evil .com": "-----BEGIN PUBLIC KEY-----\ntest" },
            }),
        ).toThrow("Invalid domain");
    });

    it("normalises domain case and trailing dots (config-time)", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "case.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "case-article",
            contentItems: [{ contentName: "bodytext", content: "Case test" }],
            issuers: [
                {
                    issuerName: "case-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "c-1",
                    unlockUrl: "https://case.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        // Config uses uppercase + trailing dot — should still match
        const issuer = createDcaIssuer({
            issuerName: "case-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "c-1",
            trustedPublisherKeys: {
                "Case.Example.COM.": keys.signingPems.publicKeyPem,
            },
        });

        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["case-issuer"].keys,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
        );

        expect(findKey(response, "bodytext").contentKey).toBeDefined();
    });

    it("rejects duplicate domains after normalisation", () => {
        expect(() =>
            createDcaIssuer({
                issuerName: "test",
                privateKeyPem: "unused",
                keyId: "k-1",
                trustedPublisherKeys: {
                    "Example.com": "-----BEGIN PUBLIC KEY-----\nkey-a",
                    "example.com": "-----BEGIN PUBLIC KEY-----\nkey-b",
                },
            }),
        ).toThrow(/duplicate domain.*example\.com/i);
    });

    it("supports extended DcaTrustedPublisher config with allowedResourceIds (exact)", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "constrained.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const allowed = await publisher.render({
            resourceId: "article-ok",
            contentItems: [{ contentName: "bodytext", content: "Allowed" }],
            issuers: [
                {
                    issuerName: "constrained-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "cr-1",
                    unlockUrl: "https://constrained.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const denied = await publisher.render({
            resourceId: "article-forbidden",
            contentItems: [{ contentName: "bodytext", content: "Forbidden" }],
            issuers: [
                {
                    issuerName: "constrained-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "cr-1",
                    unlockUrl: "https://constrained.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const issuer = createDcaIssuer({
            issuerName: "constrained-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "cr-1",
            trustedPublisherKeys: {
                "constrained.example.com": {
                    signingKeyPem: keys.signingPems.publicKeyPem,
                    allowedResourceIds: ["article-ok"],
                },
            },
        });

        // Allowed resource
        const response = await issuer.unlock(
            {
                resourceJWT: allowed.manifest.resourceJWT,
                keys: allowed.manifest.issuers["constrained-issuer"].keys,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
        );
        expect(findKey(response, "bodytext").contentKey).toBeDefined();

        // Denied resource
        await expect(
            issuer.unlock(
                {
                    resourceJWT: denied.manifest.resourceJWT,
                    keys: denied.manifest.issuers["constrained-issuer"].keys,
                },
                { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
            ),
        ).rejects.toThrow(/not allowed to claim resourceId/);
    });

    it("supports allowedResourceIds with RegExp patterns", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "regex.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const premium = await publisher.render({
            resourceId: "premium-article-42",
            contentItems: [{ contentName: "bodytext", content: "Premium" }],
            issuers: [
                {
                    issuerName: "regex-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "rx-1",
                    unlockUrl: "https://regex.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const free = await publisher.render({
            resourceId: "free-article-1",
            contentItems: [{ contentName: "bodytext", content: "Free" }],
            issuers: [
                {
                    issuerName: "regex-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "rx-1",
                    unlockUrl: "https://regex.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const issuer = createDcaIssuer({
            issuerName: "regex-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "rx-1",
            trustedPublisherKeys: {
                "regex.example.com": {
                    signingKeyPem: keys.signingPems.publicKeyPem,
                    allowedResourceIds: [/^premium-/],
                },
            },
        });

        // "premium-article-42" matches /^premium-/
        const response = await issuer.unlock(
            {
                resourceJWT: premium.manifest.resourceJWT,
                keys: premium.manifest.issuers["regex-issuer"].keys,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
        );
        expect(findKey(response, "bodytext").contentKey).toBeDefined();

        // "free-article-1" does NOT match
        await expect(
            issuer.unlock(
                {
                    resourceJWT: free.manifest.resourceJWT,
                    keys: free.manifest.issuers["regex-issuer"].keys,
                },
                { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
            ),
        ).rejects.toThrow(/not allowed to claim resourceId/);
    });

    it("plain string entries (backward compat) allow all resourceIds", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "compat.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "anything-at-all",
            contentItems: [{ contentName: "bodytext", content: "Compat" }],
            issuers: [
                {
                    issuerName: "compat-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "co-1",
                    unlockUrl: "https://compat.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        // Plain string entry (no constraints)
        const issuer = createDcaIssuer({
            issuerName: "compat-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "co-1",
            trustedPublisherKeys: {
                "compat.example.com": keys.signingPems.publicKeyPem,
            },
        });

        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["compat-issuer"].keys,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
        );

        expect(findKey(response, "bodytext").contentKey).toBeDefined();
    });
});

// ============================================================================
// 7. Client-bound transport (RSA-OAEP key wrapping)
// ============================================================================

describe("DCA client-bound transport", () => {
    /** Generate an RSA-OAEP key pair for the client, with non-extractable private key */
    async function generateClientKeyPair() {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"],
        );

        // Re-import private key as non-extractable (mirrors DcaClient behavior)
        const privJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
        const nonExtractablePriv = await crypto.subtle.importKey(
            "jwk",
            privJwk,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"],
        );

        // Export public key as base64url SPKI
        const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
        const clientPublicKey = toBase64Url(new Uint8Array(spki));

        return { publicKey: keyPair.publicKey, privateKey: nonExtractablePriv, clientPublicKey };
    }

    /** RSA-OAEP decrypt a base64url blob with the client's private key */
    async function rsaUnwrap(wrappedB64: string, privateKey: WebCryptoKey): Promise<Uint8Array> {
        const ciphertext = fromBase64Url(wrappedB64);
        const decrypted = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            ciphertext,
        );
        return new Uint8Array(decrypted);
    }

    it("contentKey mode: issuer wraps keys with client public key", async () => {
        const keys = await generateTestKeys();
        const clientKeys = await generateClientKeyPair();

        // --- Publisher ---
        const publisher = createDcaPublisher({
            domain: "cb.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "cb-article-1",
            contentItems: [{ contentName: "bodytext", content: "<p>Client-bound content</p>" }],
            issuers: [{
                issuerName: "cb-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "cb-1",
                unlockUrl: "https://cb.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        // --- Issuer (with clientPublicKey) ---
        const issuer = createDcaIssuer({
            issuerName: "cb-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "cb-1",
            trustedPublisherKeys: { "cb.example.com": keys.signingPems.publicKeyPem },
        });

        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["cb-issuer"].keys,
                clientPublicKey: clientKeys.clientPublicKey,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
        );

        // Response signals client-bound transport
        expect(response.transport).toBe("client-bound");
        expect(findKey(response, "bodytext").contentKey).toBeDefined();

        // The contentKey in the response is RSA-OAEP wrapped — NOT the raw key
        const wrappedCK = findKey(response, "bodytext").contentKey!;
        // RSA-2048 ciphertext is 256 bytes → 344 base64url chars (much larger than 43)
        expect(wrappedCK.length).toBeGreaterThan(100);

        // --- Client-side: RSA unwrap + AES-GCM decrypt ---
        const contentKeyBytes = await rsaUnwrap(wrappedCK, clientKeys.privateKey);
        expect(contentKeyBytes.length).toBe(32); // AES-256 key

        const contentEntry = result.manifest.content["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(contentEntry.ciphertext),
            contentKeyBytes,
            fromBase64Url(contentEntry.iv),
            encodeUtf8(contentEntry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("<p>Client-bound content</p>");
    });

    it("wrapKey mode: issuer wraps wrapKeys with client public key", async () => {
        const keys = await generateTestKeys();
        const clientKeys = await generateClientKeyPair();

        const publisher = createDcaPublisher({
            domain: "cb-pk.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "cb-pk-article",
            contentItems: [{ contentName: "bodytext", content: "Period key CB content" }],
            issuers: [{
                issuerName: "cb-pk-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "cbpk-1",
                unlockUrl: "https://cbpk.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const issuer = createDcaIssuer({
            issuerName: "cb-pk-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "cbpk-1",
            trustedPublisherKeys: { "cb-pk.example.com": keys.signingPems.publicKeyPem },
        });

        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["cb-pk-issuer"].keys,
                clientPublicKey: clientKeys.clientPublicKey,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "wrapKey" },
        );

        expect(response.transport).toBe("client-bound");
        const wrapKeys = wrapKeysToRecord(findKey(response, "bodytext"));
        expect(Object.keys(wrapKeys).length).toBe(2);

        // RSA unwrap each wrapKey, then AES-GCM unwrap contentKey
        const wrappedEntries = result.manifest.content["bodytext"].wrappedContentKey;
        let contentKeyBytes: Uint8Array | null = null;

        for (const entry of wrappedEntries) {
            const wrappedPK = wrapKeys[entry.kid];
            if (!wrappedPK) continue;

            const wrapKeyBytes = await rsaUnwrap(wrappedPK, clientKeys.privateKey);
            expect(wrapKeyBytes.length).toBe(32);

            const iv = fromBase64Url(entry.iv);
            const wrappedCK = fromBase64Url(entry.ciphertext);

            contentKeyBytes = await aesGcmDecrypt(wrappedCK, wrapKeyBytes, iv);
            break;
        }

        expect(contentKeyBytes).not.toBeNull();

        const contentEntry = result.manifest.content["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(contentEntry.ciphertext),
            contentKeyBytes!,
            fromBase64Url(contentEntry.iv),
            encodeUtf8(contentEntry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("Period key CB content");
    });

    it("without clientPublicKey: direct transport (backward compatible)", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "direct.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "direct-article",
            contentItems: [{ contentName: "bodytext", content: "Direct content" }],
            issuers: [{
                issuerName: "direct-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "d-1",
                unlockUrl: "https://direct.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const issuer = createDcaIssuer({
            issuerName: "direct-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "d-1",
            trustedPublisherKeys: { "direct.example.com": keys.signingPems.publicKeyPem },
        });

        // No clientPublicKey — should use direct transport
        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["direct-issuer"].keys,
                // no clientPublicKey
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
        );

        // No transport field (or undefined) means direct
        expect(response.transport).toBeUndefined();

        // Raw contentKey — 32 bytes = 43 base64url chars
        const ck = findKey(response, "bodytext").contentKey!;
        expect(ck.length).toBe(43);

        // Verify it decrypts
        const contentKeyBytes = fromBase64Url(ck);
        const contentEntry = result.manifest.content["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(contentEntry.ciphertext),
            contentKeyBytes,
            fromBase64Url(contentEntry.iv),
            encodeUtf8(contentEntry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("Direct content");
    });
});

// ============================================================================
// Share Link Tokens
// ============================================================================

describe("Share Link Tokens", () => {
    it("creates and validates a share link token (full E2E)", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "share.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        // Render the page
        const result = await publisher.render({
            resourceId: "shared-article-1",
            contentItems: [
                { contentName: "bodytext", content: "<p>Shared premium content</p>" },
            ],
            issuers: [{
                issuerName: "share-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "sk-1",
                unlockUrl: "https://share.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        // Publisher creates a share link token
        const shareToken = await publisher.createShareLinkToken({
            resourceId: "shared-article-1",
            contentNames: ["bodytext"],
            expiresIn: 7 * 24 * 3600, // 7 days
        });

        expect(typeof shareToken).toBe("string");
        expect(shareToken.split(".")).toHaveLength(3); // JWT format

        // Issuer validates the share token and unlocks
        const issuer = createDcaIssuer({
            issuerName: "share-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "sk-1",
            trustedPublisherKeys: {
                "share.example.com": keys.signingPems.publicKeyPem,
            },
        });

        const response = await issuer.unlockWithShareToken({
            resourceJWT: result.manifest.resourceJWT,
            keys: result.manifest.issuers["share-issuer"].keys,
            shareToken,
        });

        // Should return contentKey (default for share links)
        expect(findKey(response, "bodytext")).toBeDefined();
        expect(findKey(response, "bodytext").contentKey).toBeDefined();

        // Decrypt the content
        const contentKeyBytes = fromBase64Url(findKey(response, "bodytext").contentKey!);
        const contentEntry = result.manifest.content["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(contentEntry.ciphertext),
            contentKeyBytes,
            fromBase64Url(contentEntry.iv),
            encodeUtf8(contentEntry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("<p>Shared premium content</p>");
    });

    it("share link token works with wrapKey delivery mode", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "share-pk.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "shared-pk-1",
            contentItems: [
                { contentName: "bodytext", content: "Period key shared content" },
            ],
            issuers: [{
                issuerName: "share-pk-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "spk-1",
                unlockUrl: "https://share-pk.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const shareToken = await publisher.createShareLinkToken({
            resourceId: "shared-pk-1",
            contentNames: ["bodytext"],
        });

        const issuer = createDcaIssuer({
            issuerName: "share-pk-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "spk-1",
            trustedPublisherKeys: {
                "share-pk.example.com": keys.signingPems.publicKeyPem,
            },
        });

        const response = await issuer.unlockWithShareToken(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["share-pk-issuer"].keys,
                shareToken,
            },
            { deliveryMode: "wrapKey" },
        );

        // Should return wrapKeys
        expect(findKey(response, "bodytext").wrapKeys).toBeDefined();
        expect(findKey(response, "bodytext").contentKey).toBeUndefined();

        // Unwrap contentKey from wrappedContentKey using wrapKey
        const wrapKeys = wrapKeysToRecord(findKey(response, "bodytext"));
        const wrappedContentKey = result.manifest.content["bodytext"].wrappedContentKey;
        let contentKeyBytes: Uint8Array | null = null;

        for (const entry of wrappedContentKey) {
            const pkB64 = wrapKeys[entry.kid];
            if (!pkB64) continue;

            const wrapKeyBytes = fromBase64Url(pkB64);
            const iv = fromBase64Url(entry.iv);
            const wrappedKey = fromBase64Url(entry.ciphertext);

            const decryptedKey = await aesGcmDecrypt(wrappedKey, wrapKeyBytes, iv);
            contentKeyBytes = decryptedKey;
            break;
        }

        expect(contentKeyBytes).not.toBeNull();

        // Decrypt content
        const contentEntry = result.manifest.content["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(contentEntry.ciphertext),
            contentKeyBytes!,
            fromBase64Url(contentEntry.iv),
            encodeUtf8(contentEntry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("Period key shared content");
    });

    it("rejects expired share link tokens", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "expire.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "expired-article",
            contentItems: [
                { contentName: "bodytext", content: "Expired content" },
            ],
            issuers: [{
                issuerName: "expire-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "ek-1",
                unlockUrl: "https://expire.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        // Create an already-expired token
        const shareToken = await publisher.createShareLinkToken({
            resourceId: "expired-article",
            contentNames: ["bodytext"],
            expiresIn: -1, // already expired
        });

        const issuer = createDcaIssuer({
            issuerName: "expire-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "ek-1",
            trustedPublisherKeys: {
                "expire.example.com": keys.signingPems.publicKeyPem,
            },
        });

        await expect(
            issuer.unlockWithShareToken({
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["expire-issuer"].keys,
                shareToken,
            }),
        ).rejects.toThrow(/expired/);
    });

    it("rejects share token for wrong resourceId", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "mismatch.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "article-A",
            contentItems: [
                { contentName: "bodytext", content: "Article A content" },
            ],
            issuers: [{
                issuerName: "mm-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "mm-1",
                unlockUrl: "https://mm.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        // Create token for a different article
        const shareToken = await publisher.createShareLinkToken({
            resourceId: "article-B", // Wrong!
            contentNames: ["bodytext"],
        });

        const issuer = createDcaIssuer({
            issuerName: "mm-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "mm-1",
            trustedPublisherKeys: {
                "mismatch.example.com": keys.signingPems.publicKeyPem,
            },
        });

        await expect(
            issuer.unlockWithShareToken({
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["mm-issuer"].keys,
                shareToken,
            }),
        ).rejects.toThrow(/resourceId mismatch/);
    });

    it("rejects share token signed by untrusted publisher", async () => {
        const keys = await generateTestKeys();
        const evilKeys = await generateTestKeys(); // Different signing key

        const publisher = createDcaPublisher({
            domain: "trusted.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const evilPublisher = createDcaPublisher({
            domain: "trusted.example.com", // Claims to be trusted
            signingKeyPem: evilKeys.signingPems.privateKeyPem,
            rotationSecret: evilKeys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "article-trust",
            contentItems: [
                { contentName: "bodytext", content: "Trusted content" },
            ],
            issuers: [{
                issuerName: "trust-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "tk-1",
                unlockUrl: "https://trust.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        // Evil publisher signs a share token
        const evilShareToken = await evilPublisher.createShareLinkToken({
            resourceId: "article-trust",
            contentNames: ["bodytext"],
        });

        const issuer = createDcaIssuer({
            issuerName: "trust-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "tk-1",
            trustedPublisherKeys: {
                "trusted.example.com": keys.signingPems.publicKeyPem, // Only trusts real key
            },
        });

        await expect(
            issuer.unlockWithShareToken({
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["trust-issuer"].keys,
                shareToken: evilShareToken,
            }),
        ).rejects.toThrow(/signature/i);
    });

    it("rejects unlock when no shareToken provided", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "noshare.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "article-noshare",
            contentItems: [
                { contentName: "bodytext", content: "No share content" },
            ],
            issuers: [{
                issuerName: "ns-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "ns-1",
                unlockUrl: "https://ns.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const issuer = createDcaIssuer({
            issuerName: "ns-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "ns-1",
            trustedPublisherKeys: {
                "noshare.example.com": keys.signingPems.publicKeyPem,
            },
        });

        await expect(
            issuer.unlockWithShareToken({
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["ns-issuer"].keys,
                // no shareToken
            }),
        ).rejects.toThrow(/shareToken/);
    });

    it("share token only grants specified content names", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "partial.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "partial-article",
            contentItems: [
                { contentName: "preview", content: "Preview text" },
                { contentName: "bodytext", content: "Full body text" },
                { contentName: "bonus", content: "Bonus content" },
            ],
            issuers: [{
                issuerName: "partial-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "pk-1",
                unlockUrl: "https://partial.test/unlock",
                contentNames: ["preview", "bodytext", "bonus"],
            }],
        });

        // Share token only grants access to "preview" and "bodytext", not "bonus"
        const shareToken = await publisher.createShareLinkToken({
            resourceId: "partial-article",
            contentNames: ["preview", "bodytext"],
        });

        const issuer = createDcaIssuer({
            issuerName: "partial-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "pk-1",
            trustedPublisherKeys: {
                "partial.example.com": keys.signingPems.publicKeyPem,
            },
        });

        const response = await issuer.unlockWithShareToken({
            resourceJWT: result.manifest.resourceJWT,
            keys: result.manifest.issuers["partial-issuer"].keys,
            shareToken,
        });

        // Should only grant preview and bodytext
        expect(response.keys.map(k => k.contentName).sort()).toEqual(["bodytext", "preview"]);
        expect(response.keys.find(k => k.contentName === "bonus")).toBeUndefined();

        // Verify both decrypt correctly
        for (const [name, expected] of [
            ["preview", "Preview text"],
            ["bodytext", "Full body text"],
        ] as const) {
            const ck = fromBase64Url(findKey(response, name).contentKey!);
            const entry = result.manifest.content[name];
            const decrypted = await decryptContent(
                fromBase64Url(entry.ciphertext),
                ck,
                fromBase64Url(entry.iv),
                encodeUtf8(entry.aad),
            );
            expect(decodeUtf8(decrypted)).toBe(expected);
        }
    });

    it("supports onShareToken callback for use-count tracking", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "callback.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "callback-article",
            contentItems: [
                { contentName: "bodytext", content: "Callback content" },
            ],
            issuers: [{
                issuerName: "cb-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "cb-1",
                unlockUrl: "https://cb.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const shareToken = await publisher.createShareLinkToken({
            resourceId: "callback-article",
            contentNames: ["bodytext"],
            maxUses: 5,
            jti: "share-token-001",
            data: { sharedBy: "user-42" },
        });

        const issuer = createDcaIssuer({
            issuerName: "cb-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "cb-1",
            trustedPublisherKeys: {
                "callback.example.com": keys.signingPems.publicKeyPem,
            },
        });

        let callbackInvoked = false;
        let receivedPayload: unknown = null;

        const response = await issuer.unlockWithShareToken(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["cb-issuer"].keys,
                shareToken,
            },
            {
                onShareToken: (payload, _resource) => {
                    callbackInvoked = true;
                    receivedPayload = payload;
                },
            },
        );

        expect(callbackInvoked).toBe(true);
        const p = receivedPayload as { type: string; jti: string; maxUses: number; data: Record<string, unknown> };
        expect(p.type).toBe("dca-share");
        expect(p.jti).toBe("share-token-001");
        expect(p.maxUses).toBe(5);
        expect(p.data).toEqual({ sharedBy: "user-42" });

        // Verify decryption works
        expect(findKey(response, "bodytext").contentKey).toBeDefined();
    });

    it("onShareToken callback can reject the request", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "reject.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "rejected-article",
            contentItems: [
                { contentName: "bodytext", content: "Rejected content" },
            ],
            issuers: [{
                issuerName: "rj-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "rj-1",
                unlockUrl: "https://rj.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const shareToken = await publisher.createShareLinkToken({
            resourceId: "rejected-article",
            contentNames: ["bodytext"],
            maxUses: 1,
        });

        const issuer = createDcaIssuer({
            issuerName: "rj-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "rj-1",
            trustedPublisherKeys: {
                "reject.example.com": keys.signingPems.publicKeyPem,
            },
        });

        await expect(
            issuer.unlockWithShareToken(
                {
                    resourceJWT: result.manifest.resourceJWT,
                    keys: result.manifest.issuers["rj-issuer"].keys,
                    shareToken,
                },
                {
                    onShareToken: () => {
                        throw new Error("Share link usage limit exceeded");
                    },
                },
            ),
        ).rejects.toThrow("Share link usage limit exceeded");
    });

    it("verifyShareToken standalone method", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "verify.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const shareToken = await publisher.createShareLinkToken({
            resourceId: "verify-article",
            contentNames: ["bodytext", "sidebar"],
            expiresIn: 3600,
            jti: "verify-token-id",
        });

        const issuer = createDcaIssuer({
            issuerName: "v-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "v-1",
            trustedPublisherKeys: {
                "verify.example.com": keys.signingPems.publicKeyPem,
            },
        });

        const payload = await issuer.verifyShareToken(shareToken, "verify.example.com");

        expect(payload.type).toBe("dca-share");
        expect(payload.domain).toBe("verify.example.com");
        expect(payload.resourceId).toBe("verify-article");
        expect(payload.contentNames).toEqual(["bodytext", "sidebar"]);
        expect(payload.jti).toBe("verify-token-id");
        expect(payload.exp).toBeGreaterThan(payload.iat);
    });

    it("auto-generates jti when options.jti is omitted", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "jti-auto.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const issuer = createDcaIssuer({
            issuerName: "jti-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "jti-1",
            trustedPublisherKeys: {
                "jti-auto.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Create two tokens without specifying jti
        const token1 = await publisher.createShareLinkToken({
            resourceId: "article-jti",
            contentNames: ["bodytext"],
        });
        const token2 = await publisher.createShareLinkToken({
            resourceId: "article-jti",
            contentNames: ["bodytext"],
        });

        const payload1 = await issuer.verifyShareToken(token1, "jti-auto.example.com");
        const payload2 = await issuer.verifyShareToken(token2, "jti-auto.example.com");

        // jti must be a non-empty string
        expect(typeof payload1.jti).toBe("string");
        expect(payload1.jti.length).toBeGreaterThan(0);

        // Each token gets a unique jti
        expect(payload1.jti).not.toBe(payload2.jti);
    });

    describe("rejects malformed timestamp claims", () => {
        /**
         * Helper: craft a share-link token JWT with arbitrary payload,
         * signed by the publisher's real key (so the signature is valid).
         */
        async function craftShareToken(
            signingKeyPem: string,
            payloadOverrides: Record<string, unknown>,
        ): Promise<string> {
            const now = Math.floor(Date.now() / 1000);
            const base = {
                type: "dca-share",
                domain: "malformed.example.com",
                resourceId: "malformed-article",
                contentNames: ["bodytext"],
                iat: now,
                exp: now + 3600,
            };
            return createJwt({ ...base, ...payloadOverrides }, signingKeyPem);
        }

        async function makeIssuer() {
            const keys = await generateTestKeys();
            const issuer = createDcaIssuer({
                issuerName: "mf-issuer",
                privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
                keyId: "mf-1",
                trustedPublisherKeys: {
                    "malformed.example.com": keys.signingPems.publicKeyPem,
                },
            });
            return { issuer, keys };
        }

        it("rejects missing exp", async () => {
            const { issuer, keys } = await makeIssuer();
            const token = await craftShareToken(keys.signingPems.privateKeyPem, {
                exp: undefined,
            });
            await expect(
                issuer.verifyShareToken(token, "malformed.example.com"),
            ).rejects.toThrow(/exp must be a finite number/);
        });

        it("rejects missing iat", async () => {
            const { issuer, keys } = await makeIssuer();
            const token = await craftShareToken(keys.signingPems.privateKeyPem, {
                iat: undefined,
            });
            await expect(
                issuer.verifyShareToken(token, "malformed.example.com"),
            ).rejects.toThrow(/iat must be a finite number/);
        });

        it("rejects string exp", async () => {
            const { issuer, keys } = await makeIssuer();
            const token = await craftShareToken(keys.signingPems.privateKeyPem, {
                exp: "9999999999",
            });
            await expect(
                issuer.verifyShareToken(token, "malformed.example.com"),
            ).rejects.toThrow(/exp must be a finite number/);
        });

        it("rejects string iat", async () => {
            const { issuer, keys } = await makeIssuer();
            const token = await craftShareToken(keys.signingPems.privateKeyPem, {
                iat: "0",
            });
            await expect(
                issuer.verifyShareToken(token, "malformed.example.com"),
            ).rejects.toThrow(/iat must be a finite number/);
        });

        it("rejects NaN exp", async () => {
            const { issuer, keys } = await makeIssuer();
            // NaN survives JSON round-trip as null, but let's test explicitly
            const token = await craftShareToken(keys.signingPems.privateKeyPem, {
                exp: null,
            });
            await expect(
                issuer.verifyShareToken(token, "malformed.example.com"),
            ).rejects.toThrow(/exp must be a finite number/);
        });

        it("rejects Infinity exp", async () => {
            const { issuer, keys } = await makeIssuer();
            // Infinity serializes to null in JSON
            const token = await craftShareToken(keys.signingPems.privateKeyPem, {
                exp: null,
            });
            await expect(
                issuer.verifyShareToken(token, "malformed.example.com"),
            ).rejects.toThrow(/exp must be a finite number/);
        });

        it("rejects object exp", async () => {
            const { issuer, keys } = await makeIssuer();
            const token = await craftShareToken(keys.signingPems.privateKeyPem, {
                exp: { valueOf: 9999999999 },
            });
            await expect(
                issuer.verifyShareToken(token, "malformed.example.com"),
            ).rejects.toThrow(/exp must be a finite number/);
        });

        it("rejects boolean exp", async () => {
            const { issuer, keys } = await makeIssuer();
            const token = await craftShareToken(keys.signingPems.privateKeyPem, {
                exp: true,
            });
            await expect(
                issuer.verifyShareToken(token, "malformed.example.com"),
            ).rejects.toThrow(/exp must be a finite number/);
        });
    });
});

// ============================================================================
// Unlock Request Format
// ============================================================================

describe("unlock request format", () => {
    it("unlocks with resourceJWT and contentEncryptionKeys", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "v2.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "v2-article",
            contentItems: [
                { contentName: "bodytext", content: "<p>v2 content</p>" },
            ],
            issuers: [
                {
                    issuerName: "v2-issuer",
                    publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                    keyId: "v2-key-1",
                    unlockUrl: "https://v2.test/unlock",
                    contentNames: ["bodytext"],
                },
            ],
        });

        const issuer = createDcaIssuer({
            issuerName: "v2-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "v2-key-1",
            trustedPublisherKeys: {
                "v2.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Unlock request: resourceJWT + keys
        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["v2-issuer"].keys,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
        );

        expect(findKey(response, "bodytext")).toBeDefined();
        expect(findKey(response, "bodytext").contentKey).toBeDefined();

        // Decrypt to verify the full chain works
        const contentKeyBytes = fromBase64Url(findKey(response, "bodytext").contentKey!);
        const contentEntry = result.manifest.content["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(contentEntry.ciphertext),
            contentKeyBytes,
            fromBase64Url(contentEntry.iv),
            encodeUtf8(contentEntry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("<p>v2 content</p>");
    });

    it("unlocks with wrapKey delivery mode", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "v2pk.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "v2-pk-article",
            contentItems: [{ contentName: "bodytext", content: "v2 period key content" }],
            issuers: [{
                issuerName: "v2pk-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "v2pk-1",
                unlockUrl: "https://v2pk.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const issuer = createDcaIssuer({
            issuerName: "v2pk-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "v2pk-1",
            trustedPublisherKeys: {
                "v2pk.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Unlock with wrapKey delivery
        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["v2pk-issuer"].keys,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "wrapKey" },
        );

        expect(findKey(response, "bodytext").wrapKeys).toBeDefined();
        const wrapKeys = wrapKeysToRecord(findKey(response, "bodytext"));
        expect(Object.keys(wrapKeys).length).toBe(2);

        // Unwrap contentKey from wrappedContentKey using a wrapKey
        const wrappedEntries = result.manifest.content["bodytext"].wrappedContentKey;
        let contentKeyBytes: Uint8Array | null = null;
        for (const entry of wrappedEntries) {
            const wrapKeyB64 = wrapKeys[entry.kid];
            if (!wrapKeyB64) continue;
            contentKeyBytes = await aesGcmDecrypt(
                fromBase64Url(entry.ciphertext),
                fromBase64Url(wrapKeyB64),
                fromBase64Url(entry.iv),
            );
            break;
        }
        expect(contentKeyBytes).not.toBeNull();

        const contentEntry = result.manifest.content["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(contentEntry.ciphertext),
            contentKeyBytes!,
            fromBase64Url(contentEntry.iv),
            encodeUtf8(contentEntry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("v2 period key content");
    });

    it("rejects untrusted domain (decoded from JWT)", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "untrusted-v2.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "reject-v2",
            contentItems: [{ contentName: "bodytext", content: "Should fail" }],
            issuers: [{
                issuerName: "reject-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "r-1",
                unlockUrl: "https://reject.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        // Issuer only trusts "trusted.example.com"
        const issuer = createDcaIssuer({
            issuerName: "reject-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "r-1",
            trustedPublisherKeys: {
                "trusted.example.com": keys.signingPems.publicKeyPem,
            },
        });

        await expect(
            issuer.unlock(
                {
                    resourceJWT: result.manifest.resourceJWT,
                    keys: result.manifest.issuers["reject-issuer"].keys,
                },
                { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
            ),
        ).rejects.toThrow("Untrusted publisher domain");
    });

    it("unlocks with share link token", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "v2share.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "v2-share-article",
            contentItems: [{ contentName: "bodytext", content: "v2 share content" }],
            issuers: [{
                issuerName: "v2share-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "vs-1",
                unlockUrl: "https://v2share.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const shareToken = await publisher.createShareLinkToken({
            resourceId: "v2-share-article",
            contentNames: ["bodytext"],
            expiresIn: 3600,
        });

        const issuer = createDcaIssuer({
            issuerName: "v2share-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "vs-1",
            trustedPublisherKeys: {
                "v2share.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Share link unlock
        const response = await issuer.unlockWithShareToken(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["v2share-issuer"].keys,
                shareToken,
            },
            { deliveryMode: "direct" },
        );

        expect(findKey(response, "bodytext").contentKey).toBeDefined();
        const contentKeyBytes = fromBase64Url(findKey(response, "bodytext").contentKey!);
        const contentEntry = result.manifest.content["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(contentEntry.ciphertext),
            contentKeyBytes,
            fromBase64Url(contentEntry.iv),
            encodeUtf8(contentEntry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("v2 share content");
    });

    it("rejects request without contentEncryptionKeys", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "v2nokeys.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "v2-no-keys",
            contentItems: [{ contentName: "bodytext", content: "no keys" }],
            issuers: [{
                issuerName: "v2nokeys-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "nk-1",
                unlockUrl: "https://v2nokeys.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        const issuer = createDcaIssuer({
            issuerName: "v2nokeys-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "nk-1",
            trustedPublisherKeys: {
                "v2nokeys.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Request without keys — should fail at runtime even though type requires it
        await expect(
            issuer.unlock(
                {
                    resourceJWT: result.manifest.resourceJWT,
                } as any,
                { grantedContentNames: ["bodytext"], deliveryMode: "direct" },
            ),
        ).rejects.toThrow(/keys/);
    });
});

// ============================================================================
// scope — role-based access separation
// ============================================================================

describe("scope (role-based access)", () => {
    it("publishes multiple content items sharing a scope", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "keyname.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "kn-article-1",
            contentItems: [
                { contentName: "bodytext", scope: "premium", content: "<p>Body</p>" },
                { contentName: "sidebar", scope: "premium", content: "<p>Sidebar</p>" },
                { contentName: "teaser", content: "Free teaser" }, // no scope → defaults to "teaser"
            ],
            issuers: [{
                issuerName: "kn-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "kn-1",
                unlockUrl: "https://kn.test/unlock",
                scopes: ["premium", "teaser"],
            }],
        });

        // Each entry carries its own scope
        const entries = result.manifest.issuers["kn-issuer"].keys;
        expect(entries.find(e => e.contentName === "bodytext")?.scope).toBe("premium");
        expect(entries.find(e => e.contentName === "sidebar")?.scope).toBe("premium");
        expect(entries.find(e => e.contentName === "teaser")?.scope).toBe("teaser");

        // All three items are sealed for the issuer
        expect(entries.map(k => k.contentName)).toEqual(
            expect.arrayContaining(["bodytext", "sidebar", "teaser"]),
        );

        // Each item has its own content entry with unified AAD: domain|resourceId|contentName|scope
        expect(result.manifest.content["bodytext"].aad).toBe(
            "keyname.example.com|kn-article-1|bodytext|premium",
        );
        expect(result.manifest.content["sidebar"].aad).toBe(
            "keyname.example.com|kn-article-1|sidebar|premium",
        );
    });

    it("items sharing a scope can be decrypted with the same wrapKey", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "shared-pk.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "shared-pk-1",
            contentItems: [
                { contentName: "body", scope: "premium", content: "Body content" },
                { contentName: "sidebar", scope: "premium", content: "Sidebar content" },
            ],
            issuers: [{
                issuerName: "sp-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "sp-1",
                unlockUrl: "https://sp.test/unlock",
                scopes: ["premium"],
            }],
        });

        const issuer = createDcaIssuer({
            issuerName: "sp-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "sp-1",
            trustedPublisherKeys: {
                "shared-pk.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Unlock with wrapKey delivery — request just "body"
        const bodyResponse = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["sp-issuer"].keys,
            },
            { grantedContentNames: ["body"], deliveryMode: "wrapKey" },
        );

        const bodyWrapKeys = wrapKeysToRecord(findKey(bodyResponse, "body"));

        // Unwrap "body" contentKey using wrapKey
        let bodyContentKey: Uint8Array | null = null;
        for (const entry of result.manifest.content["body"].wrappedContentKey) {
            const pkB64 = bodyWrapKeys[entry.kid];
            if (!pkB64) continue;
            bodyContentKey = await aesGcmDecrypt(
                fromBase64Url(entry.ciphertext),
                fromBase64Url(pkB64),
                fromBase64Url(entry.iv),
            );
            break;
        }
        expect(bodyContentKey).not.toBeNull();

        // Now use the SAME wrapKey to unwrap "sidebar" contentKey
        // (both share scope "premium", so the wrapKey works for both)
        let sidebarContentKey: Uint8Array | null = null;
        for (const entry of result.manifest.content["sidebar"].wrappedContentKey) {
            const pkB64 = bodyWrapKeys[entry.kid];
            if (!pkB64) continue;
            sidebarContentKey = await aesGcmDecrypt(
                fromBase64Url(entry.ciphertext),
                fromBase64Url(pkB64),
                fromBase64Url(entry.iv),
            );
            break;
        }
        expect(sidebarContentKey).not.toBeNull();

        // Decrypt both items
        const bodyEntry = result.manifest.content["body"];
        const bodyDecrypted = await decryptContent(
            fromBase64Url(bodyEntry.ciphertext),
            bodyContentKey!,
            fromBase64Url(bodyEntry.iv),
            encodeUtf8(bodyEntry.aad),
        );
        expect(decodeUtf8(bodyDecrypted)).toBe("Body content");

        const sidebarEntry = result.manifest.content["sidebar"];
        const sidebarDecrypted = await decryptContent(
            fromBase64Url(sidebarEntry.ciphertext),
            sidebarContentKey!,
            fromBase64Url(sidebarEntry.iv),
            encodeUtf8(sidebarEntry.aad),
        );
        expect(decodeUtf8(sidebarDecrypted)).toBe("Sidebar content");
    });

    it("issuer supports grantedKeyNames access decision", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "gkn.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "gkn-article",
            contentItems: [
                { contentName: "body", scope: "premium", content: "Premium body" },
                { contentName: "sidebar", scope: "premium", content: "Premium sidebar" },
                { contentName: "teaser", content: "Free teaser" },
            ],
            issuers: [{
                issuerName: "gkn-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "gkn-1",
                unlockUrl: "https://gkn.test/unlock",
                scopes: ["premium", "teaser"],
            }],
        });

        const issuer = createDcaIssuer({
            issuerName: "gkn-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "gkn-1",
            trustedPublisherKeys: {
                "gkn.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Grant by scope "premium" → should unlock "body" and "sidebar"
        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["gkn-issuer"].keys,
            },
            { grantedScopes: ["premium"], deliveryMode: "direct" },
        );

        // Should get keys for body and sidebar, but not teaser
        expect(response.keys.map(k => k.contentName).sort()).toEqual(["body", "sidebar"]);
        expect(response.keys.find(k => k.contentName === "teaser")).toBeUndefined();

        // Verify both decrypt correctly
        for (const [name, expected] of [
            ["body", "Premium body"],
            ["sidebar", "Premium sidebar"],
        ] as const) {
            const ck = fromBase64Url(findKey(response, name).contentKey!);
            const entry = result.manifest.content[name];
            const decrypted = await decryptContent(
                fromBase64Url(entry.ciphertext),
                ck,
                fromBase64Url(entry.iv),
                encodeUtf8(entry.aad),
            );
            expect(decodeUtf8(decrypted)).toBe(expected);
        }
    });

    it("unlocks with grantedKeyNames", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "v2kn.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "v2kn-article",
            contentItems: [
                { contentName: "body", scope: "premium", content: "v2 premium" },
                { contentName: "extra", scope: "premium", content: "v2 extra" },
            ],
            issuers: [{
                issuerName: "v2kn-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "v2kn-1",
                unlockUrl: "https://v2kn.test/unlock",
                scopes: ["premium"],
            }],
        });

        const issuer = createDcaIssuer({
            issuerName: "v2kn-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "v2kn-1",
            trustedPublisherKeys: {
                "v2kn.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // scope resolution uses the scope field on each entry
        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["v2kn-issuer"].keys,
            },
            { grantedScopes: ["premium"], deliveryMode: "direct" },
        );

        expect(response.keys.map(k => k.contentName).sort()).toEqual(["body", "extra"]);

        const ck = fromBase64Url(findKey(response, "body").contentKey!);
        const entry = result.manifest.content["body"];
        const decrypted = await decryptContent(
            fromBase64Url(entry.ciphertext),
            ck,
            fromBase64Url(entry.iv),
            encodeUtf8(entry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("v2 premium");
    });

    it("scope defaults to contentName when not explicitly set", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "nokm.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "nokm-article",
            contentItems: [
                { contentName: "bodytext", content: "Normal content" },
            ],
            issuers: [{
                issuerName: "nokm-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "nokm-1",
                unlockUrl: "https://nokm.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        // No explicit scope → defaults to contentName
        const entry = result.manifest.issuers["nokm-issuer"].keys[0];
        expect(entry.scope).toBe("bodytext");
    });

    it("share link token with scopes grants all matching content items", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "share-kn.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "share-kn-article",
            contentItems: [
                { contentName: "body", scope: "premium", content: "Share body" },
                { contentName: "sidebar", scope: "premium", content: "Share sidebar" },
                { contentName: "teaser", content: "Free" },
            ],
            issuers: [{
                issuerName: "skn-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "skn-1",
                unlockUrl: "https://skn.test/unlock",
                scopes: ["premium", "teaser"],
            }],
        });

        // Create share token with scopes
        const shareToken = await publisher.createShareLinkToken({
            resourceId: "share-kn-article",
            scopes: ["premium"],
        });

        const issuer = createDcaIssuer({
            issuerName: "skn-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "skn-1",
            trustedPublisherKeys: {
                "share-kn.example.com": keys.signingPems.publicKeyPem,
            },
        });

        const response = await issuer.unlockWithShareToken({
            resourceJWT: result.manifest.resourceJWT,
            keys: result.manifest.issuers["skn-issuer"].keys,
            shareToken,
        });

        // Should grant body + sidebar (scope "premium"), but not teaser
        expect(response.keys.map(k => k.contentName).sort()).toEqual(["body", "sidebar"]);
    });

    it("issuer config scopes selects correct content items for wrapping", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "sel.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "sel-article",
            contentItems: [
                { contentName: "body", scope: "premium", content: "Premium" },
                { contentName: "sidebar", scope: "premium", content: "Sidebar" },
                { contentName: "teaser", scope: "free", content: "Free" },
            ],
            issuers: [{
                issuerName: "premium-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "sel-1",
                unlockUrl: "https://sel.test/unlock",
                scopes: ["premium"], // only premium content
            }],
        });

        // Only body and sidebar should be sealed (both have scope "premium")
        const sealedNames = result.manifest.issuers["premium-issuer"].keys.map(k => k.contentName);
        expect(sealedNames.sort()).toEqual(["body", "sidebar"]);

        // "teaser" should not be in sealed data for this issuer
        expect(result.manifest.issuers["premium-issuer"].keys.find(k => k.contentName === "teaser")).toBeUndefined();
    });

    it("grantedScopes resolves via entry scope (defaults to contentName)", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "fb.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        // No explicit scope → defaults to contentName "bodytext"
        const result = await publisher.render({
            resourceId: "fb-article",
            contentItems: [
                { contentName: "bodytext", content: "Fallback content" },
            ],
            issuers: [{
                issuerName: "fb-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "fb-1",
                unlockUrl: "https://fb.test/unlock",
                contentNames: ["bodytext"],
            }],
        });

        // Verify entry has scope defaulted to contentName
        const entry = result.manifest.issuers["fb-issuer"].keys[0];
        expect(entry.scope).toBe("bodytext");

        const issuer = createDcaIssuer({
            issuerName: "fb-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "fb-1",
            trustedPublisherKeys: {
                "fb.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // grantedScopes resolves via entry.scope
        const response = await issuer.unlock(
            {
                resourceJWT: result.manifest.resourceJWT,
                keys: result.manifest.issuers["fb-issuer"].keys,
            },
            { grantedScopes: ["bodytext"], deliveryMode: "direct" },
        );

        expect(findKey(response, "bodytext").contentKey).toBeDefined();

        const ck = fromBase64Url(findKey(response, "bodytext").contentKey!);
        const contentEntry = result.manifest.content["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(contentEntry.ciphertext),
            ck,
            fromBase64Url(contentEntry.iv),
            encodeUtf8(contentEntry.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("Fallback content");
    });

    it("rejects cross-tier key substitution (scope AAD binding)", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "aad.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            rotationSecret: keys.rotationSecret,
        });

        const result = await publisher.render({
            resourceId: "aad-article",
            contentItems: [
                { contentName: "body", scope: "premium", content: "Premium body" },
                { contentName: "teaser", scope: "free", content: "Free teaser" },
            ],
            issuers: [{
                issuerName: "aad-issuer",
                publicKeyPem: keys.issuerEcdhPems.publicKeyPem,
                keyId: "aad-1",
                unlockUrl: "https://aad.test/unlock",
                scopes: ["premium", "free"],
            }],
        });

        const issuer = createDcaIssuer({
            issuerName: "aad-issuer",
            privateKeyPem: keys.issuerEcdhPems.privateKeyPem,
            keyId: "aad-1",
            trustedPublisherKeys: {
                "aad.example.com": keys.signingPems.publicKeyPem,
            },
        });

        // Tamper: swap the "free" entry's scope to "premium" to try to get it unsealed
        const entries = result.manifest.issuers["aad-issuer"].keys;
        const tamperedEntries = entries.map(e =>
            e.contentName === "teaser" ? { ...e, scope: "premium" } : e,
        );

        // Unseal should fail — the sealed bytes were AAD-bound to "free", not "premium"
        await expect(
            issuer.unlock(
                {
                    resourceJWT: result.manifest.resourceJWT,
                    keys: tamperedEntries,
                },
                { grantedScopes: ["premium"], deliveryMode: "direct" },
            ),
        ).rejects.toThrow();
    });
});
