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
    sealEcdhP256,
    unsealEcdhP256,
    importIssuerPublicKey,
    importIssuerPrivateKey,
} from "../dca-seal";
import {
    formatTimeBucket,
    getCurrentTimeBuckets,
    deriveDcaPeriodKey,
    generateRenderId,
} from "../dca-time-buckets";
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
} from "../web-crypto";
import { encryptContent, decryptContent, generateContentKey } from "../encryption";

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

    // Period secret
    const periodSecret = generateAesKeyBytes();

    return {
        signingPems,
        issuerEcdhPems,
        periodSecret,
    };
}

// ============================================================================
// 1. AAD in AES-GCM
// ============================================================================

describe("AAD in AES-GCM", () => {
    it("encrypts and decrypts with AAD", async () => {
        const key = generateContentKey();
        const plaintext = "Hello, DCA with AAD!";
        const aad = encodeUtf8("example.com|article-1|bodytext|1");

        const { encryptedContent, iv } = await encryptContent(plaintext, key, undefined, aad);
        const decrypted = await decryptContent(encryptedContent, key, iv, aad);

        expect(decodeUtf8(decrypted)).toBe(plaintext);
    });

    it("decryption fails with wrong AAD", async () => {
        const key = generateContentKey();
        const plaintext = "Secret content";
        const aad = encodeUtf8("example.com|article-1|bodytext|1");
        const wrongAad = encodeUtf8("evil.com|article-1|bodytext|1");

        const { encryptedContent, iv } = await encryptContent(plaintext, key, undefined, aad);

        await expect(decryptContent(encryptedContent, key, iv, wrongAad)).rejects.toThrow();
    });

    it("decryption fails without AAD when AAD was used", async () => {
        const key = generateContentKey();
        const plaintext = "Secret content";
        const aad = encodeUtf8("example.com|article-1|bodytext|1");

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
        const sealed = await sealEcdhP256(originalKey, pubKey);

        // Sealed blob should be a non-empty base64url string
        expect(sealed.length).toBeGreaterThan(0);
        expect(sealed).toMatch(/^[A-Za-z0-9_-]+$/);

        const unsealed = await unsealEcdhP256(sealed, privKey);
        expect(unsealed).toEqual(originalKey);
    });

    it("different seals produce different ciphertexts (ephemeral keys)", async () => {
        const keyPair = await generateEcdhP256KeyPair();
        const pems = await exportP256KeyPairPem(keyPair.privateKey, keyPair.publicKey);
        const { key: pubKey } = await importIssuerPublicKey(pems.publicKeyPem, "ECDH-P256");

        const originalKey = generateAesKeyBytes();
        const sealed1 = await sealEcdhP256(originalKey, pubKey);
        const sealed2 = await sealEcdhP256(originalKey, pubKey);

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
        await expect(unsealEcdhP256(tooShort, privKey)).rejects.toThrow(
            /Invalid ECDH-P256 sealed blob: expected at least 93 bytes, got 92/,
        );

        // Empty blob
        const empty = toBase64Url(new Uint8Array(0));
        await expect(unsealEcdhP256(empty, privKey)).rejects.toThrow(
            /Invalid ECDH-P256 sealed blob: expected at least 93 bytes, got 0/,
        );

        // Just below threshold (header only)
        const headerOnly = toBase64Url(new Uint8Array(65));
        await expect(unsealEcdhP256(headerOnly, privKey)).rejects.toThrow(
            /Invalid ECDH-P256 sealed blob: expected at least 93 bytes, got 65/,
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
        expect(formatTimeBucket(date)).toBe("251023T13");
    });

    it("formats sub-hour buckets as YYMMDDTHHMM", () => {
        const date = new Date("2025-10-23T14:30:00Z");
        expect(formatTimeBucket(date, true)).toBe("251023T1430");
    });

    it("returns current and next bucket", () => {
        const now = new Date("2025-10-23T13:45:00Z");
        const buckets = getCurrentTimeBuckets(1, now);

        expect(buckets.current.t).toBe("251023T13");
        expect(buckets.next.t).toBe("251023T14");
    });

    it("derives content-specific period keys", async () => {
        const secret = generateAesKeyBytes();

        const key1 = await deriveDcaPeriodKey(secret, "bodytext", "251023T13");
        const key2 = await deriveDcaPeriodKey(secret, "sidebar", "251023T13");
        const key3 = await deriveDcaPeriodKey(secret, "bodytext", "251023T14");

        // Same content name + same time bucket → same key
        const key1b = await deriveDcaPeriodKey(secret, "bodytext", "251023T13");
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
            periodSecret: keys.periodSecret,
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
        expect(result.dcaData.version).toBe("1");
        expect(result.dcaData.resource.domain).toBe("example.com");
        expect(result.dcaData.resource.resourceId).toBe("article-1");
        expect(result.dcaData.resource.data).toEqual({ section: "politics" });
        expect(result.dcaData.contentSealData["bodytext"]).toBeDefined();
        expect(result.dcaData.sealedContentKeys["bodytext"]).toHaveLength(2); // current + next period
        expect(result.dcaData.issuerData["test-issuer"]).toBeDefined();
        expect(result.dcaData.issuerJWT["test-issuer"]).toBeDefined();
        expect(result.sealedContent["bodytext"]).toBeDefined();

        // Verify HTML output
        expect(result.html.dcaDataScript).toContain('<script type="application/json" class="dca-data">');
        expect(result.html.sealedContentTemplate).toContain('<template class="dca-sealed-content">');
        expect(result.html.sealedContentTemplate).toContain('data-dca-content-name="bodytext"');

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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["test-issuer"],
                sealed: result.dcaData.issuerData["test-issuer"].sealed,
                keyId: "key-1",
                issuerName: "test-issuer",
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
        );

        expect(unlockResponse.keys["bodytext"]).toBeDefined();
        expect(unlockResponse.keys["bodytext"].contentKey).toBeDefined();

        // --- Client-side decryption ---
        const contentKeyBytes = fromBase64Url(unlockResponse.keys["bodytext"].contentKey!);
        const sealData = result.dcaData.contentSealData["bodytext"];
        const iv = fromBase64Url(sealData.nonce);
        const aad = encodeUtf8(sealData.aad);
        const ciphertext = fromBase64Url(result.sealedContent["bodytext"]);

        const decrypted = await decryptContent(ciphertext, contentKeyBytes, iv, aad);
        expect(decodeUtf8(decrypted)).toBe("<p>Premium content</p>");
    });

    it("publishes and decrypts multiple content items", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "multi.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
        expect(Object.keys(result.dcaData.contentSealData)).toEqual(["body", "sidebar", "data"]);
        expect(result.dcaData.contentSealData["data"].contentType).toBe("application/json");

        // Check that each content item has its own nonce
        const bodyNonce = result.dcaData.contentSealData["body"].nonce;
        const sidebarNonce = result.dcaData.contentSealData["sidebar"].nonce;
        expect(bodyNonce).not.toBe(sidebarNonce);

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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["multi-issuer"],
                sealed: result.dcaData.issuerData["multi-issuer"].sealed,
                keyId: "mk-1",
                issuerName: "multi-issuer",
            },
            { grantedContentNames: ["body", "sidebar", "data"], deliveryMode: "contentKey" },
        );

        // Decrypt each content item
        for (const [name, expectedContent] of [
            ["body", "Main article body"],
            ["sidebar", "Premium sidebar content"],
            ["data", '{"key":"value"}'],
        ]) {
            const contentKey = fromBase64Url(response.keys[name].contentKey!);
            const seal = result.dcaData.contentSealData[name];
            const decrypted = await decryptContent(
                fromBase64Url(result.sealedContent[name]),
                contentKey,
                fromBase64Url(seal.nonce),
                encodeUtf8(seal.aad),
            );
            expect(decodeUtf8(decrypted)).toBe(expectedContent);
        }
    });

    it("supports periodKey delivery mode", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "period.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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

        // Request periodKeys instead of contentKey
        const response = await issuer.unlock(
            {
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["pk-issuer"],
                sealed: result.dcaData.issuerData["pk-issuer"].sealed,
                keyId: "pk-1",
                issuerName: "pk-issuer",
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "periodKey" },
        );

        expect(response.keys["bodytext"].periodKeys).toBeDefined();
        const periodKeys = response.keys["bodytext"].periodKeys!;
        expect(Object.keys(periodKeys).length).toBe(2); // current + next

        // Unwrap contentKey from sealedContentKeys using a periodKey
        const sealedEntries = result.dcaData.sealedContentKeys["bodytext"];
        let contentKeyBytes: Uint8Array | null = null;

        for (const entry of sealedEntries) {
            const periodKeyB64 = periodKeys[entry.t];
            if (!periodKeyB64) continue;

            const periodKeyBytes = fromBase64Url(periodKeyB64);
            const nonce = fromBase64Url(entry.nonce);
            const wrappedKey = fromBase64Url(entry.key);

            contentKeyBytes = await aesGcmDecrypt(wrappedKey, periodKeyBytes, nonce);
            break;
        }

        expect(contentKeyBytes).not.toBeNull();

        // Decrypt content
        const sealData = result.dcaData.contentSealData["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(result.sealedContent["bodytext"]),
            contentKeyBytes!,
            fromBase64Url(sealData.nonce),
            encodeUtf8(sealData.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("Period key content");
    });

    it("issuer rejects tampered sealed blobs", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "tamper.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
        const tamperedSealed = { ...result.dcaData.issuerData["tamper-issuer"].sealed };
        tamperedSealed["bodytext"] = {
            ...tamperedSealed["bodytext"],
            contentKey: toBase64Url(generateAesKeyBytes()), // random blob
        };

        await expect(
            issuer.unlock(
                {
                    resource: result.dcaData.resource,
                    resourceJWT: result.dcaData.resourceJWT,
                    issuerJWT: result.dcaData.issuerJWT["tamper-issuer"],
                    sealed: tamperedSealed,
                    keyId: "t-1",
                    issuerName: "tamper-issuer",
                },
                { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
            ),
        ).rejects.toThrow("Integrity failure");
    });

    it("issuer rejects unknown publisher domain", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "unknown.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                    resource: result.dcaData.resource,
                    resourceJWT: result.dcaData.resourceJWT,
                    issuerJWT: result.dcaData.issuerJWT["domain-issuer"],
                    sealed: result.dcaData.issuerData["domain-issuer"].sealed,
                    keyId: "d-1",
                    issuerName: "domain-issuer",
                },
                { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
            ),
        ).rejects.toThrow("Untrusted publisher domain");
    });

    it("issuer verify returns verified resource data", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "verify.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
            resource: result.dcaData.resource,
            resourceJWT: result.dcaData.resourceJWT,
            issuerJWT: result.dcaData.issuerJWT["verify-issuer"],
            sealed: result.dcaData.issuerData["verify-issuer"].sealed,
            keyId: "v-1",
            issuerName: "verify-issuer",
        });

        expect(verified.resource.resourceId).toBe("verify-test");
        expect(verified.resource.domain).toBe("verify.example.com");
        expect(verified.resource.data).toEqual({ section: "politics" });
        expect(verified.issuerPayload.issuerName).toBe("verify-issuer");
    });

    it("JSON API response includes all fields", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "json.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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

        // JSON response should have all DCA data fields plus sealedContent
        const json = result.json;
        expect(json.version).toBe("1");
        expect(json.sealedContent["bodytext"]).toBeDefined();
        expect(json.resource).toBeDefined();
        expect(json.resourceJWT).toBeDefined();
        expect(json.issuerJWT).toBeDefined();
        expect(json.contentSealData).toBeDefined();
        expect(json.sealedContentKeys).toBeDefined();
        expect(json.issuerData).toBeDefined();
    });

    it("AAD string follows the convention domain|resourceId|contentName|version", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "aad.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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

        expect(result.dcaData.contentSealData["bodytext"].aad).toBe("aad.example.com|aad-article|bodytext|1");
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
            periodSecret: keys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["case-issuer"],
                sealed: result.dcaData.issuerData["case-issuer"].sealed,
                keyId: "c-1",
                issuerName: "case-issuer",
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
        );

        expect(response.keys["bodytext"].contentKey).toBeDefined();
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
            periodSecret: keys.periodSecret,
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
                resource: allowed.dcaData.resource,
                resourceJWT: allowed.dcaData.resourceJWT,
                issuerJWT: allowed.dcaData.issuerJWT["constrained-issuer"],
                sealed: allowed.dcaData.issuerData["constrained-issuer"].sealed,
                keyId: "cr-1",
                issuerName: "constrained-issuer",
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
        );
        expect(response.keys["bodytext"].contentKey).toBeDefined();

        // Denied resource
        await expect(
            issuer.unlock(
                {
                    resource: denied.dcaData.resource,
                    resourceJWT: denied.dcaData.resourceJWT,
                    issuerJWT: denied.dcaData.issuerJWT["constrained-issuer"],
                    sealed: denied.dcaData.issuerData["constrained-issuer"].sealed,
                    keyId: "cr-1",
                    issuerName: "constrained-issuer",
                },
                { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
            ),
        ).rejects.toThrow(/not allowed to claim resourceId/);
    });

    it("supports allowedResourceIds with RegExp patterns", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "regex.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                resource: premium.dcaData.resource,
                resourceJWT: premium.dcaData.resourceJWT,
                issuerJWT: premium.dcaData.issuerJWT["regex-issuer"],
                sealed: premium.dcaData.issuerData["regex-issuer"].sealed,
                keyId: "rx-1",
                issuerName: "regex-issuer",
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
        );
        expect(response.keys["bodytext"].contentKey).toBeDefined();

        // "free-article-1" does NOT match
        await expect(
            issuer.unlock(
                {
                    resource: free.dcaData.resource,
                    resourceJWT: free.dcaData.resourceJWT,
                    issuerJWT: free.dcaData.issuerJWT["regex-issuer"],
                    sealed: free.dcaData.issuerData["regex-issuer"].sealed,
                    keyId: "rx-1",
                    issuerName: "regex-issuer",
                },
                { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
            ),
        ).rejects.toThrow(/not allowed to claim resourceId/);
    });

    it("plain string entries (backward compat) allow all resourceIds", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "compat.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["compat-issuer"],
                sealed: result.dcaData.issuerData["compat-issuer"].sealed,
                keyId: "co-1",
                issuerName: "compat-issuer",
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
        );

        expect(response.keys["bodytext"].contentKey).toBeDefined();
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
    async function rsaUnwrap(wrappedB64: string, privateKey: CryptoKey): Promise<Uint8Array> {
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
            periodSecret: keys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["cb-issuer"],
                sealed: result.dcaData.issuerData["cb-issuer"].sealed,
                keyId: "cb-1",
                issuerName: "cb-issuer",
                clientPublicKey: clientKeys.clientPublicKey,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
        );

        // Response signals client-bound transport
        expect(response.transport).toBe("client-bound");
        expect(response.keys["bodytext"].contentKey).toBeDefined();

        // The contentKey in the response is RSA-OAEP wrapped — NOT the raw key
        const wrappedCK = response.keys["bodytext"].contentKey!;
        // RSA-2048 ciphertext is 256 bytes → 344 base64url chars (much larger than 43)
        expect(wrappedCK.length).toBeGreaterThan(100);

        // --- Client-side: RSA unwrap + AES-GCM decrypt ---
        const contentKeyBytes = await rsaUnwrap(wrappedCK, clientKeys.privateKey);
        expect(contentKeyBytes.length).toBe(32); // AES-256 key

        const sealData = result.dcaData.contentSealData["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(result.sealedContent["bodytext"]),
            contentKeyBytes,
            fromBase64Url(sealData.nonce),
            encodeUtf8(sealData.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("<p>Client-bound content</p>");
    });

    it("periodKey mode: issuer wraps periodKeys with client public key", async () => {
        const keys = await generateTestKeys();
        const clientKeys = await generateClientKeyPair();

        const publisher = createDcaPublisher({
            domain: "cb-pk.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["cb-pk-issuer"],
                sealed: result.dcaData.issuerData["cb-pk-issuer"].sealed,
                keyId: "cbpk-1",
                issuerName: "cb-pk-issuer",
                clientPublicKey: clientKeys.clientPublicKey,
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "periodKey" },
        );

        expect(response.transport).toBe("client-bound");
        const periodKeys = response.keys["bodytext"].periodKeys!;
        expect(Object.keys(periodKeys).length).toBe(2);

        // RSA unwrap each periodKey, then AES-GCM unwrap contentKey
        const sealedEntries = result.dcaData.sealedContentKeys["bodytext"];
        let contentKeyBytes: Uint8Array | null = null;

        for (const entry of sealedEntries) {
            const wrappedPK = periodKeys[entry.t];
            if (!wrappedPK) continue;

            const periodKeyBytes = await rsaUnwrap(wrappedPK, clientKeys.privateKey);
            expect(periodKeyBytes.length).toBe(32);

            const nonce = fromBase64Url(entry.nonce);
            const wrappedCK = fromBase64Url(entry.key);

            contentKeyBytes = await aesGcmDecrypt(wrappedCK, periodKeyBytes, nonce);
            break;
        }

        expect(contentKeyBytes).not.toBeNull();

        const sealData = result.dcaData.contentSealData["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(result.sealedContent["bodytext"]),
            contentKeyBytes!,
            fromBase64Url(sealData.nonce),
            encodeUtf8(sealData.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("Period key CB content");
    });

    it("without clientPublicKey: direct transport (backward compatible)", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "direct.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["direct-issuer"],
                sealed: result.dcaData.issuerData["direct-issuer"].sealed,
                keyId: "d-1",
                issuerName: "direct-issuer",
                // no clientPublicKey
            },
            { grantedContentNames: ["bodytext"], deliveryMode: "contentKey" },
        );

        // No transport field (or undefined) means direct
        expect(response.transport).toBeUndefined();

        // Raw contentKey — 32 bytes = 43 base64url chars
        const ck = response.keys["bodytext"].contentKey!;
        expect(ck.length).toBe(43);

        // Verify it decrypts
        const contentKeyBytes = fromBase64Url(ck);
        const sealData = result.dcaData.contentSealData["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(result.sealedContent["bodytext"]),
            contentKeyBytes,
            fromBase64Url(sealData.nonce),
            encodeUtf8(sealData.aad),
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
            periodSecret: keys.periodSecret,
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
            resource: result.dcaData.resource,
            resourceJWT: result.dcaData.resourceJWT,
            issuerJWT: result.dcaData.issuerJWT["share-issuer"],
            sealed: result.dcaData.issuerData["share-issuer"].sealed,
            keyId: "sk-1",
            issuerName: "share-issuer",
            shareToken,
        });

        // Should return contentKey (default for share links)
        expect(response.keys["bodytext"]).toBeDefined();
        expect(response.keys["bodytext"].contentKey).toBeDefined();

        // Decrypt the content
        const contentKeyBytes = fromBase64Url(response.keys["bodytext"].contentKey!);
        const sealData = result.dcaData.contentSealData["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(result.sealedContent["bodytext"]),
            contentKeyBytes,
            fromBase64Url(sealData.nonce),
            encodeUtf8(sealData.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("<p>Shared premium content</p>");
    });

    it("share link token works with periodKey delivery mode", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "share-pk.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["share-pk-issuer"],
                sealed: result.dcaData.issuerData["share-pk-issuer"].sealed,
                keyId: "spk-1",
                issuerName: "share-pk-issuer",
                shareToken,
            },
            { deliveryMode: "periodKey" },
        );

        // Should return periodKeys
        expect(response.keys["bodytext"].periodKeys).toBeDefined();
        expect(response.keys["bodytext"].contentKey).toBeUndefined();

        // Unwrap contentKey from sealedContentKeys using periodKey
        const periodKeys = response.keys["bodytext"].periodKeys!;
        const sealedContentKeys = result.dcaData.sealedContentKeys["bodytext"];
        let contentKeyBytes: Uint8Array | null = null;

        for (const entry of sealedContentKeys) {
            const pkB64 = periodKeys[entry.t];
            if (!pkB64) continue;

            const periodKeyBytes = fromBase64Url(pkB64);
            const nonce = fromBase64Url(entry.nonce);
            const wrappedKey = fromBase64Url(entry.key);

            const decryptedKey = await aesGcmDecrypt(wrappedKey, periodKeyBytes, nonce);
            contentKeyBytes = decryptedKey;
            break;
        }

        expect(contentKeyBytes).not.toBeNull();

        // Decrypt content
        const sealData = result.dcaData.contentSealData["bodytext"];
        const decrypted = await decryptContent(
            fromBase64Url(result.sealedContent["bodytext"]),
            contentKeyBytes!,
            fromBase64Url(sealData.nonce),
            encodeUtf8(sealData.aad),
        );
        expect(decodeUtf8(decrypted)).toBe("Period key shared content");
    });

    it("rejects expired share link tokens", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "expire.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["expire-issuer"],
                sealed: result.dcaData.issuerData["expire-issuer"].sealed,
                keyId: "ek-1",
                issuerName: "expire-issuer",
                shareToken,
            }),
        ).rejects.toThrow(/expired/);
    });

    it("rejects share token for wrong resourceId", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "mismatch.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["mm-issuer"],
                sealed: result.dcaData.issuerData["mm-issuer"].sealed,
                keyId: "mm-1",
                issuerName: "mm-issuer",
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
            periodSecret: keys.periodSecret,
        });

        const evilPublisher = createDcaPublisher({
            domain: "trusted.example.com", // Claims to be trusted
            signingKeyPem: evilKeys.signingPems.privateKeyPem,
            periodSecret: evilKeys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["trust-issuer"],
                sealed: result.dcaData.issuerData["trust-issuer"].sealed,
                keyId: "tk-1",
                issuerName: "trust-issuer",
                shareToken: evilShareToken,
            }),
        ).rejects.toThrow(/signature/i);
    });

    it("rejects unlock when no shareToken provided", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "noshare.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["ns-issuer"],
                sealed: result.dcaData.issuerData["ns-issuer"].sealed,
                keyId: "ns-1",
                issuerName: "ns-issuer",
                // no shareToken
            }),
        ).rejects.toThrow(/shareToken/);
    });

    it("share token only grants specified content names", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "partial.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
            resource: result.dcaData.resource,
            resourceJWT: result.dcaData.resourceJWT,
            issuerJWT: result.dcaData.issuerJWT["partial-issuer"],
            sealed: result.dcaData.issuerData["partial-issuer"].sealed,
            keyId: "pk-1",
            issuerName: "partial-issuer",
            shareToken,
        });

        // Should only grant preview and bodytext
        expect(Object.keys(response.keys).sort()).toEqual(["bodytext", "preview"]);
        expect(response.keys["bonus"]).toBeUndefined();

        // Verify both decrypt correctly
        for (const [name, expected] of [
            ["preview", "Preview text"],
            ["bodytext", "Full body text"],
        ] as const) {
            const ck = fromBase64Url(response.keys[name].contentKey!);
            const seal = result.dcaData.contentSealData[name];
            const decrypted = await decryptContent(
                fromBase64Url(result.sealedContent[name]),
                ck,
                fromBase64Url(seal.nonce),
                encodeUtf8(seal.aad),
            );
            expect(decodeUtf8(decrypted)).toBe(expected);
        }
    });

    it("supports onShareToken callback for use-count tracking", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "callback.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                resource: result.dcaData.resource,
                resourceJWT: result.dcaData.resourceJWT,
                issuerJWT: result.dcaData.issuerJWT["cb-issuer"],
                sealed: result.dcaData.issuerData["cb-issuer"].sealed,
                keyId: "cb-1",
                issuerName: "cb-issuer",
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
        expect(response.keys["bodytext"].contentKey).toBeDefined();
    });

    it("onShareToken callback can reject the request", async () => {
        const keys = await generateTestKeys();

        const publisher = createDcaPublisher({
            domain: "reject.example.com",
            signingKeyPem: keys.signingPems.privateKeyPem,
            periodSecret: keys.periodSecret,
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
                    resource: result.dcaData.resource,
                    resourceJWT: result.dcaData.resourceJWT,
                    issuerJWT: result.dcaData.issuerJWT["rj-issuer"],
                    sealed: result.dcaData.issuerData["rj-issuer"].sealed,
                    keyId: "rj-1",
                    issuerName: "rj-issuer",
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
            periodSecret: keys.periodSecret,
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
