#!/usr/bin/env node
/**
 * Generate the **pinned**, never-regenerate cross-language interop fixtures.
 *
 * Run this once. Commit the resulting JSON files. Do NOT add this to
 * `run-interop.sh` — these fixtures are the static known-answer vectors that
 * catch lockstep refactors of both implementations. Re-running this would
 * silently absorb such drift.
 *
 * Output: packages/capsule-publisher-php/tests/fixtures/static/*.json
 *
 * To regenerate intentionally (e.g. wire format change), delete the files
 * and re-run:
 *
 *     pnpm --filter @sesamy/capsule-server build
 *     node packages/capsule-server/scripts/generate-static-fixtures.mjs
 */

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto as nodeCrypto } from "node:crypto";

import {
    buildPublisherJwk,
    deriveWrapKey,
    hkdf,
    wrapEcdhP256,
    unwrapEcdhP256,
    wrapRsaOaep,
    unwrapRsaOaep,
    importEcdhP256PublicKey,
    importEcdhP256PrivateKey,
    importRsaPublicKey,
    importRsaPrivateKey,
    exportP256KeyPairPem,
    generateEcdhP256KeyPair,
    generateEcdsaP256KeyPair,
} from "../dist/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = resolve(
    __dirname,
    "../../capsule-publisher-php/tests/fixtures/static",
);

mkdirSync(FIXTURE_DIR, { recursive: true });

function hex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(s) {
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    return out;
}

function writeJson(filename, data) {
    const path = resolve(FIXTURE_DIR, filename);
    if (existsSync(path)) {
        throw new Error(
            `${path} already exists. Refusing to overwrite a pinned fixture. ` +
                `Delete it intentionally if you really mean to regenerate.`,
        );
    }
    writeFileSync(path, JSON.stringify(data, null, 2) + "\n");
    console.log(`  wrote ${path}`);
}

// ----------------------------------------------------------------------------
// HKDF — pin OKM bytes for the (salt, info) shapes the publisher actually uses.
// ----------------------------------------------------------------------------
const HKDF_INPUTS = [
    {
        // Zero IKM — exercises the hardest edge case (HMAC over zero key)
        ikmHex: "00".repeat(32),
        salt: "premium",
        info: "dca|260101T00",
        length: 32,
    },
    {
        ikmHex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        salt: "free",
        info: "dca|251023T13",
        length: 32,
    },
    {
        // 64-byte IKM, longer than the SHA-256 block size
        ikmHex: "deadbeef".repeat(16),
        salt: "dca-wrap",
        info: "dca-wrap-aes256gcm",
        length: 32,
    },
    {
        ikmHex: "ff".repeat(32),
        salt: "tier-a",
        info: "dca|260501T15",
        length: 64,
    },
];

const hkdfVectors = [];
for (const v of HKDF_INPUTS) {
    const okm = await hkdf(fromHex(v.ikmHex), v.salt, v.info, v.length);
    hkdfVectors.push({ ...v, okmHex: hex(okm) });
}
writeJson("hkdf-vectors.json", hkdfVectors);

// ----------------------------------------------------------------------------
// deriveWrapKey — pin the publisher's HKDF input shape (salt = scope,
// info = "dca|" + kid). Uses a fixed rotationSecret across all rows so a
// drift in HKDF bridging or in the prefix string is caught.
// ----------------------------------------------------------------------------
const ROTATION_SECRET_HEX =
    "7b935ba21f8568200fa926385a759f5eb30c134480ba463e3975764f52c66ad8";
const ROTATION_SECRET = fromHex(ROTATION_SECRET_HEX);
const DERIVE_INPUTS = [
    { scope: "premium", kid: "260501T14" },
    { scope: "premium", kid: "260501T15" },
    { scope: "free", kid: "260101T00" },
    { scope: "tier-a", kid: "251023T13" },
];

const deriveVectors = [];
for (const v of DERIVE_INPUTS) {
    const wk = await deriveWrapKey(ROTATION_SECRET, v.scope, v.kid);
    deriveVectors.push({
        rotationSecretHex: ROTATION_SECRET_HEX,
        scope: v.scope,
        kid: v.kid,
        wrapKeyHex: hex(wk),
    });
}
writeJson("derive-wrap-key-vectors.json", deriveVectors);

// ----------------------------------------------------------------------------
// Publisher JWK — pin the EC PEM → JWK transformation. Generated once with
// real key material so the JWK has real x/y values; both sides verify they
// produce the same JWK from the same PEM.
// ----------------------------------------------------------------------------
const signing = await generateEcdsaP256KeyPair();
const signingPem = await exportP256KeyPairPem(signing.privateKey, signing.publicKey);
const SIGNING_KID = "static-sign-1";
const jwk = await buildPublisherJwk({
    publicKeyPem: signingPem.publicKeyPem,
    kid: SIGNING_KID,
});
writeJson("publisher-jwk-vector.json", {
    inputPublicKeyPem: signingPem.publicKeyPem,
    inputPrivateKeyPem: signingPem.privateKeyPem,
    inputKid: SIGNING_KID,
    expectedJwk: jwk,
});

// ----------------------------------------------------------------------------
// ECDH-P256 unwrap — pin a wrapped blob + its private key + AAD + plaintext.
// We pick the wrapping ourselves with `wrapEcdhP256`, but the test on each
// side just asserts that unwrap(blob, privateKey, aad) === plaintext.
// (RSA-OAEP is non-deterministic; ECDH wrap also uses a random ephemeral
// keypair; that's fine — what we pin is the (key, ciphertext, plaintext)
// equality, not the ciphertext bytes.)
// ----------------------------------------------------------------------------
const ecdhKeys = await generateEcdhP256KeyPair();
const ecdhPem = await exportP256KeyPairPem(ecdhKeys.privateKey, ecdhKeys.publicKey);
const ecdhPlaintext = nodeCrypto.getRandomValues(new Uint8Array(32));
const ecdhAad = "premium"; // matches the "scope as AAD" convention
const ecdhPub = await importEcdhP256PublicKey(ecdhPem.publicKeyPem);
const ecdhBlob = await wrapEcdhP256(
    ecdhPlaintext,
    ecdhPub,
    new TextEncoder().encode(ecdhAad),
);
// Round-trip self-check before pinning.
{
    const priv = await importEcdhP256PrivateKey(ecdhPem.privateKeyPem);
    const back = await unwrapEcdhP256(ecdhBlob, priv, new TextEncoder().encode(ecdhAad));
    if (hex(back) !== hex(ecdhPlaintext)) {
        throw new Error("ECDH self-check failed before pinning");
    }
}
writeJson("ecdh-unwrap-vector.json", {
    issuerPrivateKeyPem: ecdhPem.privateKeyPem,
    issuerPublicKeyPem: ecdhPem.publicKeyPem,
    aad: ecdhAad,
    wrappedBlob: ecdhBlob,
    expectedPlaintextHex: hex(ecdhPlaintext),
});

// ----------------------------------------------------------------------------
// RSA-OAEP unwrap — pin (privateKey, ciphertext, AAD, plaintext).
// ----------------------------------------------------------------------------
const rsa = await generateRsaPemPair();
const rsaPlaintext = nodeCrypto.getRandomValues(new Uint8Array(32));
const rsaAad = "premium";
const rsaPub = await importRsaPublicKey(rsa.publicKeyPem);
const rsaBlob = await wrapRsaOaep(
    rsaPlaintext,
    rsaPub,
    new TextEncoder().encode(rsaAad),
);
{
    const priv = await importRsaPrivateKey(rsa.privateKeyPem);
    const back = await unwrapRsaOaep(rsaBlob, priv, new TextEncoder().encode(rsaAad));
    if (hex(back) !== hex(rsaPlaintext)) {
        throw new Error("RSA self-check failed before pinning");
    }
}
writeJson("rsa-unwrap-vector.json", {
    issuerPrivateKeyPem: rsa.privateKeyPem,
    issuerPublicKeyPem: rsa.publicKeyPem,
    aad: rsaAad,
    wrappedBlob: rsaBlob,
    expectedPlaintextHex: hex(rsaPlaintext),
});

console.log("Done.");

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

async function generateRsaPemPair() {
    const kp = await nodeCrypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"],
    );
    const pubDer = new Uint8Array(await nodeCrypto.subtle.exportKey("spki", kp.publicKey));
    const privDer = new Uint8Array(await nodeCrypto.subtle.exportKey("pkcs8", kp.privateKey));
    return {
        publicKeyPem: derToPem(pubDer, "PUBLIC KEY"),
        privateKeyPem: derToPem(privDer, "PRIVATE KEY"),
    };
}

function derToPem(der, label) {
    const b64 = Buffer.from(der).toString("base64");
    const lines = b64.match(/.{1,64}/g).join("\n");
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}
