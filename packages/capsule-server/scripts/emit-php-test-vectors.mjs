#!/usr/bin/env node
/**
 * Emit interop fixtures for the PHP capsule-publisher package.
 *
 * Writes pinned keys + JS-computed test vectors + a JS-rendered DCA manifest
 * into ../capsule-publisher-php/tests/fixtures/ so the PHP suite can verify
 * its primitives match the JS implementation byte-for-byte without a Node
 * runtime at PHP test time.
 *
 * Re-run after any change to the wire format or to the underlying primitives:
 *
 *     pnpm --filter @sesamy/capsule-server build
 *     node packages/capsule-server/scripts/emit-php-test-vectors.mjs
 *
 * Imports from dist/ to avoid needing tsx in the workspace.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto as nodeCrypto } from "node:crypto";

import {
    createDcaPublisher,
    buildPublisherJwk,
    deriveWrapKey,
    hkdf,
    toBase64Url,
    generateEcdsaP256KeyPair,
    generateEcdhP256KeyPair,
    exportP256KeyPairPem,
} from "../dist/index.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = resolve(__dirname, "../../capsule-publisher-php/tests/fixtures");

mkdirSync(FIXTURES_DIR, { recursive: true });

function hex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

async function generateRsaPemPair() {
    const kp = await nodeCrypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
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

function writeJson(filename, data) {
    const path = resolve(FIXTURES_DIR, filename);
    writeFileSync(path, JSON.stringify(data, null, 2) + "\n");
    console.log(`  wrote ${path}`);
}

// ----------------------------------------------------------------------------
// 1. Pinned keys — both sides use these so the manifests round-trip.
// ----------------------------------------------------------------------------

const signing = await generateEcdsaP256KeyPair();
const signingPem = await exportP256KeyPairPem(signing.privateKey, signing.publicKey);
const SIGNING_KID = "sign-2025-10";

const ecdhIssuer = await generateEcdhP256KeyPair();
const ecdhIssuerPem = await exportP256KeyPairPem(ecdhIssuer.privateKey, ecdhIssuer.publicKey);
const ECDH_ISSUER_KID = "iss-ecdh-1";

const rsaIssuerPem = await generateRsaPemPair();
const RSA_ISSUER_KID = "iss-rsa-1";

const ROTATION_SECRET_BYTES = nodeCrypto.getRandomValues(new Uint8Array(32));
const ROTATION_SECRET_B64 = Buffer.from(ROTATION_SECRET_BYTES).toString("base64");
const DOMAIN = "interop.example.com";

writeJson("keys.json", {
    domain: DOMAIN,
    rotationSecretBase64: ROTATION_SECRET_B64,
    signingKid: SIGNING_KID,
    publisherSigningPrivateKeyPem: signingPem.privateKeyPem,
    publisherSigningPublicKeyPem: signingPem.publicKeyPem,
    ecdhIssuerKid: ECDH_ISSUER_KID,
    ecdhIssuerPrivateKeyPem: ecdhIssuerPem.privateKeyPem,
    ecdhIssuerPublicKeyPem: ecdhIssuerPem.publicKeyPem,
    rsaIssuerKid: RSA_ISSUER_KID,
    rsaIssuerPrivateKeyPem: rsaIssuerPem.privateKeyPem,
    rsaIssuerPublicKeyPem: rsaIssuerPem.publicKeyPem,
});

// ----------------------------------------------------------------------------
// 2. HKDF vectors — sanity-check PHP's hash_hkdf wraps it correctly for
//    inputs the publisher actually hits.
// ----------------------------------------------------------------------------

const hkdfVectors = [];
const ikms = [
    new Uint8Array(32),
    nodeCrypto.getRandomValues(new Uint8Array(32)),
    nodeCrypto.getRandomValues(new Uint8Array(64)),
];
const cases = [
    { salt: "premium", info: "dca|251023T13", length: 32 },
    { salt: "free", info: "dca|251023T13", length: 32 },
    { salt: "dca-wrap", info: "dca-wrap-aes256gcm", length: 32 },
];
for (let i = 0; i < ikms.length; i++) {
    for (const c of cases) {
        const okm = await hkdf(ikms[i], c.salt, c.info, c.length);
        hkdfVectors.push({
            ikmHex: hex(ikms[i]),
            salt: c.salt,
            info: c.info,
            length: c.length,
            okmHex: hex(okm),
        });
    }
}
writeJson("hkdf.json", hkdfVectors);

// ----------------------------------------------------------------------------
// 3. deriveWrapKey vectors — exercises HKDF + the publisher's input shape.
// ----------------------------------------------------------------------------

const wrapKeyVectors = [];
for (const scope of ["premium", "free", "tier-a"]) {
    for (const kid of ["251023T13", "251023T14", "260101T00"]) {
        const wk = await deriveWrapKey(ROTATION_SECRET_BYTES, scope, kid);
        wrapKeyVectors.push({
            rotationSecretHex: hex(ROTATION_SECRET_BYTES),
            scope,
            kid,
            wrapKeyHex: hex(wk),
        });
    }
}
writeJson("derive-wrap-key.json", wrapKeyVectors);

// ----------------------------------------------------------------------------
// 4. Publisher JWK — PHP must emit byte-equal JWK for the same PEM + kid.
// ----------------------------------------------------------------------------

const jwk = await buildPublisherJwk({
    publicKeyPem: signingPem.publicKeyPem,
    kid: SIGNING_KID,
});
writeJson("publisher-jwk.json", {
    inputPublicKeyPem: signingPem.publicKeyPem,
    inputKid: SIGNING_KID,
    expectedJwk: jwk,
});

// ----------------------------------------------------------------------------
// 5. JS-rendered manifests — PHP unwraps these with the matching issuer keys
//    to confirm wire-format compatibility in the JS → PHP direction.
// ----------------------------------------------------------------------------

const RESOURCE_ID = "article-interop-1";
const PLAINTEXT = "<p>Premium body — interop fixture</p>";

const ecdhPublisher = createDcaPublisher({
    domain: DOMAIN,
    signingKeyPem: signingPem.privateKeyPem,
    signingKeyId: SIGNING_KID,
    rotationSecret: ROTATION_SECRET_B64,
});
const ecdhResult = await ecdhPublisher.render({
    resourceId: RESOURCE_ID,
    contentItems: [{ contentName: "bodytext", scope: "premium", content: PLAINTEXT }],
    issuers: [{
        issuerName: "interop",
        publicKeyPem: ecdhIssuerPem.publicKeyPem,
        keyId: ECDH_ISSUER_KID,
        unlockUrl: "https://issuer.example/unlock",
        scopes: ["premium"],
    }],
});
writeJson("js-rendered-manifest-ecdh.json", {
    resourceId: RESOURCE_ID,
    plaintext: PLAINTEXT,
    issuerName: "interop",
    issuerAlgorithm: "ECDH-P256",
    manifest: ecdhResult.manifest,
});

const rsaPublisher = createDcaPublisher({
    domain: DOMAIN,
    signingKeyPem: signingPem.privateKeyPem,
    signingKeyId: SIGNING_KID,
    rotationSecret: ROTATION_SECRET_B64,
});
const rsaResult = await rsaPublisher.render({
    resourceId: RESOURCE_ID,
    contentItems: [{ contentName: "bodytext", scope: "premium", content: PLAINTEXT }],
    issuers: [{
        issuerName: "interop",
        publicKeyPem: rsaIssuerPem.publicKeyPem,
        keyId: RSA_ISSUER_KID,
        unlockUrl: "https://issuer.example/unlock",
        scopes: ["premium"],
    }],
});
writeJson("js-rendered-manifest-rsa.json", {
    resourceId: RESOURCE_ID,
    plaintext: PLAINTEXT,
    issuerName: "interop",
    issuerAlgorithm: "RSA-OAEP",
    manifest: rsaResult.manifest,
});

console.log("Done.");
