/**
 * PHP → JS interop test.
 *
 * Loads DCA manifests rendered by the PHP capsule-publisher package and
 * verifies the JS primitives can:
 *   1. Verify the resourceJWT signature with the matching publisher public key.
 *   2. Unwrap the issuer-wrapped contentKey (ECDH-P256 + RSA-OAEP paths).
 *   3. AES-GCM-decrypt the content body (with the bound AAD).
 *
 * If this passes, the WordPress plugin using the PHP publisher can talk to the
 * JS issuer service in production.
 *
 * Fixture refresh workflow (re-run after any wire-format change):
 *
 *     pnpm --filter @sesamy/capsule-server build                                # build dist/
 *     node packages/capsule-server/scripts/emit-php-test-vectors.mjs            # JS → PHP fixtures
 *     php packages/capsule-publisher-php/scripts/render-fixture.php             # PHP → JS fixtures
 *     pnpm --filter @sesamy/capsule-server test                                 # this file
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { decryptContent } from "../encryption";
import { verifyJwt } from "../dca-jwt";
import { unwrap, importIssuerPrivateKey } from "../dca-wrap";
import { fromBase64Url, encodeUtf8 } from "../web-crypto";

const FIXTURE_DIR = resolve(__dirname, "../../../capsule-publisher-php/tests/fixtures");

interface ManifestFixture {
  resourceId: string;
  plaintext: string;
  issuerName: string;
  issuerAlgorithm: "ECDH-P256" | "RSA-OAEP";
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  manifest: any;
}

// Skip if the PHP renderer hasn't been run yet — keep this test deterministic
// for `pnpm test` runs in CI while still being useful for local interop checks.
const keysPath = resolve(FIXTURE_DIR, "keys.json");
const phpEcdhPath = resolve(FIXTURE_DIR, "php-rendered-manifest-ecdh.json");
const phpRsaPath = resolve(FIXTURE_DIR, "php-rendered-manifest-rsa.json");
const fixturesPresent = [keysPath, phpEcdhPath, phpRsaPath].every(existsSync);

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf-8")) as T;
}

interface KeysFixture {
  domain: string;
  signingKid: string;
  publisherSigningPublicKeyPem: string;
  ecdhIssuerPrivateKeyPem: string;
  rsaIssuerPrivateKeyPem: string;
}

async function decryptManifestContent(
  manifest: ManifestFixture["manifest"],
  contentKey: Uint8Array,
  contentName: string,
): Promise<string> {
  const entry = manifest.content[contentName];
  const iv = fromBase64Url(entry.iv);
  const ciphertext = fromBase64Url(entry.ciphertext);
  const aad = encodeUtf8(entry.aad);
  const plaintext = await decryptContent(ciphertext, contentKey, iv, aad);
  return new TextDecoder().decode(plaintext);
}

describe.skipIf(!fixturesPresent)("PHP-rendered manifests round-trip through the JS issuer primitives", () => {
  const keys = fixturesPresent ? readJson<KeysFixture>(keysPath) : ({} as KeysFixture);

  it("ECDH-P256 manifest: verify resourceJWT, unwrap contentKey, decrypt body", async () => {
    const fixture = readJson<ManifestFixture>(phpEcdhPath);
    expect(fixture.issuerAlgorithm).toBe("ECDH-P256");

    // 1. resourceJWT signature.
    const payload = await verifyJwt<{ iss: string; sub: string }>(
      fixture.manifest.resourceJWT,
      keys.publisherSigningPublicKeyPem,
    );
    expect(payload.iss).toBe(keys.domain);
    expect(payload.sub).toBe(fixture.resourceId);

    // 2. Unwrap contentKey for the bodytext entry (scope-bound AAD).
    const issuerEntry = fixture.manifest.issuers[fixture.issuerName].keys[0];
    const issuerPriv = await importIssuerPrivateKey(keys.ecdhIssuerPrivateKeyPem, "ECDH-P256");
    const contentKey = await unwrap(
      issuerEntry.contentKey,
      issuerPriv.key,
      "ECDH-P256",
      encodeUtf8(issuerEntry.scope),
    );

    // 3. AES-GCM decrypt with content AAD.
    const decrypted = await decryptManifestContent(fixture.manifest, contentKey, "bodytext");
    expect(decrypted).toBe(fixture.plaintext);
  });

  it("RSA-OAEP manifest: verify resourceJWT, unwrap contentKey, decrypt body", async () => {
    const fixture = readJson<ManifestFixture>(phpRsaPath);
    expect(fixture.issuerAlgorithm).toBe("RSA-OAEP");

    const payload = await verifyJwt<{ iss: string; sub: string }>(
      fixture.manifest.resourceJWT,
      keys.publisherSigningPublicKeyPem,
    );
    expect(payload.iss).toBe(keys.domain);
    expect(payload.sub).toBe(fixture.resourceId);

    const issuerEntry = fixture.manifest.issuers[fixture.issuerName].keys[0];
    const issuerPriv = await importIssuerPrivateKey(keys.rsaIssuerPrivateKeyPem, "RSA-OAEP");
    const contentKey = await unwrap(
      issuerEntry.contentKey,
      issuerPriv.key,
      "RSA-OAEP",
      encodeUtf8(issuerEntry.scope),
    );

    const decrypted = await decryptManifestContent(fixture.manifest, contentKey, "bodytext");
    expect(decrypted).toBe(fixture.plaintext);
  });

  it("ECDH-P256 manifest: scope wrapKey unwraps and AES-unwraps the contentKey", async () => {
    const fixture = readJson<ManifestFixture>(phpEcdhPath);
    const issuerEntry = fixture.manifest.issuers[fixture.issuerName].keys[0];
    expect(issuerEntry.wrapKeys?.length ?? 0).toBeGreaterThan(0);

    const issuerPriv = await importIssuerPrivateKey(keys.ecdhIssuerPrivateKeyPem, "ECDH-P256");
    const wrapKey = await unwrap(
      issuerEntry.wrapKeys[0].key,
      issuerPriv.key,
      "ECDH-P256",
      encodeUtf8(issuerEntry.scope),
    );
    expect(wrapKey.byteLength).toBe(32);

    // The current-rotation wrapped contentKey for "bodytext" should unwrap with this wrapKey.
    const contentEntry = fixture.manifest.content.bodytext;
    const wrappedKid = issuerEntry.wrapKeys[0].kid as string;
    const wrappedEntry = (contentEntry.wrappedContentKey as { kid: string; iv: string; ciphertext: string }[])
      .find(e => e.kid === wrappedKid);
    expect(wrappedEntry).toBeDefined();

    const contentKey = await decryptContent(
      fromBase64Url(wrappedEntry!.ciphertext),
      wrapKey,
      fromBase64Url(wrappedEntry!.iv),
    );
    expect(contentKey.byteLength).toBe(32);

    const decrypted = await decryptManifestContent(fixture.manifest, contentKey, "bodytext");
    expect(decrypted).toBe(fixture.plaintext);
  });
});

describe.skipIf(fixturesPresent)("PHP interop fixtures missing", () => {
  it("explains how to generate them", () => {
    // eslint-disable-next-line no-console
    console.warn(
      "Skipping PHP interop tests. Generate fixtures with:\n" +
        "  pnpm --filter @sesamy/capsule-server build\n" +
        "  node packages/capsule-server/scripts/emit-php-test-vectors.mjs\n" +
        "  php packages/capsule-publisher-php/scripts/render-fixture.php",
    );
    expect(true).toBe(true);
  });
});
