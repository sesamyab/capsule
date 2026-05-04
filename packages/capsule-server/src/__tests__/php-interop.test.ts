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
import type { DcaShareLinkTokenPayload } from "../dca-types";

const FIXTURE_DIR = resolve(__dirname, "../../../capsule-publisher-php/tests/fixtures");

interface ManifestFixture {
  resourceId: string;
  plaintext: string;
  issuerName: string;
  issuerAlgorithm: "ECDH-P256" | "RSA-OAEP";
  manifest: any;
}

// Skip if the PHP renderer hasn't been run yet — keep this test deterministic
// for `pnpm test` runs in CI while still being useful for local interop checks.
const keysPath = resolve(FIXTURE_DIR, "keys.json");
const phpEcdhPath = resolve(FIXTURE_DIR, "php-rendered-manifest-ecdh.json");
const phpRsaPath = resolve(FIXTURE_DIR, "php-rendered-manifest-rsa.json");
const phpShareTokensPath = resolve(FIXTURE_DIR, "php-rendered-share-tokens.json");
const phpRichPath = resolve(FIXTURE_DIR, "php-rendered-manifest-rich.json");
const fixturesPresent = [keysPath, phpEcdhPath, phpRsaPath].every(existsSync);
const extendedFixturesPresent =
  fixturesPresent && [phpShareTokensPath, phpRichPath].every(existsSync);

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

describe.skipIf(!extendedFixturesPresent)("PHP-rendered share tokens & rich manifest round-trip through JS", () => {
  const keys = extendedFixturesPresent ? readJson<KeysFixture>(keysPath) : ({} as KeysFixture);

  interface PhpShareTokenFixture {
    domain: string;
    resourceId: string;
    signingKid: string;
    tokens: { contentNames: string; scopes: string };
  }

  it("share tokens (contentNames + scopes variants) verify under publisher signing key", async () => {
    const f = readJson<PhpShareTokenFixture>(phpShareTokensPath);

    // contentNames variant: full claim shape, including data + maxUses.
    const namesPayload = await verifyJwt<DcaShareLinkTokenPayload & { data?: unknown; maxUses?: number }>(
      f.tokens.contentNames,
      keys.publisherSigningPublicKeyPem,
    );
    expect(namesPayload.type).toBe("dca-share");
    expect(namesPayload.domain).toBe(f.domain);
    expect(namesPayload.resourceId).toBe(f.resourceId);
    expect(namesPayload.contentNames).toEqual(["bodytext"]);
    expect(namesPayload.maxUses).toBe(5);
    expect(namesPayload.data).toEqual({ campaign: "fall" });
    expect(namesPayload.exp).toBe(namesPayload.iat + 3600);

    // scopes variant: scopes set, contentNames absent or empty in the payload.
    const scopesPayload = await verifyJwt<DcaShareLinkTokenPayload & { scopes?: string[] }>(
      f.tokens.scopes,
      keys.publisherSigningPublicKeyPem,
    );
    expect(scopesPayload.scopes).toEqual(["premium"]);
    expect(scopesPayload.exp).toBe(scopesPayload.iat + 7200);
    // PHP omits contentNames entirely when scopes are used (cf. JS, which sets [])
    // — both shapes are accepted by the issuer's verifyShareToken (one-of check).
    expect(
      scopesPayload.contentNames === undefined ||
        (Array.isArray(scopesPayload.contentNames) && scopesPayload.contentNames.length === 0),
    ).toBe(true);
  });

  interface PhpRichFixture {
    resourceId: string;
    plaintext: string;
    sidebarPlaintext: string;
    primary: { issuerName: string; keyId: string; privateKeyPem: string };
    secondary: { issuerName: string; keyId: string; privateKeyPem: string };
    expectedResourceData: any;
    manifest: any;
  }

  it("rich manifest: resourceData passes through, multi-issuer + name-granular both unwrap", async () => {
    const f = readJson<PhpRichFixture>(phpRichPath);

    // resourceJWT must verify under the publisher signing key, and resourceData passes through.
    const resourcePayload = await verifyJwt<{ sub: string; data: unknown }>(
      f.manifest.resourceJWT,
      keys.publisherSigningPublicKeyPem,
    );
    expect(resourcePayload.sub).toBe(f.resourceId);
    expect(resourcePayload.data).toEqual(f.expectedResourceData);

    // Primary issuer (scope mode): wraps both content items, has wrapKeys.
    const primary = f.manifest.issuers[f.primary.issuerName];
    const primaryPriv = await importIssuerPrivateKey(f.primary.privateKeyPem, "ECDH-P256");
    const primaryBody = primary.keys.find((k: { contentName?: string }) => k.contentName === "bodytext");
    expect(primaryBody).toBeDefined();
    expect(primaryBody.wrapKeys?.length).toBe(2); // current + next kid

    const primaryContentKey = await unwrap(
      primaryBody.contentKey,
      primaryPriv.key,
      "ECDH-P256",
      encodeUtf8(primaryBody.scope),
    );
    const bodyEntry = f.manifest.content.bodytext;
    const bodyText = await decryptContent(
      fromBase64Url(bodyEntry.ciphertext),
      primaryContentKey,
      fromBase64Url(bodyEntry.iv),
      encodeUtf8(bodyEntry.aad),
    );
    expect(new TextDecoder().decode(bodyText)).toBe(f.plaintext);

    // wrapKey path: first wrapKey unwraps, then unwraps the matching wrappedContentKey.
    const wk = await unwrap(
      primaryBody.wrapKeys[0].key,
      primaryPriv.key,
      "ECDH-P256",
      encodeUtf8(primaryBody.scope),
    );
    const wrapped = bodyEntry.wrappedContentKey.find(
      (w: { kid: string }) => w.kid === primaryBody.wrapKeys[0].kid,
    );
    expect(wrapped).toBeDefined();
    const contentKeyFromWrap = await decryptContent(
      fromBase64Url(wrapped.ciphertext),
      wk,
      fromBase64Url(wrapped.iv),
    );
    expect(Array.from(contentKeyFromWrap)).toEqual(Array.from(primaryContentKey));

    // Secondary issuer (name-granular): only bodytext, no wrapKeys.
    const secondary = f.manifest.issuers[f.secondary.issuerName];
    expect(secondary.keys).toHaveLength(1);
    expect(secondary.keys[0].contentName).toBe("bodytext");
    expect(secondary.keys[0].wrapKeys).toBeUndefined();

    const secondaryPriv = await importIssuerPrivateKey(f.secondary.privateKeyPem, "ECDH-P256");
    const secondaryContentKey = await unwrap(
      secondary.keys[0].contentKey,
      secondaryPriv.key,
      "ECDH-P256",
      encodeUtf8(secondary.keys[0].scope),
    );
    const secBody = await decryptContent(
      fromBase64Url(bodyEntry.ciphertext),
      secondaryContentKey,
      fromBase64Url(bodyEntry.iv),
      encodeUtf8(bodyEntry.aad),
    );
    expect(new TextDecoder().decode(secBody)).toBe(f.plaintext);

    // Sidebar content: only the primary issuer wraps it (secondary is name-granular
    // for bodytext only). Exercise the second name-bound contentKey end-to-end so
    // multi-content scope manifests don't silently regress for non-bodytext items.
    const primarySidebar = primary.keys.find(
      (k: { contentName?: string }) => k.contentName === "sidebar",
    );
    expect(primarySidebar).toBeDefined();
    const sidebarContentKey = await unwrap(
      primarySidebar.contentKey,
      primaryPriv.key,
      "ECDH-P256",
      encodeUtf8(primarySidebar.scope),
    );
    const sidebarEntry = f.manifest.content.sidebar;
    const sidebarBytes = await decryptContent(
      fromBase64Url(sidebarEntry.ciphertext),
      sidebarContentKey,
      fromBase64Url(sidebarEntry.iv),
      encodeUtf8(sidebarEntry.aad),
    );
    expect(new TextDecoder().decode(sidebarBytes)).toBe(f.sidebarPlaintext);
  });
});

describe.skipIf(fixturesPresent)("PHP interop fixtures missing", () => {
  it("explains how to generate them", () => {
    console.warn(
      "Skipping PHP interop tests. Generate fixtures with:\n" +
        "  pnpm --filter @sesamy/capsule-server build\n" +
        "  node packages/capsule-server/scripts/emit-php-test-vectors.mjs\n" +
        "  php packages/capsule-publisher-php/scripts/render-fixture.php",
    );
    expect(true).toBe(true);
  });
});
