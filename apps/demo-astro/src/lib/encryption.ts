/**
 * Server-side DCA encryption for the Astro demo.
 *
 * Uses createDcaPublisher + createDcaIssuer for all key operations.
 * Zero network calls — all key derivation is local.
 */

import {
  createDcaPublisher,
  createDcaIssuer,
} from "@sesamy/capsule-server";
import type { DcaRenderResult } from "@sesamy/capsule-server";

export type { DcaRenderResult };

type DcaPublisher = ReturnType<typeof createDcaPublisher>;
type DcaIssuerServer = ReturnType<typeof createDcaIssuer>;

// ── Constants ───────────────────────────────────────────────────────────
const DEMO_DOMAIN = "capsule-astro-demo.sesamy.com";
const DEMO_ISSUER_NAME = "sesamy-astro-demo";
const DEMO_KEY_ID = "astro-demo-2026";
const PERIOD_DURATION_HOURS = 1;

// ── Lazy singletons ────────────────────────────────────────────────────
let _publisher: DcaPublisher | null = null;
let _issuer: DcaIssuerServer | null = null;
let _issuerPublicKeyPem: string | null = null;

/**
 * Auto-generate P-256 key pairs when env vars aren't set (dev mode only).
 */
async function ensureKeys() {
  if (
    !process.env.PUBLISHER_ES256_PRIVATE_KEY &&
    import.meta.env.DEV
  ) {
    console.warn("[dca] Auto-generating P-256 keys for dev mode");

    const { webcrypto } = await import("node:crypto");
    const subtle = webcrypto.subtle;

    // Signing key (ECDSA P-256 / ES256)
    const signingPair = await subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const sigPriv = await subtle.exportKey("pkcs8", signingPair.privateKey);
    const sigPub = await subtle.exportKey("spki", signingPair.publicKey);
    process.env.PUBLISHER_ES256_PRIVATE_KEY = toPem(sigPriv, "PRIVATE KEY");
    process.env.PUBLISHER_ES256_PUBLIC_KEY = toPem(sigPub, "PUBLIC KEY");

    // Sealing key (ECDH P-256)
    const sealPair = await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
    const sealPriv = await subtle.exportKey("pkcs8", sealPair.privateKey);
    const sealPub = await subtle.exportKey("spki", sealPair.publicKey);
    process.env.ISSUER_ECDH_PRIVATE_KEY = toPem(sealPriv, "PRIVATE KEY");
    process.env.ISSUER_ECDH_PUBLIC_KEY = toPem(sealPub, "PUBLIC KEY");

    // Period secret
    if (!process.env.PERIOD_SECRET) {
      const bytes = new Uint8Array(32);
      webcrypto.getRandomValues(bytes);
      process.env.PERIOD_SECRET = Buffer.from(bytes).toString("base64");
    }
  }
}

function toPem(buf: ArrayBuffer, label: string): string {
  const b64 = Buffer.from(buf).toString("base64");
  const lines = b64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function env(name: string): string {
  const v = process.env[name] ?? (import.meta.env as Record<string, string>)[name];
  if (!v) throw new Error(`Missing environment variable: ${name}`);
  return v;
}

export async function getPublisher(): Promise<DcaPublisher> {
  if (!_publisher) {
    await ensureKeys();
    _publisher = createDcaPublisher({
      domain: DEMO_DOMAIN,
      signingKeyPem: env("PUBLISHER_ES256_PRIVATE_KEY"),
      periodSecret: env("PERIOD_SECRET"),
      periodDurationHours: PERIOD_DURATION_HOURS,
    });
  }
  return _publisher;
}

export async function getIssuer(): Promise<DcaIssuerServer> {
  if (!_issuer) {
    await ensureKeys();
    _issuer = createDcaIssuer({
      issuerName: DEMO_ISSUER_NAME,
      privateKeyPem: env("ISSUER_ECDH_PRIVATE_KEY"),
      keyId: DEMO_KEY_ID,
      trustedPublisherKeys: {
        [DEMO_DOMAIN]: {
          signingKeyPem: env("PUBLISHER_ES256_PUBLIC_KEY"),
        },
      },
    });
  }
  return _issuer;
}

export async function getIssuerPublicKeyPem(): Promise<string> {
  if (!_issuerPublicKeyPem) {
    await ensureKeys();
    _issuerPublicKeyPem = env("ISSUER_ECDH_PUBLIC_KEY");
  }
  return _issuerPublicKeyPem;
}

// ── Render cache ────────────────────────────────────────────────────────
interface CachedRender {
  data: DcaRenderResult;
  hourBucket: string;
}
const renderCache = new Map<string, CachedRender>();

function getCurrentHourBucket(): string {
  const now = new Date();
  return `${now.getUTCFullYear()}-${now.getUTCMonth()}-${now.getUTCDate()}-${now.getUTCHours()}`;
}

/**
 * Render a DCA-encrypted article.
 */
export async function renderDcaArticle(
  resourceId: string,
  content: string,
  contentName = "bodytext",
): Promise<DcaRenderResult> {
  const hourBucket = getCurrentHourBucket();
  const cached = renderCache.get(resourceId);
  if (cached && cached.hourBucket === hourBucket) return cached.data;

  const publisher = await getPublisher();
  const issuerPub = await getIssuerPublicKeyPem();

  const result = await publisher.render({
    resourceId,
    contentItems: [
      { contentName, content, contentType: "text/html" },
    ],
    issuers: [
      {
        issuerName: DEMO_ISSUER_NAME,
        publicKeyPem: issuerPub,
        keyId: DEMO_KEY_ID,
        unlockUrl: "/api/unlock",
        contentNames: [contentName],
      },
    ],
    resourceData: { title: resourceId },
  });

  renderCache.set(resourceId, { data: result, hourBucket });
  return result;
}

export { DEMO_ISSUER_NAME };
