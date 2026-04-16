/**
 * Server-side DCA encryption for the Astro demo.
 *
 * Uses createDcaPublisher + createDcaIssuer for all key operations.
 * Zero network calls — all key derivation is local.
 */

import {
  createDcaPublisher,
  createDcaIssuer,
  generateEcdsaP256KeyPair,
  generateEcdhP256KeyPair,
  exportP256KeyPairPem,
} from "@sesamy/capsule-server";
import type { DcaRenderResult } from "@sesamy/capsule-server";

export type { DcaRenderResult };

type DcaPublisher = ReturnType<typeof createDcaPublisher>;
type DcaIssuerServer = ReturnType<typeof createDcaIssuer>;

// ── Constants ───────────────────────────────────────────────────────────
const DEMO_DOMAIN = "capsule-astro-demo.sesamy.com";
const DEMO_ISSUER_NAME = "sesamy-astro-demo";
const DEMO_KEY_ID = "astro-demo-2026";
const ROTATION_INTERVAL_HOURS = 1;

const DEV_FALLBACK_SECRET = Buffer.from(
  "demo-secret-do-not-use-in-production!!",
  "utf-8",
).toString("base64");

// ── Lazy singletons ────────────────────────────────────────────────────
let _publisher: DcaPublisher | null = null;
let _issuer: DcaIssuerServer | null = null;
let _issuerPublicKeyPem: string | null = null;

// ---------------------------------------------------------------------------
// Secret helpers
// ---------------------------------------------------------------------------

let _rotationSecret: string | undefined;

function getRotationSecret(): string {
  if (_rotationSecret) return _rotationSecret;
  const secret = process.env.ROTATION_SECRET ?? process.env.PERIOD_SECRET;
  if (secret) {
    _rotationSecret = secret;
    return secret;
  }
  if (import.meta.env.DEV) {
    console.warn(
      "[capsule] ROTATION_SECRET not set — using insecure demo fallback (dev only)",
    );
    _rotationSecret = DEV_FALLBACK_SECRET;
    return _rotationSecret;
  }
  throw new Error(
    "ROTATION_SECRET environment variable is required in production",
  );
}

// ---------------------------------------------------------------------------
// DCA Key management — uses library helpers instead of raw node:crypto
// ---------------------------------------------------------------------------

interface DcaKeys {
  signingPrivateKeyPem: string;
  signingPublicKeyPem: string;
  issuerPrivateKeyPem: string;
  issuerPublicKeyPem: string;
}

let _keysPromise: Promise<DcaKeys> | null = null;

async function getDcaKeys(): Promise<DcaKeys> {
  if (!_keysPromise) {
    _keysPromise = (async () => {
      if (
        process.env.PUBLISHER_ES256_PRIVATE_KEY &&
        process.env.PUBLISHER_ES256_PUBLIC_KEY &&
        process.env.ISSUER_ECDH_PRIVATE_KEY &&
        process.env.ISSUER_ECDH_PUBLIC_KEY
      ) {
        return {
          signingPrivateKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY,
          signingPublicKeyPem: process.env.PUBLISHER_ES256_PUBLIC_KEY,
          issuerPrivateKeyPem: process.env.ISSUER_ECDH_PRIVATE_KEY,
          issuerPublicKeyPem: process.env.ISSUER_ECDH_PUBLIC_KEY,
        };
      }

      if (!import.meta.env.DEV) {
        throw new Error(
          "DCA key pair environment variables are required in production: " +
          "PUBLISHER_ES256_PRIVATE_KEY, PUBLISHER_ES256_PUBLIC_KEY, " +
          "ISSUER_ECDH_PRIVATE_KEY, ISSUER_ECDH_PUBLIC_KEY",
        );
      }

      console.warn(
        "[capsule] DCA keys not set — generating ephemeral keys (dev only)",
      );

      const [signingPair, issuerPair] = await Promise.all([
        generateEcdsaP256KeyPair().then((kp) =>
          exportP256KeyPairPem(kp.privateKey, kp.publicKey),
        ),
        generateEcdhP256KeyPair().then((kp) =>
          exportP256KeyPairPem(kp.privateKey, kp.publicKey),
        ),
      ]);

      return {
        signingPrivateKeyPem: signingPair.privateKeyPem,
        signingPublicKeyPem: signingPair.publicKeyPem,
        issuerPrivateKeyPem: issuerPair.privateKeyPem,
        issuerPublicKeyPem: issuerPair.publicKeyPem,
      };
    })();
  }
  return _keysPromise;
}

function env(name: string): string {
  const v = process.env[name] ?? (import.meta.env as Record<string, string>)[name];
  if (!v) throw new Error(`Missing environment variable: ${name}`);
  return v;
}

export async function getPublisher(): Promise<DcaPublisher> {
  if (!_publisher) {
    const keys = await getDcaKeys();
    _publisher = createDcaPublisher({
      domain: DEMO_DOMAIN,
      signingKeyPem: keys.signingPrivateKeyPem,
      rotationSecret: getRotationSecret(),
      rotationIntervalHours: ROTATION_INTERVAL_HOURS,
    });
  }
  return _publisher;
}

export async function getIssuer(): Promise<DcaIssuerServer> {
  if (!_issuer) {
    const keys = await getDcaKeys();
    _issuer = createDcaIssuer({
      issuerName: DEMO_ISSUER_NAME,
      privateKeyPem: keys.issuerPrivateKeyPem,
      keyId: DEMO_KEY_ID,
      trustedPublisherKeys: {
        [DEMO_DOMAIN]: keys.signingPublicKeyPem,
      },
    });
  }
  return _issuer;
}

export async function getIssuerPublicKeyPem(): Promise<string> {
  const keys = await getDcaKeys();
  return keys.issuerPublicKeyPem;
}

// ── Render cache ────────────────────────────────────────────────────────
interface CachedRender {
  data: DcaRenderResult;
  tier: string;
  rotationBucket: number;
}
const renderCache = new Map<string, CachedRender>();

/**
 * Bucket aligned to the configured rotation interval. Re-renders happen when
 * the bucket flips, so cache invalidation matches wrap-key rotation.
 */
function getCurrentRotationBucket(): number {
  return Math.floor(Date.now() / (ROTATION_INTERVAL_HOURS * 60 * 60 * 1000));
}

/**
 * Render a DCA-encrypted article.
 *
 * Looks up the article by resourceId and uses:
 * - contentName: "bodytext" (stable content identity)
 * - scope: article tier (access scope)
 */
export async function renderDcaArticle(
  resourceId: string,
): Promise<{ result: DcaRenderResult; tier: string } | null> {
  const rotationBucket = getCurrentRotationBucket();
  const cached = renderCache.get(resourceId);
  if (cached && cached.rotationBucket === rotationBucket) {
    return { result: cached.data, tier: cached.tier };
  }

  const { articles } = await import("./articles");
  const article = articles[resourceId];
  if (!article) return null;

  const publisher = await getPublisher();
  const issuerPub = await getIssuerPublicKeyPem();

  const result = await publisher.render({
    resourceId,
    contentItems: [
      {
        contentName: "bodytext",
        scope: article.tier,
        content: article.premiumContent,
        contentType: "text/html",
      },
    ],
    issuers: [
      {
        issuerName: DEMO_ISSUER_NAME,
        publicKeyPem: issuerPub,
        keyId: DEMO_KEY_ID,
        unlockUrl: "/api/unlock",
        scopes: [article.tier],
      },
    ],
    resourceData: {
      title: article.title,
      author: article.author,
    },
  });

  renderCache.set(resourceId, { data: result, tier: article.tier, rotationBucket });
  return { result, tier: article.tier };
}

export { DEMO_ISSUER_NAME };
