/**
 * DCA publisher and issuer singletons for the demo app.
 *
 * Uses the DCA (Delegated Content Access) standard for content encryption.
 * The publisher derives wrapKeys locally from a rotationSecret (HKDF) —
 * zero runtime network calls for key generation.
 *
 * All secrets and key pairs are resolved lazily so that `next build` can
 * collect pages without crashing when env vars are absent.
 */

import {
  createDcaPublisher,
  createDcaIssuer,
  generateEcdsaP256KeyPair,
  generateEcdhP256KeyPair,
  exportP256KeyPairPem,
} from "@sesamy/capsule-server";

/** Rotation interval in hours (1 hour for demo, configurable for production) */
export const ROTATION_INTERVAL_HOURS = 1;

const DEV_FALLBACK_SECRET = Buffer.from(
  "demo-secret-do-not-use-in-production!!",
  "utf-8",
).toString("base64");

// ---------------------------------------------------------------------------
// Secret helpers – throw at runtime if missing outside dev
// ---------------------------------------------------------------------------

let _rotationSecret: string | undefined;

/** @throws if ROTATION_SECRET is missing and NODE_ENV !== "development" */
export function getRotationSecret(): string {
  if (_rotationSecret) return _rotationSecret;
  const secret = process.env.ROTATION_SECRET ?? process.env.PERIOD_SECRET;
  if (secret) {
    _rotationSecret = secret;
    return secret;
  }
  if (process.env.NODE_ENV === "development") {
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
// DCA Key management
//
// In production, these should be stable keys persisted in KMS.
// For the demo, we generate ephemeral keys at startup or read from env.
// ---------------------------------------------------------------------------

interface DcaKeys {
  /** ES256 (ECDSA P-256) signing key pair PEMs — publisher signs JWTs */
  signingPrivateKeyPem: string;
  signingPublicKeyPem: string;
  /** ECDH P-256 key pair PEMs — issuer unwraps keys */
  issuerPrivateKeyPem: string;
  issuerPublicKeyPem: string;
}

let _keysPromise: Promise<DcaKeys> | null = null;

async function getDcaKeys(): Promise<DcaKeys> {
  if (!_keysPromise) {
    _keysPromise = (async () => {
      // Check for env vars first
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

      // Generate ephemeral keys for development
      if (process.env.NODE_ENV !== "development") {
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

// ---------------------------------------------------------------------------
// Publisher singleton
// ---------------------------------------------------------------------------

const DEMO_DOMAIN = "capsule-demo.sesamy.com";
const DEMO_ISSUER_NAME = "sesamy-demo";
const DEMO_KEY_ID = "demo-2026";

let _publisher: ReturnType<typeof createDcaPublisher> | undefined;

export async function getPublisher() {
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

/**
 * Get the issuer public key PEM (needed by publisher to wrap keys for the issuer).
 */
export async function getIssuerPublicKeyPem(): Promise<string> {
  const keys = await getDcaKeys();
  return keys.issuerPublicKeyPem;
}

// ---------------------------------------------------------------------------
// Issuer singleton
// ---------------------------------------------------------------------------

let _issuerPromise: Promise<ReturnType<typeof createDcaIssuer>> | null = null;

export function getIssuer() {
  if (!_issuerPromise) {
    _issuerPromise = (async () => {
      const keys = await getDcaKeys();
      return createDcaIssuer({
        issuerName: DEMO_ISSUER_NAME,
        privateKeyPem: keys.issuerPrivateKeyPem,
        keyId: DEMO_KEY_ID,
        trustedPublisherKeys: {
          [DEMO_DOMAIN]: keys.signingPublicKeyPem,
        },
      });
    })();
  }
  return _issuerPromise;
}

// ---------------------------------------------------------------------------
// Shared constants for demo routes
// ---------------------------------------------------------------------------

export { DEMO_DOMAIN, DEMO_ISSUER_NAME, DEMO_KEY_ID };
