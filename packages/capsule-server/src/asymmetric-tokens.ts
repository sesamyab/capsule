/**
 * Asymmetric token signing with Ed25519 for public key verification.
 *
 * This module provides Ed25519-based token signing that enables:
 * - Public key verification without sharing secrets
 * - JWKS endpoint for key discovery
 * - Key rotation with multiple active keys
 *
 * @example
 * ```typescript
 * import { createAsymmetricTokenManager, generateSigningKeyPair } from '@sesamy/capsule-server';
 *
 * // Generate a new key pair (do this once, store securely)
 * const { privateKey, publicKey, keyId } = await generateSigningKeyPair();
 *
 * // Create token manager with private key
 * const tokens = createAsymmetricTokenManager({
 *   privateKey,
 *   publicKey,
 *   keyId,
 *   issuer: 'https://api.example.com',
 * });
 *
 * // Generate tokens
 * const token = tokens.generate({ tier: 'premium', contentId: 'article-123', expiresIn: '7d' });
 *
 * // Get JWKS for /.well-known/jwks.json endpoint
 * const jwks = tokens.getJwks();
 * ```
 */

import { createPrivateKey, createPublicKey, sign, verify, generateKeyPairSync, randomBytes, KeyObject } from "crypto";

/** Ed25519 key pair for signing */
export interface SigningKeyPair {
  /** Private key in PEM format (keep secret!) */
  privateKey: string;
  /** Public key in PEM format (safe to share) */
  publicKey: string;
  /** Unique key identifier */
  keyId: string;
}

/** A single key in JWKS format */
export interface JwkKey {
  /** Key type: OKP for Ed25519 */
  kty: "OKP";
  /** Curve: Ed25519 */
  crv: "Ed25519";
  /** Key ID */
  kid: string;
  /** Public key (base64url encoded) */
  x: string;
  /** Key use: signature */
  use: "sig";
  /** Algorithm: EdDSA */
  alg: "EdDSA";
}

/** JWKS (JSON Web Key Set) structure */
export interface Jwks {
  keys: JwkKey[];
}

/** Token payload - same as symmetric version */
export interface AsymmetricTokenPayload {
  /** Token version */
  v: 1;
  /** Unique token ID */
  tid: string;
  /** Issuer URL (used for JWKS discovery) */
  iss: string;
  /** Key ID used for signing */
  kid: string;
  /** Algorithm used */
  alg: "EdDSA";
  /** Tier this token grants access to */
  tier: string;
  /** Publisher's content ID */
  contentId: string;
  /** Optional: full URL for the content */
  url?: string;
  /** Optional: user/purchaser ID */
  userId?: string;
  /** Optional: maximum uses */
  maxUses?: number;
  /** Issued at (Unix seconds) */
  iat: number;
  /** Expires at (Unix seconds) */
  exp: number;
  /** Optional: custom metadata */
  meta?: Record<string, string | number | boolean>;
}

/** Options for generating a token */
export interface AsymmetricGenerateOptions {
  tier: string;
  contentId: string;
  url?: string;
  userId?: string;
  maxUses?: number;
  expiresIn: string | number;
  meta?: Record<string, string | number | boolean>;
}

/** Token manager options for asymmetric signing */
export interface AsymmetricTokenManagerOptions {
  /** Private key in PEM format for signing */
  privateKey: string;
  /** Public key in PEM format for JWKS */
  publicKey: string;
  /** Key ID for this key pair */
  keyId: string;
  /** Issuer URL (e.g., "https://api.example.com") */
  issuer: string;
  /** Additional public keys to include in JWKS (for key rotation) */
  additionalPublicKeys?: Array<{ publicKey: string; keyId: string }>;
}

/** Result of token validation */
export interface AsymmetricValidationResult {
  valid: true;
  payload: AsymmetricTokenPayload;
}

/** Token validation error */
export interface AsymmetricValidationError {
  valid: false;
  error: "invalid" | "expired" | "malformed" | "unknown_key";
  message: string;
}

/**
 * Parse duration string to seconds.
 */
function parseDuration(duration: string | number): number {
  if (typeof duration === "number") return duration;

  const match = duration.match(/^(\d+)(s|m|h|d)$/);
  if (!match) {
    throw new Error(`Invalid duration format: ${duration}. Use "1h", "24h", "7d", etc.`);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case "s": return value;
    case "m": return value * 60;
    case "h": return value * 60 * 60;
    case "d": return value * 60 * 60 * 24;
    default: throw new Error(`Unknown duration unit: ${unit}`);
  }
}

/**
 * Convert a PEM public key to JWK format for JWKS.
 */
function publicKeyToJwk(publicKeyPem: string, keyId: string): JwkKey {
  const keyObject = createPublicKey(publicKeyPem);
  const exported = keyObject.export({ format: "jwk" });
  
  return {
    kty: "OKP",
    crv: "Ed25519",
    kid: keyId,
    x: exported.x as string,
    use: "sig",
    alg: "EdDSA",
  };
}

/**
 * Generate a new Ed25519 signing key pair.
 *
 * @example
 * ```typescript
 * const { privateKey, publicKey, keyId } = await generateSigningKeyPair();
 * // Store privateKey securely (e.g., in KMS)
 * // publicKey will be exposed via JWKS
 * ```
 */
export function generateSigningKeyPair(customKeyId?: string): SigningKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  const keyId = customKeyId || `key-${Date.now()}-${randomBytes(4).toString("hex")}`;

  return {
    privateKey: privateKey as string,
    publicKey: publicKey as string,
    keyId,
  };
}

/**
 * Asymmetric Token Manager using Ed25519 signing.
 *
 * Tokens are signed with Ed25519 and can be verified using the public key
 * exposed via the JWKS endpoint.
 */
export class AsymmetricTokenManager {
  private privateKey: KeyObject;
  private keyId: string;
  private issuer: string;
  private jwks: Jwks;
  /** Map of keyId → public key for signature verification */
  private publicKeys: Map<string, KeyObject>;

  constructor(options: AsymmetricTokenManagerOptions) {
    this.privateKey = createPrivateKey(options.privateKey);
    this.keyId = options.keyId;
    this.issuer = options.issuer;

    // Build public key map for verification
    this.publicKeys = new Map();
    this.publicKeys.set(options.keyId, createPublicKey(options.publicKey));

    // Build JWKS with current key and any additional keys
    const keys: JwkKey[] = [publicKeyToJwk(options.publicKey, options.keyId)];
    
    if (options.additionalPublicKeys) {
      for (const { publicKey, keyId } of options.additionalPublicKeys) {
        keys.push(publicKeyToJwk(publicKey, keyId));
        this.publicKeys.set(keyId, createPublicKey(publicKey));
      }
    }

    this.jwks = { keys };
  }

  /**
   * Generate a signed token.
   */
  generate(options: AsymmetricGenerateOptions): string {
    const now = Math.floor(Date.now() / 1000);
    const expiresInSeconds = parseDuration(options.expiresIn);

    const payload: AsymmetricTokenPayload = {
      v: 1,
      tid: randomBytes(12).toString("base64url"),
      iss: this.issuer,
      kid: this.keyId,
      alg: "EdDSA",
      tier: options.tier,
      contentId: options.contentId,
      iat: now,
      exp: now + expiresInSeconds,
    };

    if (options.url) payload.url = options.url;
    if (options.userId) payload.userId = options.userId;
    if (options.maxUses !== undefined) payload.maxUses = options.maxUses;
    if (options.meta) payload.meta = options.meta;

    return this.sign(payload);
  }

  /**
   * Validate a token using the public key.
   */
  validate(token: string): AsymmetricValidationResult | AsymmetricValidationError {
    const dotIndex = token.lastIndexOf(".");
    if (dotIndex === -1) {
      return { valid: false, error: "malformed", message: "Invalid token format" };
    }

    const payloadB64 = token.substring(0, dotIndex);
    const signatureB64 = token.substring(dotIndex + 1);

    // Decode payload first to check kid
    let payload: AsymmetricTokenPayload;
    try {
      const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf-8");
      payload = JSON.parse(payloadJson);
    } catch {
      return { valid: false, error: "malformed", message: "Invalid payload encoding" };
    }

    // Look up the public key for this kid
    const publicKey = this.publicKeys.get(payload.kid);
    if (!publicKey) {
      return { valid: false, error: "unknown_key", message: `Unknown key ID: ${payload.kid}` };
    }

    // Verify signature using the correct key
    const signatureBuffer = Buffer.from(signatureB64, "base64url");
    const isValid = verify(null, Buffer.from(payloadB64), publicKey, signatureBuffer);

    if (!isValid) {
      return { valid: false, error: "invalid", message: "Invalid signature" };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return { valid: false, error: "expired", message: "Token has expired" };
    }

    return { valid: true, payload };
  }

  /**
   * Get the JWKS (JSON Web Key Set) for the /.well-known/jwks.json endpoint.
   */
  getJwks(): Jwks {
    return this.jwks;
  }

  /**
   * Get the issuer URL.
   */
  getIssuer(): string {
    return this.issuer;
  }

  /**
   * Peek at token payload without validation.
   */
  peek(token: string): AsymmetricTokenPayload | null {
    try {
      const dotIndex = token.lastIndexOf(".");
      if (dotIndex === -1) return null;

      const payloadB64 = token.substring(0, dotIndex);
      const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf-8");
      return JSON.parse(payloadJson);
    } catch {
      return null;
    }
  }

  /**
   * Sign a payload and return the complete token.
   */
  private sign(payload: AsymmetricTokenPayload): string {
    const payloadJson = JSON.stringify(payload);
    const payloadB64 = Buffer.from(payloadJson).toString("base64url");
    const signature = sign(null, Buffer.from(payloadB64), this.privateKey);
    return `${payloadB64}.${signature.toString("base64url")}`;
  }
}

/**
 * Create an asymmetric token manager for Ed25519 signing.
 */
export function createAsymmetricTokenManager(
  options: AsymmetricTokenManagerOptions
): AsymmetricTokenManager {
  return new AsymmetricTokenManager(options);
}
