/**
 * DCA JWT — ES256 signing, verification, and SHA-256 integrity proofs.
 *
 * The header is always `{ "alg": "ES256", "typ": "JWT" }`.
 *
 * resourceJWT uses standard JWT claims (RFC 7519):
 *   - `iss` = publisher domain, `sub` = resourceId, `iat` = render time, `jti` = renderId
 *   - `scopes` = required access scopes (custom claim)
 *   - `data` = custom publisher metadata
 *
 * One JWT per page:
 *   - resourceJWT: signs resource metadata (shared across issuers)
 */

import {
  importEcdsaP256PrivateKey,
  importEcdsaP256PublicKey,
  ecdsaP256Sign,
  ecdsaP256Verify,
  sha256,
  toBase64Url,
  fromBase64Url,
  encodeUtf8,
  decodeUtf8,
  type WebCryptoKey,
} from "./web-crypto";

import type {
  DcaResource,
  DcaResourceJwtPayload,
} from "./dca-types";

// ============================================================================
// JWT creation / verification
// ============================================================================

/** DCA JWT header fields (ES256). `kid` is included when signed by a
 *  publisher configured with a signing key id. */
export interface DcaJwtHeader {
  alg: "ES256";
  typ: "JWT";
  kid?: string;
}

/** Default header for backwards compatibility (no kid). */
const DEFAULT_HEADER_B64 = toBase64Url(encodeUtf8(JSON.stringify({ alg: "ES256", typ: "JWT" })));

function encodeHeader(kid: string | undefined): string {
  if (!kid) return DEFAULT_HEADER_B64;
  return toBase64Url(encodeUtf8(JSON.stringify({ alg: "ES256", typ: "JWT", kid })));
}

/**
 * Create an ES256 JWT from a payload object.
 *
 * @param payload - Any JSON-serializable object
 * @param privateKey - ECDSA P-256 private key (CryptoKey or PEM string)
 * @param opts - Optional header fields (e.g. kid to help JWKS-based verifiers pick a key)
 * @returns Signed JWT string (header.payload.signature)
 */
export async function createJwt(
  payload: unknown,
  privateKey: WebCryptoKey | string,
  opts?: { kid?: string },
): Promise<string> {
  const key = typeof privateKey === "string"
    ? await importEcdsaP256PrivateKey(privateKey)
    : privateKey;

  const headerB64 = encodeHeader(opts?.kid);
  const payloadB64 = toBase64Url(encodeUtf8(JSON.stringify(payload)));
  const signingInput = encodeUtf8(`${headerB64}.${payloadB64}`);
  const signature = await ecdsaP256Sign(key, signingInput);

  return `${headerB64}.${payloadB64}.${toBase64Url(signature)}`;
}

/**
 * Verify an ES256 JWT and return the decoded payload.
 *
 * @param jwt - The JWT string to verify
 * @param publicKey - ECDSA P-256 public key (CryptoKey or PEM string)
 * @returns Decoded payload object
 * @throws Error if signature is invalid or JWT is malformed
 */
export async function verifyJwt<T = unknown>(
  jwt: string,
  publicKey: WebCryptoKey | string,
): Promise<T> {
  const key = typeof publicKey === "string"
    ? await importEcdsaP256PublicKey(publicKey)
    : publicKey;

  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed JWT: expected 3 parts");
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // Verify header is ES256
  const header = JSON.parse(decodeUtf8(fromBase64Url(headerB64)));
  if (header.alg !== "ES256") {
    throw new Error(`Unsupported JWT algorithm: ${header.alg}`);
  }

  // Verify signature
  const signingInput = encodeUtf8(`${headerB64}.${payloadB64}`);
  const signature = fromBase64Url(signatureB64);
  const valid = await ecdsaP256Verify(key, signature, signingInput);

  if (!valid) {
    throw new Error("JWT signature verification failed");
  }

  // Decode payload
  return JSON.parse(decodeUtf8(fromBase64Url(payloadB64))) as T;
}

/**
 * Decode a JWT payload without verifying the signature.
 * Useful for extracting resource.domain before key lookup.
 */
export function decodeJwtPayload<T = unknown>(jwt: string): T {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed JWT: expected 3 parts");
  }
  return JSON.parse(decodeUtf8(fromBase64Url(parts[1]))) as T;
}

/**
 * Decode a JWT header without verifying the signature.
 * Used on the issuer side to extract `kid` before JWKS-based key lookup.
 */
export function decodeJwtHeader(jwt: string): DcaJwtHeader {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed JWT: expected 3 parts");
  }
  return JSON.parse(decodeUtf8(fromBase64Url(parts[0]))) as DcaJwtHeader;
}

// ============================================================================
// SHA-256 integrity proofs
// ============================================================================

/**
 * Compute the DCA proof hash of a wrapped blob string.
 *
 * Hash input: the base64url string as-is (UTF-8 bytes), NOT the decoded binary.
 * Output: base64url(SHA-256(utf8_bytes_of_base64url_string)), 43 chars no padding.
 */
export async function computeProofHash(wrappedBlobBase64Url: string): Promise<string> {
  const bytes = encodeUtf8(wrappedBlobBase64Url);
  const hash = await sha256(bytes);
  return toBase64Url(hash);
}

/**
 * Create a resourceJWT: ES256 JWT signing the resource using standard claims.
 *
 * Maps DcaResource fields to standard JWT claims:
 *   - domain → iss, resourceId → sub, issuedAt → iat (Unix seconds), renderId → jti
 */
export async function createResourceJwt(
  resource: DcaResource,
  signingKey: WebCryptoKey | string,
  opts?: { kid?: string },
): Promise<string> {
  const payload: DcaResourceJwtPayload = {
    iss: resource.domain,
    sub: resource.resourceId,
    iat: Math.floor(new Date(resource.issuedAt).getTime() / 1000),
    jti: resource.renderId,
    scopes: resource.scopes,
    data: resource.data,
  };
  return createJwt(payload, signingKey, opts);
}

/**
 * Convert a verified DcaResourceJwtPayload back to a DcaResource.
 *
 * Used by the issuer after JWT verification to produce the human-readable
 * DcaResource that the rest of the codebase works with.
 */
export function resourceJwtPayloadToResource(payload: DcaResourceJwtPayload): DcaResource {
  return {
    domain: payload.iss,
    resourceId: payload.sub,
    issuedAt: new Date(payload.iat * 1000).toISOString(),
    renderId: payload.jti,
    scopes: payload.scopes ?? [],
    data: payload.data,
  };
}

