/**
 * DCA JWT — ES256 signing, verification, and SHA-256 integrity proofs.
 *
 * DCA uses JWT solely as a signed JSON envelope. Standard claims (iss, sub, iat, exp)
 * are not used. The header is always `{ "alg": "ES256", "typ": "JWT" }`.
 *
 * Two JWTs per page:
 *   - resourceJWT: signs resource metadata (shared across issuers)
 *   - issuerJWT: per-issuer, signs SHA-256 proofs of sealed blobs
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
  DcaIssuerJwtPayload,
  DcaIssuerSealed,
  DcaIssuerProof,
} from "./dca-types";

// ============================================================================
// JWT creation / verification
// ============================================================================

/** Fixed JWT header for DCA (ES256) */
const JWT_HEADER = toBase64Url(encodeUtf8(JSON.stringify({ alg: "ES256", typ: "JWT" })));

/**
 * Create an ES256 JWT from a payload object.
 *
 * @param payload - Any JSON-serializable object
 * @param privateKey - ECDSA P-256 private key (CryptoKey or PEM string)
 * @returns Signed JWT string (header.payload.signature)
 */
export async function createJwt(
  payload: unknown,
  privateKey: WebCryptoKey | string,
): Promise<string> {
  const key = typeof privateKey === "string"
    ? await importEcdsaP256PrivateKey(privateKey)
    : privateKey;

  const payloadB64 = toBase64Url(encodeUtf8(JSON.stringify(payload)));
  const signingInput = encodeUtf8(`${JWT_HEADER}.${payloadB64}`);
  const signature = await ecdsaP256Sign(key, signingInput);

  return `${JWT_HEADER}.${payloadB64}.${toBase64Url(signature)}`;
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

// ============================================================================
// SHA-256 integrity proofs
// ============================================================================

/**
 * Compute the DCA proof hash of a sealed blob string.
 *
 * Hash input: the base64url string as-is (UTF-8 bytes), NOT the decoded binary.
 * Output: base64url(SHA-256(utf8_bytes_of_base64url_string)), 43 chars no padding.
 */
export async function computeProofHash(sealedBlobBase64Url: string): Promise<string> {
  const bytes = encodeUtf8(sealedBlobBase64Url);
  const hash = await sha256(bytes);
  return toBase64Url(hash);
}

/**
 * Build the proof object for one issuer's sealed blobs.
 *
 * @param sealed - Map of contentName → { contentKey, periodKeys } sealed blobs
 * @returns Proof object matching the issuerJWT payload shape
 */
export async function buildIssuerProof(
  sealed: Record<string, DcaIssuerSealed>,
): Promise<Record<string, DcaIssuerProof>> {
  const proof: Record<string, DcaIssuerProof> = {};

  for (const [contentName, entry] of Object.entries(sealed)) {
    const contentKeyHash = await computeProofHash(entry.contentKey);
    const periodKeysHashes: Record<string, string> = {};

    for (const [t, sealedPeriodKey] of Object.entries(entry.periodKeys)) {
      periodKeysHashes[t] = await computeProofHash(sealedPeriodKey);
    }

    proof[contentName] = {
      contentKey: contentKeyHash,
      periodKeys: periodKeysHashes,
    };
  }

  return proof;
}

/**
 * Create a resourceJWT: ES256 JWT signing the resource object.
 */
export async function createResourceJwt(
  resource: DcaResource,
  signingKey: WebCryptoKey | string,
): Promise<string> {
  return createJwt(resource, signingKey);
}

/**
 * Create an issuerJWT: ES256 JWT signing the integrity proofs for one issuer.
 */
export async function createIssuerJwt(
  renderId: string,
  issuerName: string,
  sealed: Record<string, DcaIssuerSealed>,
  signingKey: WebCryptoKey | string,
): Promise<string> {
  const proof = await buildIssuerProof(sealed);

  const payload: DcaIssuerJwtPayload = {
    renderId,
    issuerName,
    proof,
  };

  return createJwt(payload, signingKey);
}

/**
 * Verify an issuerJWT's integrity proofs against the actual sealed blobs.
 *
 * @param issuerJwtPayload - Verified issuerJWT payload
 * @param sealed - The actual sealed blobs from the unlock request
 * @throws Error on any hash mismatch (integrity failure)
 */
export async function verifyIssuerProof(
  issuerJwtPayload: DcaIssuerJwtPayload,
  sealed: Record<string, DcaIssuerSealed>,
): Promise<void> {
  for (const [contentName, proofEntry] of Object.entries(issuerJwtPayload.proof)) {
    const sealedEntry = sealed[contentName];
    if (!sealedEntry) {
      throw new Error(`Integrity failure: content item "${contentName}" in proof but not in sealed data`);
    }

    // Verify contentKey hash
    const actualContentKeyHash = await computeProofHash(sealedEntry.contentKey);
    if (actualContentKeyHash !== proofEntry.contentKey) {
      throw new Error(`Integrity failure: contentKey hash mismatch for "${contentName}"`);
    }

    // Verify periodKey hashes
    for (const [t, expectedHash] of Object.entries(proofEntry.periodKeys)) {
      const sealedPeriodKey = sealedEntry.periodKeys[t];
      if (!sealedPeriodKey) {
        throw new Error(`Integrity failure: period "${t}" in proof but not in sealed data for "${contentName}"`);
      }
      const actualHash = await computeProofHash(sealedPeriodKey);
      if (actualHash !== expectedHash) {
        throw new Error(`Integrity failure: periodKey hash mismatch for "${contentName}" period "${t}"`);
      }
    }
  }
}
