/**
 * @sesamy/capsule-server
 *
 * Server-side DCA (Delegated Content Access) library.
 *
 * This package provides:
 * - DCA Publisher for encrypting content (local key derivation, zero network calls)
 * - DCA Issuer for handling unlock requests
 * - ES256 JWT signing and verification
 * - ECDH P-256 / RSA-OAEP key wrapping for issuer delivery
 * - Low-level AES-256-GCM encryption utilities
 *
 * @example Publisher (CMS side)
 * ```typescript
 * import { createDcaPublisher } from '@sesamy/capsule-server';
 *
 * const publisher = createDcaPublisher({
 *   domain: "www.news-site.com",
 *   signingKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY!,
 *   rotationSecret: process.env.ROTATION_SECRET!,
 * });
 *
 * const result = await publisher.render({
 *   resourceId: "article-123",
 *   contentItems: [
 *     { contentName: "bodytext", content: "<p>Premium article body...</p>" },
 *   ],
 *   issuers: [
 *     {
 *       issuerName: "sesamy",
 *       publicKeyPem: process.env.SESAMY_ECDH_PUBLIC_KEY!,
 *       keyId: "2025-10",
 *       unlockUrl: "https://api.sesamy.com/unlock",
 *       contentNames: ["bodytext"],
 *     },
 *   ],
 * });
 * ```
 *
 * @example Issuer (unlock side)
 * ```typescript
 * import { createDcaIssuer } from '@sesamy/capsule-server';
 *
 * const issuer = createDcaIssuer({
 *   issuerName: "sesamy",
 *   privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
 *   keyId: "2025-10",
 *   trustedPublisherKeys: {
 *     "www.news-site.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
 *   },
 * });
 *
 * app.post('/api/unlock', async (req) => {
 *   const result = await issuer.unlock(req.body, {
 *     grantedContentNames: ["bodytext"],
 *     deliveryMode: "wrapKey",
 *   });
 *   return result;
 * });
 * ```
 */

// ============================================================================
// DCA Publisher
// ============================================================================

export { createDcaPublisher } from "./dca-publisher";

// ============================================================================
// DCA Issuer
// ============================================================================

export {
  createDcaIssuer,
  type DcaAccessDecision,
  type DcaVerifiedRequest,
  type DcaShareLinkUnlockOptions,
} from "./dca-issuer";

// ============================================================================
// DCA JWT (ES256 signing & integrity proofs)
// ============================================================================

export {
  createJwt,
  verifyJwt,
  decodeJwtPayload,
  createResourceJwt,
  computeProofHash,
  resourceJwtPayloadToResource,
} from "./dca-jwt";

// ============================================================================
// DCA Wrap (ECDH P-256 / RSA-OAEP key wrapping for issuer delivery)
// ============================================================================

export {
  wrapEcdhP256,
  unwrapEcdhP256,
  wrapRsaOaep,
  unwrapRsaOaep,
  wrap,
  unwrap,
  importIssuerPublicKey,
  importIssuerPrivateKey,
  type DcaWrapAlgorithm,
} from "./dca-wrap";

// ============================================================================
// DCA JWKS (issuer public key resolution via .well-known)
// ============================================================================

export {
  fetchJwks,
  refreshJwks,
  getActiveIssuerKeys,
  selectActiveKeys,
  clearJwksCache,
  type Jwk,
  type JwksDocument,
  type ResolvedIssuerKey,
} from "./dca-jwks";

// ============================================================================
// DCA Rotation (wrapKey identifiers and derivation)
// ============================================================================

export {
  formatTimeKid,
  getCurrentRotationVersions,
  deriveWrapKey,
  generateRenderId,
} from "./dca-rotation";

// ============================================================================
// DCA Types
// ============================================================================

export type {
  DcaManifest,
  DcaResource,
  DcaResourceJwtPayload,
  DcaContentEntry,
  DcaWrappedContentKeyEntry,
  DcaIssuerEntry,
  DcaIssuerKey,
  DcaWrappedIssuerWrapKey,
  DcaUnlockedKey,
  DcaDirectKey,
  DcaWrapKeyDelivery,
  DcaUnlockedWrapKey,
  DcaJsonApiResponse,
  DcaPublisherConfig,
  DcaContentItem,
  DcaIssuerConfig,
  DcaRenderOptions,
  DcaRenderResult,
  DcaIssuerServerConfig,
  DcaTrustedPublisher,
  DcaUnlockRequest,
  DcaUnlockResponse,
  DcaShareLinkTokenPayload,
  DcaShareLinkOptions,
} from "./dca-types";

// ============================================================================
// Low-level encryption utilities
// ============================================================================

export {
  encryptContent,
  decryptContent,
  wrapContentKey,
  unwrapContentKey,
  generateContentKey,
  generateIv,
  GCM_IV_SIZE,
  GCM_TAG_LENGTH,
  AES_KEY_SIZE,
} from "./encryption";

// ============================================================================
// Low-level crypto primitives
// ============================================================================

export {
  sha256,
  hkdf,
  generateEcdhP256KeyPair,
  exportEcdhP256PublicKeyRaw,
  importEcdhP256PublicKeyRaw,
  importEcdhP256PublicKey,
  importEcdhP256PrivateKey,
  ecdhDeriveBits,
  generateEcdsaP256KeyPair,
  importEcdsaP256PrivateKey,
  importEcdsaP256PublicKey,
  ecdsaP256Sign,
  ecdsaP256Verify,
  exportP256KeyPairPem,
  parsePem,
  importRsaPublicKey,
  rsaOaepEncrypt,
  importRsaPrivateKey,
  rsaOaepDecrypt,
  generateAesKeyBytes,
  toBase64Url,
  fromBase64Url,
  toBase64,
  fromBase64,
  encodeUtf8,
  decodeUtf8,
} from "./web-crypto";
