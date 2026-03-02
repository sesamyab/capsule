/**
 * @sesamy/capsule-server
 *
 * Server-side encryption library for Capsule.
 *
 * This package provides:
 * - CmsServer for encrypting content (works with any key source)
 * - PeriodKeyProvider for period-based key derivation
 * - SubscriptionServer for handling unlock requests
 * - Envelope encryption with AES-256-GCM
 *
 * @example Quick Start with Period Key Provider
 * ```typescript
 * import { createCmsServer, createPeriodKeyProvider, createSubscriptionServer } from '@sesamy/capsule-server';
 *
 * // Create period key provider (derives keys from period secret)
 * const keyProvider = createPeriodKeyProvider({
 *   periodSecret: process.env.PERIOD_SECRET,
 * });
 *
 * // CMS side: encrypt content
 * const cms = createCmsServer({
 *   getKeys: (keyIds) => keyProvider.getKeys(keyIds),
 * });
 *
 * const encrypted = await cms.encrypt('article-123', content, {
 *   keyIds: ['premium', 'enterprise'],
 * });
 *
 * // Subscription side: handle unlock requests
 * const server = createSubscriptionServer({
 *   periodSecret: process.env.PERIOD_SECRET,
 * });
 *
 * app.post('/api/unlock', async (req) => {
 *   const { wrappedKey, publicKey } = req.body;
 *   return server.unlockForUser(wrappedKey, publicKey);
 * });
 * ```
 *
 * @example With External Key Provider
 * ```typescript
 * import { createCmsServer } from '@sesamy/capsule-server';
 *
 * const cms = createCmsServer({
 *   getKeys: async (keyIds) => {
 *     // Fetch keys from your subscription server
 *     const response = await fetch('/api/keys', {
 *       method: 'POST',
 *       body: JSON.stringify({ keyIds }),
 *     });
 *     return response.json(); // [{ keyId, key, expiresAt? }]
 *   },
 * });
 *
 * const encrypted = await cms.encrypt('article-123', content, {
 *   keyIds: ['premium'],
 * });
 * ```
 */

// High-level API (recommended)
export {
  // CMS Server
  CmsServer,
  createCmsServer,
  type CmsServerOptions,
  type EncryptOptions,
  type KeyEntry,
  type KeyProvider,
  // Period Key Provider
  PeriodKeyProvider,
  createPeriodKeyProvider,
  type PeriodKeyProviderOptions,
} from "./capsule";

// CMS encryption (low-level)
export { CmsEncryptor, createPeriodEncryptor, createApiEncryptor } from "./cms";

// Subscription server
export {
  SubscriptionServer,
  createSubscriptionServer,
} from "./subscription-server";

// Token utilities for pre-signed unlock links
export {
  TokenManager,
  createTokenManager,
  type TokenManagerOptions,
  type UnlockTokenPayload,
  type GenerateTokenOptions,
  type TokenValidationResult,
  type TokenValidationError,
  type UsageTracker,
} from "./tokens";

// Asymmetric token signing (Ed25519 with JWKS support)
export {
  AsymmetricTokenManager,
  createAsymmetricTokenManager,
  generateSigningKeyPair,
  type SigningKeyPair,
  type Jwks,
  type JwkKey,
  type AsymmetricTokenPayload,
  type AsymmetricGenerateOptions,
  type AsymmetricTokenManagerOptions,
  type AsymmetricValidationResult,
  type AsymmetricValidationError,
} from "./asymmetric-tokens";

// Low-level encryption utilities
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

// Time-period utilities
export {
  derivePeriodKey,
  getPeriodKeys,
  getPeriodKey,
  getCurrentPeriod,
  getNextPeriod,
  getPreviousPeriod,
  getPeriodExpiration,
  getPeriodId,
  isPeriodValid,
  hkdf,
  DEFAULT_PERIOD_DURATION_SECONDS,
} from "./time-periods";

// Types
export type {
  EncryptedArticle,
  WrappedKey,
  KeyWrapConfig,
  PeriodKey,
  CmsEncryptorOptions,
  SubscriptionClientOptions,
  PeriodKeysResponse,
  UnlockResponse,
} from "./types";

// ============================================================================
// DCA (Delegated Content Access) standard support
// ============================================================================

// DCA Publisher
export { createDcaPublisher } from "./dca-publisher";

// DCA Issuer
export {
  createDcaIssuer,
  type DcaAccessDecision,
  type DcaVerifiedRequest,
} from "./dca-issuer";

// DCA JWT (ES256 signing & integrity proofs)
export {
  createJwt,
  verifyJwt,
  decodeJwtPayload,
  createResourceJwt,
  createIssuerJwt,
  verifyIssuerProof,
  computeProofHash,
} from "./dca-jwt";

// DCA Seal (ECDH P-256 / RSA-OAEP key sealing)
export {
  sealEcdhP256,
  unsealEcdhP256,
  sealRsaOaep,
  unsealRsaOaep,
  seal,
  unseal,
  importIssuerPublicKey,
  importIssuerPrivateKey,
  type DcaSealAlgorithm,
} from "./dca-seal";

// DCA Time Buckets
export {
  formatTimeBucket,
  getCurrentTimeBuckets,
  deriveDcaPeriodKey,
  generateRenderId,
} from "./dca-time-buckets";

// DCA Types
export type {
  DcaData,
  DcaResource,
  DcaContentSealData,
  DcaSealedContentKey,
  DcaIssuerEntry,
  DcaIssuerSealed,
  DcaIssuerJwtPayload,
  DcaIssuerProof,
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
  DcaUnlockedKeys,
} from "./dca-types";

// Low-level crypto primitives (ECDH, ECDSA, RSA, SHA-256)
export {
  sha256,
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
} from "./web-crypto";
