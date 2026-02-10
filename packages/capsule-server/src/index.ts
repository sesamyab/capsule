/**
 * @sesamy/capsule-server
 *
 * Server-side encryption library for Capsule.
 *
 * This package provides:
 * - CmsServer for encrypting content (works with any key source)
 * - TotpKeyProvider for TOTP-based key derivation
 * - SubscriptionServer for handling unlock requests
 * - Envelope encryption with AES-256-GCM
 *
 * @example Quick Start with TOTP
 * ```typescript
 * import { createCmsServer, createTotpKeyProvider, createSubscriptionServer } from '@sesamy/capsule-server';
 *
 * // Create TOTP key provider (derives keys from master secret)
 * const totp = createTotpKeyProvider({
 *   masterSecret: process.env.MASTER_SECRET,
 * });
 *
 * // CMS side: encrypt content
 * const cms = createCmsServer({
 *   getKeys: (keyIds) => totp.getKeys(keyIds),
 * });
 *
 * const encrypted = await cms.encrypt('article-123', content, {
 *   keyIds: ['premium', 'enterprise'],
 * });
 *
 * // Subscription side: handle unlock requests
 * const server = createSubscriptionServer({
 *   masterSecret: process.env.MASTER_SECRET,
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
  // TOTP Key Provider
  TotpKeyProvider,
  createTotpKeyProvider,
  type TotpKeyProviderOptions,
  // Legacy aliases (deprecated)
  CapsuleServer,
  createCapsule,
  type CapsuleServerOptions,
} from "./capsule";

// CMS encryption (low-level)
export { CmsEncryptor, createTotpEncryptor, createApiEncryptor } from "./cms";

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
  wrapDek,
  unwrapDek,
  generateDek,
  generateIv,
  GCM_IV_SIZE,
  GCM_TAG_LENGTH,
  AES_KEY_SIZE,
} from "./encryption";

// Time-bucket utilities
export {
  deriveBucketKey,
  getBucketKeys,
  getBucketKey,
  getCurrentBucket,
  getNextBucket,
  getPreviousBucket,
  getBucketExpiration,
  getBucketId,
  isBucketValid,
  generateMasterSecret,
  hkdf,
  DEFAULT_BUCKET_PERIOD_SECONDS,
} from "./time-buckets";

// Types
export type {
  EncryptedArticle,
  WrappedKey,
  KeyWrapConfig,
  BucketKey,
  CmsEncryptorOptions,
  SubscriptionClientOptions,
  BucketKeysResponse,
  UnlockResponse,
} from "./types";
