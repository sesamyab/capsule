/**
 * @sesamy/capsule-server
 * 
 * Server-side encryption library for Capsule.
 * 
 * This package provides:
 * - High-level CapsuleServer for easy content encryption
 * - CMS content encryption with envelope encryption
 * - Time-bucket key derivation (TOTP-style)
 * - Subscription server utilities for key management
 * 
 * @example Quick Start (High-Level API)
 * ```typescript
 * import { CapsuleServer } from '@sesamy/capsule-server';
 * 
 * const capsule = new CapsuleServer({
 *   masterSecret: process.env.MASTER_SECRET,
 * });
 * 
 * // Encrypt with tier-based access
 * const encrypted = await capsule.encrypt('article-123', content, {
 *   tiers: ['premium'],
 * });
 * 
 * // Or get HTML ready for templates
 * const html = await capsule.encrypt('article-123', content, {
 *   tiers: ['premium'],
 *   format: 'html',
 *   placeholder: 'Subscribe to unlock...',
 * });
 * ```
 * 
 * @example With Async Key Provider
 * ```typescript
 * import { createCapsuleWithKeyProvider } from '@sesamy/capsule-server';
 * 
 * const capsule = createCapsuleWithKeyProvider(async (articleId) => {
 *   // Fetch keys from your CMS, subscription server, or cache
 *   const response = await fetch(`/api/keys?article=${articleId}`);
 *   return response.json(); // [{ keyId, key, expiresAt? }]
 * });
 * 
 * const encrypted = await capsule.encrypt('article-123', content);
 * ```
 * 
 * @example CMS Usage (Low-Level API)
 * ```typescript
 * import { createTotpEncryptor } from '@sesamy/capsule-server';
 * 
 * const encryptor = createTotpEncryptor(process.env.MASTER_SECRET);
 * 
 * const encrypted = await encryptor.encryptArticleWithTier(
 *   'article-123',
 *   'Premium content here...',
 *   'premium'
 * );
 * ```
 * 
 * @example Subscription Server
 * ```typescript
 * import { createSubscriptionServer } from '@sesamy/capsule-server';
 * 
 * const server = createSubscriptionServer(process.env.MASTER_SECRET);
 * 
 * // Endpoint for CMS to get bucket keys
 * app.post('/api/cms/bucket-keys', (req) => {
 *   return server.getBucketKeysResponse(req.body.keyId);
 * });
 * 
 * // Endpoint for users to unlock content
 * app.post('/api/unlock', async (req) => {
 *   const { wrappedKey, publicKey } = req.body;
 *   return server.unlockForUser(wrappedKey, publicKey);
 * });
 * ```
 */

// High-level API (recommended)
export { 
  CapsuleServer, 
  createCapsule, 
  createCapsuleWithKeyProvider,
  type CapsuleServerOptions,
  type EncryptOptions,
  type KeyEntry,
  type KeyProvider,
} from "./capsule";

// CMS encryption (low-level)
export { CmsEncryptor, createTotpEncryptor, createApiEncryptor } from "./cms";

// Subscription server
export { SubscriptionServer, createSubscriptionServer } from "./subscription-server";

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
