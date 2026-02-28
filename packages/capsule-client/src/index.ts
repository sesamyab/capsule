/**
 * Capsule Client - Secure article decryption using Web Crypto API.
 *
 * This library provides client-side key management and decryption:
 * - RSA-OAEP key pair generation and storage (auto-creates on first use)
 * - Non-extractable private keys in IndexedDB
 * - AES-256-GCM content decryption
 * - Automatic content key caching and renewal
 * - HTML element processing with script execution
 * - Custom events for unlock lifecycle
 *
 * @example Minimal setup:
 * ```ts
 * import { CapsuleClient } from '@sesamy/capsule';
 *
 * const capsule = new CapsuleClient({
 *   unlock: async ({ keyId, wrappedContentKey, publicKey }) => {
 *     const res = await fetch('/api/unlock', {
 *       method: 'POST',
 *       headers: { 'Content-Type': 'application/json' },
 *       body: JSON.stringify({ keyId, wrappedContentKey, publicKey }),
 *     });
 *     return res.json();
 *   }
 * });
 *
 * // Unlock a specific article
 * await capsule.unlockElement('article-123');
 *
 * // Or process all encrypted elements on the page
 * await capsule.processAll();
 * ```
 *
 * @example Auto-process with events:
 * ```ts
 * const capsule = new CapsuleClient({
 *   unlock: myUnlockFn,
 *   autoProcess: true,
 * });
 *
 * document.addEventListener('capsule:unlock', (e) => {
 *   console.log('Unlocked:', e.detail.contentId);
 * });
 *
 * document.addEventListener('capsule:error', (e) => {
 *   console.error('Failed:', e.detail.contentId, e.detail.error);
 * });
 * ```
 *
 * @example Low-level manual control:
 * ```ts
 * const capsule = new CapsuleClient();
 * const publicKey = await capsule.getPublicKey();
 * // ... send publicKey to server, get encryptedContentKey back ...
 * const content = await capsule.decrypt(encryptedArticle, encryptedContentKey);
 * ```
 */

export { CapsuleClient } from "./client";
export { KeyStorage } from "./storage";
export {
  parseShareToken,
  getShareTokenFromUrl,
  validateTokenForContent,
  TokenValidator,
  createTokenValidator,
  JwksTokenValidator,
  createJwksTokenValidator,
  type ShareTokenPayload,
  type ParsedToken,
  type TokenParseError,
  type TrustedKeys,
  type TokenValidatorOptions,
  type TokenValidationSuccess,
  type TokenValidationFailure,
  type TokenValidationResult,
  type JwkKey,
  type Jwks,
  type JwksTokenValidatorOptions,
  type JwksValidationSuccess,
  type JwksValidationFailure,
  type JwksValidationResult,
} from "./tokens";
export type {
  // Core data types
  EncryptedPayload,
  EncryptedArticle,
  WrappedKey,

  // Unlock function types
  UnlockParams,
  UnlockResponse,
  UnlockFunction,

  // Event types
  CapsuleUnlockEvent,
  CapsuleErrorEvent,
  CapsuleStateEvent,
  CapsuleEventMap,

  // Configuration
  CapsuleClientOptions,
  ContentKeyStorageMode,
  ElementState,

  // Storage types
  StoredKeyPair,
  StoredContentKey,
} from "./types";

// DCA Client
export {
  DcaClient,
  type DcaClientOptions,
  type DcaParsedPage,
  type DcaPeriodKeyCache,
  type DcaData as DcaClientData,
  type DcaUnlockResponse as DcaClientUnlockResponse,
} from "./dca-client";
