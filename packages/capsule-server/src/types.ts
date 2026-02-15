/**
 * Type definitions for Capsule server-side encryption.
 */

/** Bucket key information */
export interface BucketKey {
  /** Bucket identifier (TOTP counter value) */
  bucketId: string;
  /** 256-bit AES key for this bucket */
  key: Uint8Array;
  /** When this bucket expires */
  expiresAt: Date;
}

/** Key wrapping entry - DEK wrapped with a specific key */
export interface WrappedKey {
  /** The key ID used to wrap (e.g., "premium:123456" or "article:crypto-guide") */
  keyId: string;
  /** Base64-encoded wrapped DEK */
  wrappedDek: string;
  /** When this wrapped key expires (for time-bucket keys) - ISO string */
  expiresAt?: string;
}

/** Encrypted article with envelope encryption */
export interface EncryptedArticle {
  /** Unique article identifier */
  articleId: string;
  /** Base64-encoded encrypted content (AES-256-GCM ciphertext + auth tag) */
  encryptedContent: string;
  /** Base64-encoded IV used for encryption */
  iv: string;
  /** Multiple wrapped versions of the content DEK for different unlock paths */
  wrappedKeys: WrappedKey[];
}

/** Configuration for key wrapping */
export interface KeyWrapConfig {
  /** Key ID (e.g., "premium", "article:crypto-guide") */
  keyId: string;
  /** 256-bit AES key-wrapping key */
  key: Uint8Array;
  /** Expiration time (for time-bucket keys) */
  expiresAt?: Date;
}

/** Options for the CMS encryptor */
export interface CmsEncryptorOptions {
  /** Subscription server URL (for API mode) */
  subscriptionServerUrl?: string;
  /** API key for subscription server authentication */
  apiKey?: string;
  /** Master secret for TOTP mode (base64 encoded) */
  masterSecret?: string;
  /** Bucket period in seconds (default: 30) */
  bucketPeriodSeconds?: number;
}

/** Subscription server client options */
export interface SubscriptionClientOptions {
  /** Subscription server base URL */
  serverUrl: string;
  /** API key for authentication */
  apiKey: string;
}

/** Response from subscription server for bucket keys */
export interface BucketKeysResponse {
  /** Current bucket key */
  current: BucketKey;
  /** Next bucket key (for clock drift handling) */
  next: BucketKey;
}

/** Response from unlocking with a user's public key */
export interface UnlockResponse {
  /** Base64-encoded RSA-OAEP wrapped DEK */
  encryptedDek: string;
  /** Key ID that was used */
  keyId: string;
  /** Bucket ID (for time-bucket keys) */
  bucketId?: string;
  /** When the client should re-request (bucket expiration) */
  expiresAt: string;
}
