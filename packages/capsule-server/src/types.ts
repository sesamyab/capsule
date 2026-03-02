/**
 * Type definitions for Capsule server-side encryption.
 */

/** Period key information */
export type PeriodKey = {
  /** Period identifier (time-based counter value) */
  periodId: string;
  /** 256-bit AES key for this period */
  key: Uint8Array;
  /** When this period expires */
  expiresAt: Date;
};

/** Key wrapping entry - content key wrapped with a specific key */
export type WrappedKey = {
  /** The key ID used to wrap (e.g., "premium:123456" or "article:crypto-guide") */
  keyId: string;
  /** Base64-encoded wrapped content key */
  wrappedContentKey: string;
  /** When this wrapped key expires (for time-period keys) - ISO string */
  expiresAt?: string;
};

/** Encrypted article with envelope encryption */
export type EncryptedArticle = {
  /** Unique resource identifier (specific page/article) */
  resourceId: string;
  /** Content name identifier (e.g., "premium", "bodytext") used for key derivation and caching */
  contentId?: string;
  /** Base64-encoded encrypted content (AES-256-GCM ciphertext + auth tag) */
  encryptedContent: string;
  /** Base64-encoded IV used for encryption */
  iv: string;
  /** Multiple wrapped versions of the content key for different unlock paths */
  wrappedKeys: WrappedKey[];
};

/** Configuration for key wrapping */
export type KeyWrapConfig = {
  /** Key ID (e.g., "premium", "article:crypto-guide") */
  keyId: string;
  /** 256-bit AES key-wrapping key */
  key: Uint8Array;
  /** Expiration time (for time-period keys) */
  expiresAt?: Date;
};

/** Options for the CMS encryptor */
export type CmsEncryptorOptions = {
  /** Subscription server URL (for API mode) */
  subscriptionServerUrl?: string;
  /** API key for subscription server authentication */
  apiKey?: string;
  /** Period secret for period mode (base64 encoded) */
  periodSecret?: string;
  /** Period duration in seconds (default: 30) */
  periodDurationSeconds?: number;
};

/** Subscription server client options */
export type SubscriptionClientOptions = {
  /** Subscription server base URL */
  serverUrl: string;
  /** API key for authentication */
  apiKey: string;
};

/** Response from subscription server for period keys */
export type PeriodKeysResponse = {
  /** Current period key */
  current: PeriodKey;
  /** Next period key (for clock drift handling) */
  next: PeriodKey;
};

/** Response from unlocking with a user's public key */
export type UnlockResponse = {
  /** Base64-encoded RSA-OAEP wrapped content key */
  encryptedContentKey: string;
  /** Key ID that was used */
  keyId: string;
  /** Period ID (for time-period keys) */
  periodId?: string;
  /** When the client should re-request (period expiration) */
  expiresAt: string;
};
