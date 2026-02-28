/**
 * Type definitions for Capsule Client.
 */

// =============================================================================
// Core Encrypted Data Types
// =============================================================================

/**
 * Simple encrypted payload (single key).
 */
export interface EncryptedPayload {
  /** Base64-encoded encrypted content (AES-GCM ciphertext + auth tag) */
  encryptedContent: string;
  /** Base64-encoded initialization vector (12 bytes for GCM) */
  iv: string;
  /** Base64-encoded wrapped content key (RSA-OAEP encrypted) */
  encryptedContentKey: string;
  /** Optional metadata (not encrypted) */
  metadata?: Record<string, unknown>;
}

/**
 * Wrapped key entry for multi-key scenarios.
 */
export interface WrappedKey {
  /** Key identifier (e.g., "premium:period123" or "article:slug") */
  keyId: string;
  /** Base64-encoded wrapped content key (CMK-encrypted) */
  wrappedContentKey: string;
  /** Optional expiration time */
  expiresAt?: string;
}

/**
 * Encrypted article with envelope encryption (multi-key support).
 */
export interface EncryptedArticle {
  /** Unique resource identifier (specific page/article) */
  resourceId: string;
  /** Generic content tier identifier (e.g., "premium") used for key derivation and caching */
  contentId?: string;
  /** Base64-encoded encrypted content */
  encryptedContent: string;
  /** Base64-encoded IV */
  iv: string;
  /** Array of wrapped keys for different access levels */
  wrappedKeys: WrappedKey[];
}

// =============================================================================
// Unlock Function Types
// =============================================================================

/**
 * Parameters passed to the unlock function.
 */
export interface UnlockParams {
  /** Key ID being requested (e.g., "premium:period123") */
  keyId: string;
  /** Wrapped DEK from the encrypted content (CMK-encrypted) */
  wrappedContentKey: string;
  /** User's public key (Base64 SPKI) to encrypt the content key for */
  publicKey: string;
  /** Resource ID being unlocked (specific page/article) */
  resourceId: string;
  /** Optional: pre-signed token for share link unlock */
  token?: string;
  /** Optional: request shared key mode for shared-level key access */
  mode?: "shared";
}

/**
 * Response from the unlock function.
 */
export interface UnlockResponse {
  /** Base64-encoded key encrypted with user's public key (DEK or KEK depending on keyType) */
  encryptedContentKey: string;
  /** When the key expires (ISO string or timestamp) */
  expiresAt: string | number;
  /** Period identifier for time-based keys */
  periodId?: string;
  /** Period duration in seconds */
  periodDurationSeconds?: number;
  /** Token ID (for share link unlocks) */
  tokenId?: string;
  /**
   * Type of key in encryptedContentKey:
   * - 'kek': Key-encrypting key (shared key that can unwrap any content key locally)
   * - 'dek': Data-encryption key (decrypts article content directly)
   * When absent, treated as 'dek' for backward compatibility.
   */
  keyType?: "kek" | "dek";
}

/**
 * Async function to fetch encrypted DEK from the server.
 * Called when unlocking content - should authenticate user and return encrypted DEK.
 *
 * @example
 * ```ts
 * const unlock: UnlockFunction = async ({ keyId, wrappedContentKey, publicKey }) => {
 *   const res = await fetch('/api/unlock', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify({ keyId, wrappedContentKey, publicKey }),
 *   });
 *   return res.json();
 * };
 * ```
 */
export type UnlockFunction = (params: UnlockParams) => Promise<UnlockResponse>;

// =============================================================================
// Event Types
// =============================================================================

/**
 * Base event data for all Capsule events.
 */
export interface CapsuleEventBase {
  /** Resource ID (specific page/article) */
  resourceId: string;
  /** The container element */
  element: HTMLElement;
}

/**
 * Event emitted when content is successfully unlocked.
 * Listen with: element.addEventListener('capsule:unlock', handler)
 */
export interface CapsuleUnlockEvent extends CapsuleEventBase {
  /** Key ID used to unlock */
  keyId: string;
  /** The decrypted content (HTML string) */
  content: string;
}

/**
 * Event emitted when unlock fails.
 * Listen with: element.addEventListener('capsule:error', handler)
 */
export interface CapsuleErrorEvent extends CapsuleEventBase {
  /** Error that occurred */
  error: Error;
}

/**
 * Event emitted when state changes.
 * Listen with: element.addEventListener('capsule:state', handler)
 */
export interface CapsuleStateEvent extends CapsuleEventBase {
  /** Previous state */
  previousState: ElementState;
  /** New state */
  state: ElementState;
}

/**
 * All custom event types dispatched by Capsule.
 */
export interface CapsuleEventMap {
  "capsule:unlock": CustomEvent<CapsuleUnlockEvent>;
  "capsule:error": CustomEvent<CapsuleErrorEvent>;
  "capsule:state": CustomEvent<CapsuleStateEvent>;
  "capsule:ready": CustomEvent<{ publicKey: string }>;
}

// =============================================================================
// Configuration Types
// =============================================================================

/**
 * DEK storage strategy.
 */
export type ContentKeyStorageMode = "memory" | "session" | "persist";

/**
 * State of an encrypted element.
 */
export type ElementState =
  | "locked"
  | "unlocking"
  | "decrypting"
  | "unlocked"
  | "error";

/**
 * Configuration options for CapsuleClient.
 *
 * @example Minimal setup (auto-creates keys):
 * ```ts
 * const capsule = new CapsuleClient({
 *   unlock: async (params) => {
 *     const res = await fetch('/api/unlock', {
 *       method: 'POST',
 *       body: JSON.stringify(params),
 *     });
 *     return res.json();
 *   }
 * });
 * ```
 *
 * @example Full control:
 * ```ts
 * const capsule = new CapsuleClient({
 *   keySize: 4096,
 *   autoProcess: true,
 *   executeScripts: false,
 *   contentKeyStorage: 'session',
 *   selector: '.encrypted-content',
 * });
 * ```
 */
export interface CapsuleClientOptions {
  /**
   * Async function called to unlock content.
   * Receives keyId, wrappedContentKey, publicKey, and contentId.
   * Should authenticate the user and return the encrypted DEK.
   *
   * If not provided, you must call unlock() manually with the encrypted DEK.
   */
  unlock?: UnlockFunction;

  /**
   * RSA key size in bits.
   * @default 2048
   */
  keySize?: 2048 | 4096;

  /**
   * Whether to automatically find and process encrypted elements on init.
   * Looks for elements matching the selector option.
   * @default false
   */
  autoProcess?: boolean;

  /**
   * Whether to execute script tags found in decrypted content.
   * Set to false for stricter security.
   * @default true
   */
  executeScripts?: boolean;

  /**
   * CSS selector for encrypted content containers.
   * Elements should have data-capsule attribute with JSON EncryptedArticle.
   * @default '[data-capsule]'
   */
  selector?: string;

  /**
   * How to store DEKs for offline access and performance.
   * - 'memory': DEKs only kept in memory (lost on page refresh)
   * - 'session': DEKs stored in sessionStorage (lost when tab closes)
   * - 'persist': DEKs stored in IndexedDB (survives browser restart)
   * @default 'persist'
   */
  contentKeyStorage?: ContentKeyStorageMode;

  /**
   * Time in ms before DEK expiry to auto-renew.
   * Set to 0 to disable auto-renewal.
   * @default 5000
   */
  renewBuffer?: number;

  /**
   * IndexedDB database name for key storage.
   * @default 'capsule-keys'
   */
  dbName?: string;

  /**
   * IndexedDB store name for key storage.
   * @default 'keypair'
   */
  storeName?: string;

  /**
   * Optional logger for debugging.
   * @example
   * ```ts
   * logger: (msg, level) => console.log(`[Capsule:${level}]`, msg)
   * ```
   */
  logger?: (message: string, level: "info" | "error" | "debug") => void;
}

// =============================================================================
// Storage Types
// =============================================================================

/**
 * Stored RSA key pair in IndexedDB.
 *
 * Note: The private key is stored as a CryptoKey with extractable: false,
 * meaning it cannot be exported from the browser.
 */
export interface StoredKeyPair {
  /** Key identifier */
  id: string;
  /** RSA public key (extractable) */
  publicKey: CryptoKey;
  /** RSA private key (non-extractable) */
  privateKey: CryptoKey;
  /** Creation timestamp */
  createdAt: number;
  /** Key size in bits */
  keySize: number;
}

/**
 * Stored DEK information for caching.
 */
export interface StoredContentKey {
  /** Type of key (shared or article) */
  type: "shared" | "article";
  /** Base identifier (content ID or article ID) */
  baseId: string;
  /** Base64-encoded encrypted DEK (encrypted with user's public key) */
  encryptedContentKey: string;
  /** Expiration timestamp (ms since epoch) */
  expiresAt: number;
  /** Period identifier for time-based rotation */
  periodId?: string;
}

// =============================================================================
// Web Crypto Algorithm Types
// =============================================================================

/**
 * RSA-OAEP algorithm parameters for Web Crypto API.
 */
export interface RsaOaepParams {
  name: "RSA-OAEP";
  modulusLength: number;
  publicExponent: Uint8Array;
  hash: "SHA-256";
}

/**
 * AES-GCM algorithm parameters for Web Crypto API.
 */
export interface AesGcmParams {
  name: "AES-GCM";
  length: 256;
}
