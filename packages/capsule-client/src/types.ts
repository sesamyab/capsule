/**
 * Type definitions for Capsule Client.
 */

/**
 * Encrypted payload from the server.
 */
export interface EncryptedPayload {
    /** Base64-encoded encrypted content (AES-GCM ciphertext + auth tag) */
    encryptedContent: string;
    /** Base64-encoded initialization vector (12 bytes for GCM) */
    iv: string;
    /** Base64-encoded wrapped Data Encryption Key (RSA-OAEP encrypted) */
    encryptedDek: string;
    /** Optional metadata (not encrypted) */
    metadata?: Record<string, unknown>;
}

/**
 * Configuration options for CapsuleClient.
 */
export interface CapsuleClientOptions {
    /** RSA key size in bits (default: 2048) */
    keySize?: 2048 | 4096;
    /** IndexedDB database name (default: 'capsule-keys') */
    dbName?: string;
    /** IndexedDB store name (default: 'keypair') */
    storeName?: string;
    /** Key identifier for multi-key scenarios (default: 'default') */
    keyId?: string;
}

/**
 * Stored key pair in IndexedDB.
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
 * RSA-OAEP algorithm parameters for Web Crypto API.
 */
export interface RsaOaepParams {
    name: 'RSA-OAEP';
    modulusLength: number;
    publicExponent: Uint8Array;
    hash: 'SHA-256';
}

/**
 * AES-GCM algorithm parameters for Web Crypto API.
 */
export interface AesGcmParams {
    name: 'AES-GCM';
    length: 256;
}
