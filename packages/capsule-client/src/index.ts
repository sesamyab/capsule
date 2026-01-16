/**
 * Capsule Client - Secure article decryption using Web Crypto API.
 *
 * This library provides client-side key management and decryption:
 * - RSA-OAEP key pair generation and storage
 * - Non-extractable private keys in IndexedDB
 * - AES-256-GCM content decryption
 */

export { CapsuleClient } from './client';
export { KeyStorage } from './storage';
export type {
    EncryptedPayload,
    CapsuleClientOptions,
    StoredKeyPair,
} from './types';
