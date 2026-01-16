/**
 * Capsule Client - Main client class for key management and decryption.
 *
 * Uses the Web Crypto API for all cryptographic operations:
 * - RSA-OAEP for key unwrapping (SHA-256)
 * - AES-256-GCM for content decryption
 */

import { KeyStorage } from './storage';
import type { EncryptedPayload, CapsuleClientOptions, StoredKeyPair } from './types';

/** Default key identifier */
const DEFAULT_KEY_ID = 'default';

/** RSA public exponent (65537) */
const RSA_PUBLIC_EXPONENT = new Uint8Array([0x01, 0x00, 0x01]);

/**
 * Main client for Capsule decryption operations.
 *
 * Handles:
 * - RSA key pair generation and storage
 * - Public key export for server registration
 * - Article decryption using stored private key
 */
export class CapsuleClient {
    private storage: KeyStorage;
    private keySize: 2048 | 4096;
    private keyId: string;

    /**
     * Create a new CapsuleClient instance.
     *
     * @param options - Configuration options
     */
    constructor(options: CapsuleClientOptions = {}) {
        this.keySize = options.keySize ?? 2048;
        this.keyId = options.keyId ?? DEFAULT_KEY_ID;
        this.storage = new KeyStorage(options.dbName, options.storeName);
    }

    /**
     * Generate a new RSA-OAEP key pair and store it in IndexedDB.
     *
     * The private key is stored with `extractable: false`, meaning it
     * cannot be exported from the browser.
     *
     * @returns Base64-encoded SPKI public key to send to the server
     * @throws Error if key generation fails
     */
    async generateKeyPair(): Promise<string> {
        // Generate RSA-OAEP key pair with extractable keys for export
        const exportableKeyPair = await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: this.keySize,
                publicExponent: RSA_PUBLIC_EXPONENT,
                hash: 'SHA-256',
            },
            true, // Need extractable for public key export and private key re-import
            ['wrapKey', 'unwrapKey']
        );

        // Export public key as SPKI
        const publicKeySpki = await crypto.subtle.exportKey('spki', exportableKeyPair.publicKey);
        const publicKeyB64 = this.arrayBufferToBase64(publicKeySpki);

        // Store the key pair with non-extractable private key
        // Re-import the private key as non-extractable
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', exportableKeyPair.privateKey);
        const nonExtractablePrivateKey = await crypto.subtle.importKey(
            'jwk',
            privateKeyJwk,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256',
            },
            false, // NOT extractable
            ['unwrapKey']
        );

        // Store the keys
        await this.storage.storeKeyPair(
            this.keyId,
            exportableKeyPair.publicKey, // Keep public key extractable for future exports
            nonExtractablePrivateKey,
            this.keySize
        );

        return publicKeyB64;
    }

    /**
     * Check if a key pair exists in storage.
     */
    async hasKeyPair(): Promise<boolean> {
        return this.storage.hasKeyPair(this.keyId);
    }

    /**
     * Get the stored public key as Base64 SPKI.
     *
     * @returns Base64-encoded SPKI public key
     * @throws Error if no key pair is stored
     */
    async getPublicKey(): Promise<string> {
        const keyPair = await this.getStoredKeyPair();
        const publicKeySpki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        return this.arrayBufferToBase64(publicKeySpki);
    }

    /**
     * Decrypt an encrypted article payload.
     *
     * @param payload - The encrypted payload from the server
     * @returns Decrypted article content as a string
     * @throws Error if decryption fails
     */
    async decryptArticle(payload: EncryptedPayload): Promise<string> {
        const decryptedBuffer = await this.decryptContent(payload);
        return new TextDecoder().decode(decryptedBuffer);
    }

    /**
     * Decrypt content and return raw bytes.
     *
     * @param payload - The encrypted payload from the server
     * @returns Decrypted content as ArrayBuffer
     * @throws Error if decryption fails
     */
    async decryptContent(payload: EncryptedPayload): Promise<ArrayBuffer> {
        const keyPair = await this.getStoredKeyPair();

        // Decode Base64 values
        const encryptedDek = this.base64ToArrayBuffer(payload.encryptedDek);
        const iv = this.base64ToArrayBuffer(payload.iv);
        const encryptedContent = this.base64ToArrayBuffer(payload.encryptedContent);

        // Unwrap the DEK using the private RSA key
        const dek = await crypto.subtle.unwrapKey(
            'raw',
            encryptedDek,
            keyPair.privateKey,
            {
                name: 'RSA-OAEP',
            },
            {
                name: 'AES-GCM',
                length: 256,
            },
            false, // DEK should not be extractable
            ['decrypt']
        );

        // Decrypt the content using AES-GCM
        const decryptedContent = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
            },
            dek,
            encryptedContent
        );

        return decryptedContent;
    }

    /**
     * Delete all stored keys.
     */
    async clearKeys(): Promise<void> {
        await this.storage.clearAll();
    }

    /**
     * Delete the current key pair.
     */
    async deleteKeyPair(): Promise<void> {
        await this.storage.deleteKeyPair(this.keyId);
    }

    /**
     * Get key information.
     */
    async getKeyInfo(): Promise<{ keySize: number; createdAt: number } | null> {
        const keyPair = await this.storage.getKeyPair(this.keyId);

        if (!keyPair) {
            return null;
        }

        return {
            keySize: keyPair.keySize,
            createdAt: keyPair.createdAt,
        };
    }

    /**
     * Get the stored key pair from IndexedDB.
     */
    private async getStoredKeyPair(): Promise<StoredKeyPair> {
        const keyPair = await this.storage.getKeyPair(this.keyId);

        if (!keyPair) {
            throw new Error(
                'No key pair found. Call generateKeyPair() first to create and store a key pair.'
            );
        }

        return keyPair;
    }

    /**
     * Convert ArrayBuffer to Base64 string.
     */
    private arrayBufferToBase64(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer);
        let binary = '';

        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]!);
        }

        return btoa(binary);
    }

    /**
     * Convert Base64 string to ArrayBuffer.
     */
    private base64ToArrayBuffer(base64: string): ArrayBuffer {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes.buffer;
    }
}
