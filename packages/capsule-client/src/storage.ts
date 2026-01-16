/**
 * IndexedDB storage for RSA key pairs using the idb library.
 *
 * Keys are stored with extractable: false for the private key,
 * ensuring they cannot leave the browser.
 */

import { openDB, type IDBPDatabase } from 'idb';
import type { StoredKeyPair } from './types';

/** Default database name */
const DEFAULT_DB_NAME = 'capsule-keys';

/** Default store name */
const DEFAULT_STORE_NAME = 'keypair';

/** Database version */
const DB_VERSION = 1;

/**
 * Manages RSA key pair storage in IndexedDB.
 */
export class KeyStorage {
    private dbName: string;
    private storeName: string;
    private dbPromise: Promise<IDBPDatabase> | null = null;

    /**
     * Create a new KeyStorage instance.
     *
     * @param dbName - IndexedDB database name
     * @param storeName - Object store name for keys
     */
    constructor(dbName: string = DEFAULT_DB_NAME, storeName: string = DEFAULT_STORE_NAME) {
        this.dbName = dbName;
        this.storeName = storeName;
    }

    /**
     * Open or create the IndexedDB database.
     */
    private async getDb(): Promise<IDBPDatabase> {
        if (!this.dbPromise) {
            const storeName = this.storeName;

            this.dbPromise = openDB(this.dbName, DB_VERSION, {
                upgrade(db) {
                    // Create the key store if it doesn't exist
                    if (!db.objectStoreNames.contains(storeName)) {
                        db.createObjectStore(storeName, { keyPath: 'id' });
                    }
                },
            });
        }

        return this.dbPromise;
    }

    /**
     * Store a key pair in IndexedDB.
     *
     * @param keyId - Unique identifier for the key pair
     * @param publicKey - RSA public key (extractable)
     * @param privateKey - RSA private key (non-extractable)
     * @param keySize - Key size in bits
     */
    async storeKeyPair(
        keyId: string,
        publicKey: CryptoKey,
        privateKey: CryptoKey,
        keySize: number
    ): Promise<void> {
        const db = await this.getDb();

        const storedKeyPair: StoredKeyPair = {
            id: keyId,
            publicKey,
            privateKey,
            createdAt: Date.now(),
            keySize,
        };

        await db.put(this.storeName, storedKeyPair);
    }

    /**
     * Retrieve a key pair from IndexedDB.
     *
     * @param keyId - The key identifier
     * @returns The stored key pair, or null if not found
     */
    async getKeyPair(keyId: string): Promise<StoredKeyPair | null> {
        const db = await this.getDb();
        const result = await db.get(this.storeName, keyId);

        return (result as StoredKeyPair) || null;
    }

    /**
     * Check if a key pair exists.
     *
     * @param keyId - The key identifier
     */
    async hasKeyPair(keyId: string): Promise<boolean> {
        const keyPair = await this.getKeyPair(keyId);
        return keyPair !== null;
    }

    /**
     * Delete a key pair from IndexedDB.
     *
     * @param keyId - The key identifier
     */
    async deleteKeyPair(keyId: string): Promise<void> {
        const db = await this.getDb();
        await db.delete(this.storeName, keyId);
    }

    /**
     * Delete all stored key pairs.
     */
    async clearAll(): Promise<void> {
        const db = await this.getDb();
        await db.clear(this.storeName);
    }

    /**
     * List all stored key IDs.
     */
    async listKeyIds(): Promise<string[]> {
        const db = await this.getDb();
        const keys = await db.getAllKeys(this.storeName);
        return keys as string[];
    }
}
