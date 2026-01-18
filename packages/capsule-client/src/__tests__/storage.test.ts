/**
 * Tests for KeyStorage (IndexedDB key pair storage)
 */

import { describe, it, expect, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import { KeyStorage } from "../storage";

// Helper to generate test key pair
async function generateTestKeyPair(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

describe("KeyStorage", () => {
  let storage: KeyStorage;

  beforeEach(() => {
    // Use a unique database name for each test to avoid conflicts
    const dbName = `test-keys-${Date.now()}-${Math.random()}`;
    storage = new KeyStorage(dbName, "keypair");
  });

  describe("constructor", () => {
    it("creates storage with default names", () => {
      const defaultStorage = new KeyStorage();
      expect(defaultStorage).toBeInstanceOf(KeyStorage);
    });

    it("creates storage with custom names", () => {
      const customStorage = new KeyStorage("my-db", "my-store");
      expect(customStorage).toBeInstanceOf(KeyStorage);
    });
  });

  describe("storeKeyPair / getKeyPair", () => {
    it("stores and retrieves key pair", async () => {
      const keyPair = await generateTestKeyPair();

      await storage.storeKeyPair(
        "test-key",
        keyPair.publicKey,
        keyPair.privateKey,
        2048
      );

      const retrieved = await storage.getKeyPair("test-key");

      expect(retrieved).not.toBeNull();
      expect(retrieved!.id).toBe("test-key");
      expect(retrieved!.keySize).toBe(2048);
      expect(typeof retrieved!.createdAt).toBe("number");
      expect(retrieved!.publicKey).toBeDefined();
      expect(retrieved!.privateKey).toBeDefined();
    });

    it("returns null for non-existent key", async () => {
      const retrieved = await storage.getKeyPair("non-existent");

      expect(retrieved).toBeNull();
    });

    it("overwrites existing key pair", async () => {
      const keyPair1 = await generateTestKeyPair();
      const keyPair2 = await generateTestKeyPair();

      await storage.storeKeyPair(
        "test-key",
        keyPair1.publicKey,
        keyPair1.privateKey,
        2048
      );
      await storage.storeKeyPair(
        "test-key",
        keyPair2.publicKey,
        keyPair2.privateKey,
        4096
      );

      const retrieved = await storage.getKeyPair("test-key");

      expect(retrieved!.keySize).toBe(4096);
    });

    it("stores multiple key pairs", async () => {
      const keyPair1 = await generateTestKeyPair();
      const keyPair2 = await generateTestKeyPair();

      await storage.storeKeyPair(
        "key-1",
        keyPair1.publicKey,
        keyPair1.privateKey,
        2048
      );
      await storage.storeKeyPair(
        "key-2",
        keyPair2.publicKey,
        keyPair2.privateKey,
        2048
      );

      const retrieved1 = await storage.getKeyPair("key-1");
      const retrieved2 = await storage.getKeyPair("key-2");

      expect(retrieved1).not.toBeNull();
      expect(retrieved2).not.toBeNull();
      expect(retrieved1!.id).toBe("key-1");
      expect(retrieved2!.id).toBe("key-2");
    });
  });

  describe("hasKeyPair", () => {
    it("returns false when key does not exist", async () => {
      const exists = await storage.hasKeyPair("non-existent");

      expect(exists).toBe(false);
    });

    it("returns true when key exists", async () => {
      const keyPair = await generateTestKeyPair();
      await storage.storeKeyPair(
        "test-key",
        keyPair.publicKey,
        keyPair.privateKey,
        2048
      );

      const exists = await storage.hasKeyPair("test-key");

      expect(exists).toBe(true);
    });
  });

  describe("deleteKeyPair", () => {
    it("deletes existing key pair", async () => {
      const keyPair = await generateTestKeyPair();
      await storage.storeKeyPair(
        "test-key",
        keyPair.publicKey,
        keyPair.privateKey,
        2048
      );

      await storage.deleteKeyPair("test-key");

      const exists = await storage.hasKeyPair("test-key");
      expect(exists).toBe(false);
    });

    it("does not throw when deleting non-existent key", async () => {
      await expect(
        storage.deleteKeyPair("non-existent")
      ).resolves.not.toThrow();
    });
  });

  describe("clearAll", () => {
    it("clears all stored keys", async () => {
      const keyPair1 = await generateTestKeyPair();
      const keyPair2 = await generateTestKeyPair();

      await storage.storeKeyPair(
        "key-1",
        keyPair1.publicKey,
        keyPair1.privateKey,
        2048
      );
      await storage.storeKeyPair(
        "key-2",
        keyPair2.publicKey,
        keyPair2.privateKey,
        2048
      );

      await storage.clearAll();

      const keys = await storage.listKeyIds();
      expect(keys).toHaveLength(0);
    });
  });

  describe("listKeyIds", () => {
    it("returns empty array when no keys stored", async () => {
      const keys = await storage.listKeyIds();

      expect(keys).toEqual([]);
    });

    it("returns all stored key IDs", async () => {
      const keyPair = await generateTestKeyPair();

      await storage.storeKeyPair(
        "key-a",
        keyPair.publicKey,
        keyPair.privateKey,
        2048
      );
      await storage.storeKeyPair(
        "key-b",
        keyPair.publicKey,
        keyPair.privateKey,
        2048
      );
      await storage.storeKeyPair(
        "key-c",
        keyPair.publicKey,
        keyPair.privateKey,
        2048
      );

      const keys = await storage.listKeyIds();

      expect(keys).toHaveLength(3);
      expect(keys).toContain("key-a");
      expect(keys).toContain("key-b");
      expect(keys).toContain("key-c");
    });
  });

  describe("key usability", () => {
    it("stored keys can be used for encryption/decryption", async () => {
      const keyPair = await generateTestKeyPair();
      await storage.storeKeyPair(
        "test-key",
        keyPair.publicKey,
        keyPair.privateKey,
        2048
      );

      const retrieved = await storage.getKeyPair("test-key");

      // Test that keys work for encryption
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      const encrypted = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        retrieved!.publicKey,
        testData
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        retrieved!.privateKey,
        encrypted
      );

      expect(new Uint8Array(decrypted)).toEqual(testData);
    });
  });
});
