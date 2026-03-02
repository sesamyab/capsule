/**
 * Tests for CapsuleClient
 *
 * These tests use jsdom for DOM APIs and fake-indexeddb for IndexedDB.
 * Web Crypto API is available in Node.js 18+.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { CapsuleClient } from "../client";
import type { EncryptedArticle, UnlockResponse } from "../types";

// Helper to convert ArrayBuffer to base64
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

// Helper to create encrypted article data for testing
async function createTestEncryptedArticle(
  resourceId: string,
  content: string,
  publicKey: CryptoKey
): Promise<{ article: EncryptedArticle; encryptedContentKeyB64: string }> {
  // Generate a content key
  const contentKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  // Encrypt content
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const encryptedContent = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    contentKey,
    encoder.encode(content)
  );

  // Export and wrap DEK with public key
  const rawDek = await crypto.subtle.exportKey("raw", contentKey);
  const wrappedContentKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    rawDek
  );

  const article: EncryptedArticle = {
    resourceId,
    encryptedContent: arrayBufferToBase64(encryptedContent),
    iv: arrayBufferToBase64(iv),
    wrappedKeys: [
      {
        keyId: "premium:12345",
        wrappedContentKey: arrayBufferToBase64(wrappedContentKey),
      },
    ],
  };

  // The encrypted content key for the client - same as wrappedContentKey
  const encryptedContentKeyB64 = arrayBufferToBase64(wrappedContentKey);

  return { article, encryptedContentKeyB64 };
}

describe("CapsuleClient", () => {
  beforeEach(() => {
    // Reset IndexedDB completely between tests
    // @ts-expect-error - replacing global indexedDB
    globalThis.indexedDB = new IDBFactory();
  });

  describe("constructor", () => {
    it("creates client with default options", () => {
      const client = new CapsuleClient();
      expect(client).toBeInstanceOf(CapsuleClient);
    });

    it("accepts custom options", () => {
      const unlock = vi.fn();
      const logger = vi.fn();

      const client = new CapsuleClient({
        keySize: 4096,
        unlock,
        autoProcess: false,
        executeScripts: false,
        selector: ".my-encrypted",
        contentKeyStorage: "session",
        renewBuffer: 10000,
        logger,
      });

      expect(client).toBeInstanceOf(CapsuleClient);
    });
  });

  describe("getPublicKey", () => {
    it("generates and returns public key", async () => {
      const client = new CapsuleClient();

      const publicKey = await client.getPublicKey();

      expect(typeof publicKey).toBe("string");
      expect(publicKey.length).toBeGreaterThan(100); // Base64 SPKI
    });

    it("returns same key on subsequent calls", async () => {
      const client = new CapsuleClient();

      const key1 = await client.getPublicKey();
      const key2 = await client.getPublicKey();

      expect(key1).toBe(key2);
    });

    it("persists key across client instances", async () => {
      const client1 = new CapsuleClient();
      const key1 = await client1.getPublicKey();

      // Create new client instance
      const client2 = new CapsuleClient();
      const key2 = await client2.getPublicKey();

      expect(key1).toBe(key2);
    });
  });

  describe("hasKeyPair", () => {
    it("returns false when no key pair exists", async () => {
      const client = new CapsuleClient();

      const hasKey = await client.hasKeyPair();

      expect(hasKey).toBe(false);
    });

    it("returns true after getPublicKey", async () => {
      const client = new CapsuleClient();
      await client.getPublicKey();

      const hasKey = await client.hasKeyPair();

      expect(hasKey).toBe(true);
    });
  });

  describe("getKeyInfo", () => {
    it("returns null when no key exists", async () => {
      const client = new CapsuleClient();

      const info = await client.getKeyInfo();

      expect(info).toBeNull();
    });

    it("returns key info after creation", async () => {
      const client = new CapsuleClient({ keySize: 2048 });
      await client.getPublicKey();

      const info = await client.getKeyInfo();

      expect(info).not.toBeNull();
      expect(info!.keySize).toBe(2048);
      expect(typeof info!.createdAt).toBe("number");
    });
  });

  describe("regenerateKeyPair", () => {
    it("creates new key pair", async () => {
      const client = new CapsuleClient();
      const key1 = await client.getPublicKey();

      const key2 = await client.regenerateKeyPair();

      expect(key2).not.toBe(key1);
    });
  });

  describe("clearAll", () => {
    it("clears all stored keys", async () => {
      const client = new CapsuleClient();
      await client.getPublicKey();

      await client.clearAll();

      const hasKey = await client.hasKeyPair();
      expect(hasKey).toBe(false);
    });
  });

  describe("decrypt", () => {
    it("decrypts content with provided encryptedContentKey", async () => {
      const client = new CapsuleClient();

      // Get the client's public key
      const publicKeyB64 = await client.getPublicKey();
      const publicKeyBuffer = Uint8Array.from(atob(publicKeyB64), (c) =>
        c.charCodeAt(0)
      );
      const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );

      // Create test encrypted article
      const originalContent = "Hello, encrypted world!";
      const { article, encryptedContentKeyB64 } = await createTestEncryptedArticle(
        "test-article",
        originalContent,
        publicKey
      );

      // Decrypt
      const decrypted = await client.decrypt(article, encryptedContentKeyB64);

      expect(decrypted).toBe(originalContent);
    });

    it("handles unicode content", async () => {
      const client = new CapsuleClient();
      const publicKeyB64 = await client.getPublicKey();
      const publicKeyBuffer = Uint8Array.from(atob(publicKeyB64), (c) =>
        c.charCodeAt(0)
      );
      const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );

      const originalContent = "你好世界 🌍 مرحبا العالم";
      const { article, encryptedContentKeyB64 } = await createTestEncryptedArticle(
        "unicode-article",
        originalContent,
        publicKey
      );

      const decrypted = await client.decrypt(article, encryptedContentKeyB64);

      expect(decrypted).toBe(originalContent);
    });
  });

  describe("unlock", () => {
    it("calls unlock function and decrypts content", async () => {
      const client = new CapsuleClient();
      const publicKeyB64 = await client.getPublicKey();
      const publicKeyBuffer = Uint8Array.from(atob(publicKeyB64), (c) =>
        c.charCodeAt(0)
      );
      const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );

      const originalContent = "Premium content here!";
      const { article, encryptedContentKeyB64 } = await createTestEncryptedArticle(
        "premium-article",
        originalContent,
        publicKey
      );

      // Create mock unlock function
      const mockUnlock = vi.fn().mockResolvedValue({
        encryptedContentKey: encryptedContentKeyB64,
        expiresAt: new Date(Date.now() + 60000).toISOString(),
        periodId: "12345",
      } satisfies UnlockResponse);

      // Create client with unlock function - use same storage
      const clientWithUnlock = new CapsuleClient({
        unlock: mockUnlock,
      });

      const decrypted = await clientWithUnlock.unlock(article);

      expect(mockUnlock).toHaveBeenCalledWith(
        expect.objectContaining({
          keyId: "premium:12345",
          wrappedContentKey: article.wrappedKeys[0].wrappedContentKey,
          resourceId: "premium-article",
        })
      );
      expect(decrypted).toBe(originalContent);
    });

    it("throws if no unlock function provided", async () => {
      const client = new CapsuleClient(); // No unlock function

      const article: EncryptedArticle = {
        resourceId: "test",
        encryptedContent: "abc",
        iv: "def",
        wrappedKeys: [{ keyId: "key1", wrappedContentKey: "ghi" }],
      };

      await expect(client.unlock(article)).rejects.toThrow(
        "No unlock function provided"
      );
    });
  });

  describe("decryptPayload", () => {
    it("decrypts simple payload", async () => {
      const client = new CapsuleClient();
      const publicKeyB64 = await client.getPublicKey();
      const publicKeyBuffer = Uint8Array.from(atob(publicKeyB64), (c) =>
        c.charCodeAt(0)
      );
      const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );

      // Generate DEK and encrypt content
      const contentKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
      );

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const originalContent = "Simple payload content";
      const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        contentKey,
        new TextEncoder().encode(originalContent)
      );

      // Wrap DEK with client's public key
      const rawDek = await crypto.subtle.exportKey("raw", contentKey);
      const encryptedContentKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        rawDek
      );

      const payload = {
        encryptedContent: arrayBufferToBase64(encryptedContent),
        iv: arrayBufferToBase64(iv),
        encryptedContentKey: arrayBufferToBase64(encryptedContentKey),
      };

      const decrypted = await client.decryptPayload(payload);

      expect(decrypted).toBe(originalContent);
    });
  });
});
