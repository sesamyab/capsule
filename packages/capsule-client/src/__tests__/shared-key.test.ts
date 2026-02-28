/**
 * Tests for shared key flow: "unlock once, access all" within a content ID.
 *
 * Tests the full lifecycle:
 * 1. Server returns keyType: "kek" (shared key-wrapping key)
 * 2. Client caches the shared key
 * 3. Subsequent articles in the same content ID are unwrapped locally (zero network)
 * 4. prefetchSharedKey() pre-warms the cache
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { CapsuleClient } from "../client";
import type { EncryptedArticle, UnlockResponse } from "../types";

// =========================================================================
// Helpers
// =========================================================================

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function base64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Generate a random 256-bit AES key as raw bytes. */
async function generateRawAesKey(): Promise<{
  key: CryptoKey;
  raw: Uint8Array;
}> {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return { key, raw };
}

/**
 * Wrap a content key with a wrapping key using AES-GCM (same format as capsule-server).
 * Returns: IV (12 bytes) + AES-GCM(DEK + auth tag)
 */
async function wrapContentKey(
  contentKeyRaw: Uint8Array,
  wrappingKey: CryptoKey,
): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    contentKeyRaw,
  );
  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), iv.length);
  return result;
}

/**
 * Create a test encrypted article using envelope encryption.
 *
 * @param resourceId - Resource ID (specific page/article)
 * @param content - Plaintext content
 * @param sharedKey - The shared key-wrapping key (AES-256)
 * @param contentId - Content ID (e.g., "premium")
 * @param periodId - Period ID (e.g., "12345")
 * @returns EncryptedArticle and the raw DEK
 */
async function createSharedEncryptedArticle(
  resourceId: string,
  content: string,
  sharedKey: CryptoKey,
  contentId: string,
  periodId: string,
): Promise<{ article: EncryptedArticle; contentKeyRaw: Uint8Array }> {
  // Generate unique content key for this article
  const { key: contentKey, raw: contentKeyRaw } = await generateRawAesKey();

  // Encrypt content with the content key
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedContent = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    contentKey,
    new TextEncoder().encode(content),
  );

  // Wrap the content key with the shared key (mimics server-side wrapContentKey)
  const wrappedContentKeyBytes = await wrapContentKey(contentKeyRaw, sharedKey);

  return {
    article: {
      resourceId,
      encryptedContent: arrayBufferToBase64(encryptedContent),
      iv: arrayBufferToBase64(iv),
      wrappedKeys: [
        {
          keyId: `${contentId}:${periodId}`,
          wrappedContentKey: arrayBufferToBase64(wrappedContentKeyBytes),
        },
      ],
    },
    contentKeyRaw,
  };
}

/**
 * RSA-OAEP encrypt a raw AES key with the client's public key.
 * Mimics server-side getSharedKeyForUser response.
 */
async function rsaEncryptKey(
  rawKey: Uint8Array,
  publicKeyB64: string,
): Promise<string> {
  const publicKeyBuffer = base64ToUint8Array(publicKeyB64);
  const publicKey = await crypto.subtle.importKey(
    "spki",
    publicKeyBuffer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  const encrypted = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    rawKey,
  );
  return arrayBufferToBase64(encrypted);
}

// =========================================================================
// Tests
// =========================================================================

describe("Shared Key Flow", () => {
  beforeEach(() => {
    // @ts-expect-error - replacing global indexedDB
    globalThis.indexedDB = new IDBFactory();
  });

  describe("unlock() with keyType: kek", () => {
    it("fetches shared key and decrypts article locally", async () => {
      // Set up: create a shared key and encrypted article
      const { key: sharedKey, raw: sharedKeyRaw } = await generateRawAesKey();
      const contentId = "premium";
      const periodId = "12345";
      const originalContent = "Premium article content";

      const { article } = await createSharedEncryptedArticle(
        "article-1",
        originalContent,
        sharedKey,
        contentId,
        periodId,
      );

      const client = new CapsuleClient();
      await client.getPublicKey();

      // Mock unlock function: returns the shared key (KEK), not the content key
      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedContentKey = await rsaEncryptKey(sharedKeyRaw, params.publicKey);
        return {
          encryptedContentKey,
          expiresAt: new Date(Date.now() + 30000).toISOString(),
          periodId,
          keyType: "kek",
        } satisfies UnlockResponse;
      });

      const clientWithUnlock = new CapsuleClient({ unlock: mockUnlock });

      // Act
      const decrypted = await clientWithUnlock.unlock(article);

      // Assert
      expect(decrypted).toBe(originalContent);
      expect(mockUnlock).toHaveBeenCalledTimes(1);
      expect(mockUnlock).toHaveBeenCalledWith(
        expect.objectContaining({
          keyId: `${contentId}:${periodId}`,
          mode: "shared",
        }),
      );
    });

    it("uses cached shared key for subsequent articles (zero network)", async () => {
      const { key: sharedKey, raw: sharedKeyRaw } = await generateRawAesKey();
      const contentId = "premium";
      const periodId = "12345";

      // Create 3 articles encrypted with the same shared key
      const articles = await Promise.all([
        createSharedEncryptedArticle("art-1", "Content 1", sharedKey, contentId, periodId),
        createSharedEncryptedArticle("art-2", "Content 2", sharedKey, contentId, periodId),
        createSharedEncryptedArticle("art-3", "Content 3", sharedKey, contentId, periodId),
      ]);

      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedContentKey = await rsaEncryptKey(sharedKeyRaw, params.publicKey);
        return {
          encryptedContentKey,
          expiresAt: new Date(Date.now() + 30000).toISOString(),
          periodId,
          keyType: "kek",
        } satisfies UnlockResponse;
      });

      const client = new CapsuleClient({ unlock: mockUnlock });

      // Unlock all 3 articles
      const results = [];
      for (const { article } of articles) {
        results.push(await client.unlock(article));
      }

      // All decrypted correctly
      expect(results).toEqual(["Content 1", "Content 2", "Content 3"]);
      // Only 1 server call! Articles 2 and 3 used the cached shared key.
      expect(mockUnlock).toHaveBeenCalledTimes(1);
    });

    it("falls back to per-content key when server returns keyType: dek", async () => {
      const client = new CapsuleClient();
      const clientPubKey = await client.getPublicKey();
      const publicKeyBuffer = base64ToUint8Array(clientPubKey);
      const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"],
      );

      // Create a standard encrypted article (DEK directly RSA-wrapped)
      const { key: contentKey, raw: contentKeyRaw } = await generateRawAesKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        contentKey,
        new TextEncoder().encode("DEK-mode content"),
      );

      const rsaWrappedDek = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        contentKeyRaw,
      );

      const article: EncryptedArticle = {
        resourceId: "dek-article",
        encryptedContent: arrayBufferToBase64(encryptedContent),
        iv: arrayBufferToBase64(iv),
        wrappedKeys: [
          { keyId: "premium:12345", wrappedContentKey: "irrelevant-for-dek-mode" },
        ],
      };

      const mockUnlock = vi.fn().mockResolvedValue({
        encryptedContentKey: arrayBufferToBase64(rsaWrappedDek),
        expiresAt: new Date(Date.now() + 30000).toISOString(),
        periodId: "12345",
        keyType: "dek", // Standard per-content key response
      } satisfies UnlockResponse);

      const clientWithUnlock = new CapsuleClient({ unlock: mockUnlock });

      const decrypted = await clientWithUnlock.unlock(article);

      expect(decrypted).toBe("DEK-mode content");
    });

    it("works without keyType field (backward compatible)", async () => {
      const client = new CapsuleClient();
      const clientPubKey = await client.getPublicKey();
      const publicKeyBuffer = base64ToUint8Array(clientPubKey);
      const publicKey = await crypto.subtle.importKey(
        "spki",
        publicKeyBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"],
      );

      const { key: contentKey, raw: contentKeyRaw } = await generateRawAesKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        contentKey,
        new TextEncoder().encode("Old server content"),
      );

      const rsaWrappedDek = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        contentKeyRaw,
      );

      const article: EncryptedArticle = {
        resourceId: "legacy-article",
        encryptedContent: arrayBufferToBase64(encryptedContent),
        iv: arrayBufferToBase64(iv),
        wrappedKeys: [
          { keyId: "premium:12345", wrappedContentKey: "not-used" },
        ],
      };

      const mockUnlock = vi.fn().mockResolvedValue({
        encryptedContentKey: arrayBufferToBase64(rsaWrappedDek),
        expiresAt: new Date(Date.now() + 30000).toISOString(),
        periodId: "12345",
        // No keyType field at all — old server response
      } as UnlockResponse);

      const clientWithUnlock = new CapsuleClient({ unlock: mockUnlock });
      const decrypted = await clientWithUnlock.unlock(article);

      expect(decrypted).toBe("Old server content");
    });
  });

  describe("prefetchSharedKey()", () => {
    it("pre-fetches shared key and enables local unlock", async () => {
      const { key: sharedKey, raw: sharedKeyRaw } = await generateRawAesKey();
      const contentId = "premium";
      const periodId = "12345";

      const { article } = await createSharedEncryptedArticle(
        "prefetch-article",
        "Pre-fetched content",
        sharedKey,
        contentId,
        periodId,
      );

      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedContentKey = await rsaEncryptKey(sharedKeyRaw, params.publicKey);
        return {
          encryptedContentKey,
          expiresAt: new Date(Date.now() + 30000).toISOString(),
          periodId,
          keyType: "kek",
        } satisfies UnlockResponse;
      });

      const client = new CapsuleClient({ unlock: mockUnlock });

      // Pre-fetch
      const result = await client.prefetchSharedKey(`${contentId}:${periodId}`);
      expect(result.periodId).toBe(periodId);
      expect(result.expiresAt).toBeGreaterThan(Date.now());

      // Verify prefetch made one call
      expect(mockUnlock).toHaveBeenCalledTimes(1);

      // Now unlock should use cached shared key (no additional server calls)
      const decrypted = await client.unlock(article);
      expect(decrypted).toBe("Pre-fetched content");
      expect(mockUnlock).toHaveBeenCalledTimes(1); // Still just 1 call
    });

    it("returns cached info if already pre-fetched", async () => {
      const { raw: sharedKeyRaw } = await generateRawAesKey();
      const contentId = "premium";
      const periodId = "12345";

      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedContentKey = await rsaEncryptKey(sharedKeyRaw, params.publicKey);
        return {
          encryptedContentKey,
          expiresAt: new Date(Date.now() + 30000).toISOString(),
          periodId,
          keyType: "kek",
        } satisfies UnlockResponse;
      });

      const client = new CapsuleClient({ unlock: mockUnlock });

      // Pre-fetch twice
      await client.prefetchSharedKey(`${contentId}:${periodId}`);
      await client.prefetchSharedKey(`${contentId}:${periodId}`);

      // Only 1 server call
      expect(mockUnlock).toHaveBeenCalledTimes(1);
    });

    it("throws if no unlock function provided", async () => {
      const client = new CapsuleClient();
      await expect(client.prefetchSharedKey("premium:12345")).rejects.toThrow(
        "No unlock function provided",
      );
    });

    it("throws if server returns dek instead of kek", async () => {
      const mockUnlock = vi.fn().mockResolvedValue({
        encryptedContentKey: "some-base64",
        expiresAt: new Date(Date.now() + 30000).toISOString(),
        periodId: "12345",
        keyType: "dek",
      });

      const client = new CapsuleClient({ unlock: mockUnlock });
      await expect(client.prefetchSharedKey("premium:12345")).rejects.toThrow(
        "expected keyType 'kek'",
      );
    });
  });

  describe("shared key expiry", () => {
    it("re-fetches shared key after expiry", async () => {
      const { key: sharedKey, raw: sharedKeyRaw } = await generateRawAesKey();
      const contentId = "premium";
      const periodId = "12345";

      const { article: article1 } = await createSharedEncryptedArticle(
        "art-1",
        "Content 1",
        sharedKey,
        contentId,
        periodId,
      );
      const { article: article2 } = await createSharedEncryptedArticle(
        "art-2",
        "Content 2",
        sharedKey,
        contentId,
        periodId,
      );

      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedContentKey = await rsaEncryptKey(sharedKeyRaw, params.publicKey);
        return {
          encryptedContentKey,
          // Already expired
          expiresAt: new Date(Date.now() - 1000).toISOString(),
          periodId,
          keyType: "kek",
        } satisfies UnlockResponse;
      });

      const client = new CapsuleClient({ unlock: mockUnlock, renewBuffer: 0 });

      // First unlock: fetches shared key
      await client.unlock(article1);
      expect(mockUnlock).toHaveBeenCalledTimes(1);

      // Second unlock: shared key is expired, must fetch again
      await client.unlock(article2);
      expect(mockUnlock).toHaveBeenCalledTimes(2);
    });
  });

  describe("clearAll clears shared keys", () => {
    it("clears shared key cache on clearAll", async () => {
      const { key: sharedKey, raw: sharedKeyRaw } = await generateRawAesKey();
      const contentId = "premium";
      const periodId = "12345";

      const { article } = await createSharedEncryptedArticle(
        "art-1",
        "Content 1",
        sharedKey,
        contentId,
        periodId,
      );

      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedContentKey = await rsaEncryptKey(sharedKeyRaw, params.publicKey);
        return {
          encryptedContentKey,
          expiresAt: new Date(Date.now() + 30000).toISOString(),
          periodId,
          keyType: "kek",
        } satisfies UnlockResponse;
      });

      const client = new CapsuleClient({ unlock: mockUnlock });

      // Populate cache
      await client.unlock(article);
      expect(mockUnlock).toHaveBeenCalledTimes(1);

      // Clear everything
      await client.clearAll();

      // Next unlock must fetch again
      await client.unlock(article);
      expect(mockUnlock).toHaveBeenCalledTimes(2);
    });
  });
});
