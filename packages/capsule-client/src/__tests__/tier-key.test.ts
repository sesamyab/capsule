/**
 * Tests for tier key flow: "unlock once, access all" within a tier.
 *
 * Tests the full lifecycle:
 * 1. Server returns keyType: "kek" (tier key-wrapping key)
 * 2. Client caches the tier key
 * 3. Subsequent articles in the same tier are unwrapped locally (zero network)
 * 4. prefetchTierKey() pre-warms the cache
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
 * Wrap a DEK with a wrapping key using AES-GCM (same format as capsule-server).
 * Returns: IV (12 bytes) + AES-GCM(DEK + auth tag)
 */
async function wrapDek(
  dekRaw: Uint8Array,
  wrappingKey: CryptoKey,
): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    dekRaw,
  );
  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), iv.length);
  return result;
}

/**
 * Create a test encrypted article using envelope encryption.
 *
 * @param articleId - Article ID
 * @param content - Plaintext content
 * @param tierKey - The tier key-wrapping key (AES-256)
 * @param tier - Tier name (e.g., "premium")
 * @param bucketId - Bucket ID (e.g., "12345")
 * @returns EncryptedArticle and the raw DEK
 */
async function createTierEncryptedArticle(
  articleId: string,
  content: string,
  tierKey: CryptoKey,
  tier: string,
  bucketId: string,
): Promise<{ article: EncryptedArticle; dekRaw: Uint8Array }> {
  // Generate unique DEK for this article
  const { key: dek, raw: dekRaw } = await generateRawAesKey();

  // Encrypt content with the DEK
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedContent = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    dek,
    new TextEncoder().encode(content),
  );

  // Wrap the DEK with the tier key (mimics server-side wrapDek)
  const wrappedDekBytes = await wrapDek(dekRaw, tierKey);

  return {
    article: {
      articleId,
      encryptedContent: arrayBufferToBase64(encryptedContent),
      iv: arrayBufferToBase64(iv),
      wrappedKeys: [
        {
          keyId: `${tier}:${bucketId}`,
          wrappedDek: arrayBufferToBase64(wrappedDekBytes),
        },
      ],
    },
    dekRaw,
  };
}

/**
 * RSA-OAEP encrypt a raw AES key with the client's public key.
 * Mimics server-side getTierKeyForUser response.
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

describe("Tier Key Flow", () => {
  beforeEach(() => {
    // @ts-expect-error - replacing global indexedDB
    globalThis.indexedDB = new IDBFactory();
  });

  describe("unlock() with keyType: kek", () => {
    it("fetches tier key and decrypts article locally", async () => {
      // Set up: create a tier key and encrypted article
      const { key: tierKey, raw: tierKeyRaw } = await generateRawAesKey();
      const tier = "premium";
      const bucketId = "12345";
      const originalContent = "Premium article content";

      const { article } = await createTierEncryptedArticle(
        "article-1",
        originalContent,
        tierKey,
        tier,
        bucketId,
      );

      const client = new CapsuleClient();
      await client.getPublicKey();

      // Mock unlock function: returns the tier key (KEK), not the article DEK
      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedDek = await rsaEncryptKey(tierKeyRaw, params.publicKey);
        return {
          encryptedDek,
          expiresAt: new Date(Date.now() + 30000).toISOString(),
          bucketId,
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
          keyId: `${tier}:${bucketId}`,
          mode: "tier",
        }),
      );
    });

    it("uses cached tier key for subsequent articles (zero network)", async () => {
      const { key: tierKey, raw: tierKeyRaw } = await generateRawAesKey();
      const tier = "premium";
      const bucketId = "12345";

      // Create 3 articles encrypted with the same tier key
      const articles = await Promise.all([
        createTierEncryptedArticle("art-1", "Content 1", tierKey, tier, bucketId),
        createTierEncryptedArticle("art-2", "Content 2", tierKey, tier, bucketId),
        createTierEncryptedArticle("art-3", "Content 3", tierKey, tier, bucketId),
      ]);

      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedDek = await rsaEncryptKey(tierKeyRaw, params.publicKey);
        return {
          encryptedDek,
          expiresAt: new Date(Date.now() + 30000).toISOString(),
          bucketId,
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
      // Only 1 server call! Articles 2 and 3 used the cached tier key.
      expect(mockUnlock).toHaveBeenCalledTimes(1);
    });

    it("falls back to per-article DEK when server returns keyType: dek", async () => {
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
      const { key: dek, raw: dekRaw } = await generateRawAesKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        dek,
        new TextEncoder().encode("DEK-mode content"),
      );

      const rsaWrappedDek = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        dekRaw,
      );

      const article: EncryptedArticle = {
        articleId: "dek-article",
        encryptedContent: arrayBufferToBase64(encryptedContent),
        iv: arrayBufferToBase64(iv),
        wrappedKeys: [
          { keyId: "premium:12345", wrappedDek: "irrelevant-for-dek-mode" },
        ],
      };

      const mockUnlock = vi.fn().mockResolvedValue({
        encryptedDek: arrayBufferToBase64(rsaWrappedDek),
        expiresAt: new Date(Date.now() + 30000).toISOString(),
        bucketId: "12345",
        keyType: "dek", // Standard per-article DEK response
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

      const { key: dek, raw: dekRaw } = await generateRawAesKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        dek,
        new TextEncoder().encode("Old server content"),
      );

      const rsaWrappedDek = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        dekRaw,
      );

      const article: EncryptedArticle = {
        articleId: "legacy-article",
        encryptedContent: arrayBufferToBase64(encryptedContent),
        iv: arrayBufferToBase64(iv),
        wrappedKeys: [
          { keyId: "premium:12345", wrappedDek: "not-used" },
        ],
      };

      const mockUnlock = vi.fn().mockResolvedValue({
        encryptedDek: arrayBufferToBase64(rsaWrappedDek),
        expiresAt: new Date(Date.now() + 30000).toISOString(),
        bucketId: "12345",
        // No keyType field at all — old server response
      } as UnlockResponse);

      const clientWithUnlock = new CapsuleClient({ unlock: mockUnlock });
      const decrypted = await clientWithUnlock.unlock(article);

      expect(decrypted).toBe("Old server content");
    });
  });

  describe("prefetchTierKey()", () => {
    it("pre-fetches tier key and enables local unlock", async () => {
      const { key: tierKey, raw: tierKeyRaw } = await generateRawAesKey();
      const tier = "premium";
      const bucketId = "12345";

      const { article } = await createTierEncryptedArticle(
        "prefetch-article",
        "Pre-fetched content",
        tierKey,
        tier,
        bucketId,
      );

      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedDek = await rsaEncryptKey(tierKeyRaw, params.publicKey);
        return {
          encryptedDek,
          expiresAt: new Date(Date.now() + 30000).toISOString(),
          bucketId,
          keyType: "kek",
        } satisfies UnlockResponse;
      });

      const client = new CapsuleClient({ unlock: mockUnlock });

      // Pre-fetch
      const result = await client.prefetchTierKey(`${tier}:${bucketId}`);
      expect(result.bucketId).toBe(bucketId);
      expect(result.expiresAt).toBeGreaterThan(Date.now());

      // Verify prefetch made one call
      expect(mockUnlock).toHaveBeenCalledTimes(1);

      // Now unlock should use cached tier key (no additional server calls)
      const decrypted = await client.unlock(article);
      expect(decrypted).toBe("Pre-fetched content");
      expect(mockUnlock).toHaveBeenCalledTimes(1); // Still just 1 call
    });

    it("returns cached info if already pre-fetched", async () => {
      const { raw: tierKeyRaw } = await generateRawAesKey();
      const tier = "premium";
      const bucketId = "12345";

      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedDek = await rsaEncryptKey(tierKeyRaw, params.publicKey);
        return {
          encryptedDek,
          expiresAt: new Date(Date.now() + 30000).toISOString(),
          bucketId,
          keyType: "kek",
        } satisfies UnlockResponse;
      });

      const client = new CapsuleClient({ unlock: mockUnlock });

      // Pre-fetch twice
      await client.prefetchTierKey(`${tier}:${bucketId}`);
      await client.prefetchTierKey(`${tier}:${bucketId}`);

      // Only 1 server call
      expect(mockUnlock).toHaveBeenCalledTimes(1);
    });

    it("throws if no unlock function provided", async () => {
      const client = new CapsuleClient();
      await expect(client.prefetchTierKey("premium:12345")).rejects.toThrow(
        "No unlock function provided",
      );
    });

    it("throws if server returns dek instead of kek", async () => {
      const mockUnlock = vi.fn().mockResolvedValue({
        encryptedDek: "some-base64",
        expiresAt: new Date(Date.now() + 30000).toISOString(),
        bucketId: "12345",
        keyType: "dek",
      });

      const client = new CapsuleClient({ unlock: mockUnlock });
      await expect(client.prefetchTierKey("premium:12345")).rejects.toThrow(
        "expected keyType 'kek'",
      );
    });
  });

  describe("tier key expiry", () => {
    it("re-fetches tier key after expiry", async () => {
      const { key: tierKey, raw: tierKeyRaw } = await generateRawAesKey();
      const tier = "premium";
      const bucketId = "12345";

      const { article: article1 } = await createTierEncryptedArticle(
        "art-1",
        "Content 1",
        tierKey,
        tier,
        bucketId,
      );
      const { article: article2 } = await createTierEncryptedArticle(
        "art-2",
        "Content 2",
        tierKey,
        tier,
        bucketId,
      );

      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedDek = await rsaEncryptKey(tierKeyRaw, params.publicKey);
        return {
          encryptedDek,
          // Already expired
          expiresAt: new Date(Date.now() - 1000).toISOString(),
          bucketId,
          keyType: "kek",
        } satisfies UnlockResponse;
      });

      const client = new CapsuleClient({ unlock: mockUnlock, renewBuffer: 0 });

      // First unlock: fetches tier key
      await client.unlock(article1);
      expect(mockUnlock).toHaveBeenCalledTimes(1);

      // Second unlock: tier key is expired, must fetch again
      await client.unlock(article2);
      expect(mockUnlock).toHaveBeenCalledTimes(2);
    });
  });

  describe("clearAll clears tier keys", () => {
    it("clears tier key cache on clearAll", async () => {
      const { key: tierKey, raw: tierKeyRaw } = await generateRawAesKey();
      const tier = "premium";
      const bucketId = "12345";

      const { article } = await createTierEncryptedArticle(
        "art-1",
        "Content 1",
        tierKey,
        tier,
        bucketId,
      );

      const mockUnlock = vi.fn().mockImplementation(async (params) => {
        const encryptedDek = await rsaEncryptKey(tierKeyRaw, params.publicKey);
        return {
          encryptedDek,
          expiresAt: new Date(Date.now() + 30000).toISOString(),
          bucketId,
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
