import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  SubscriptionServer,
  createSubscriptionServer,
} from "../subscription-server";
import { generateContentKey, wrapContentKey } from "../encryption";
import { toBase64 } from "../web-crypto";

// Generate a test RSA key pair using Web Crypto
async function generateTestKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  // Export public key as SPKI (DER) format, then base64 encode
  const publicKeyDer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const publicKeyB64 = toBase64(new Uint8Array(publicKeyDer));

  return {
    publicKeyB64,
    privateKey: keyPair.privateKey,
  };
}

// Helper to compare Uint8Arrays
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

describe("SubscriptionServer", () => {
  const periodSecret = new TextEncoder().encode(
    "test-period-secret-for-capsule-tests"
  );
  let testKeyPair: Awaited<ReturnType<typeof generateTestKeyPair>>;

  beforeEach(async () => {
    testKeyPair = await generateTestKeyPair();
    vi.useFakeTimers();
    // Set to a known time: 2024-01-01T00:00:00Z
    vi.setSystemTime(1704067200000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("createSubscriptionServer", () => {
    it("creates a SubscriptionServer instance", () => {
      const server = createSubscriptionServer({ periodSecret });
      expect(server).toBeInstanceOf(SubscriptionServer);
    });

    it("accepts base64 encoded period secret", () => {
      const server = createSubscriptionServer({
        periodSecret: toBase64(periodSecret),
      });
      expect(server).toBeInstanceOf(SubscriptionServer);
    });
  });

  describe("getPeriodKeysForCms", () => {
    it("returns current and next period keys", async () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const keys = await server.getPeriodKeysForCms("premium");

      expect(keys.current.periodId).toBe("56802240");
      expect(keys.next.periodId).toBe("56802241");
      expect(keys.current.key).toBeInstanceOf(Uint8Array);
      expect(keys.current.key.length).toBe(32);
    });
  });

  describe("getPeriodKeysResponse", () => {
    it("returns keys formatted for API response", async () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const response = await server.getPeriodKeysResponse("premium");

      expect(typeof response.current.key).toBe("string"); // Base64
      expect(typeof response.current.expiresAt).toBe("string"); // ISO date
      expect(response.current.periodId).toBe("56802240");
    });
  });

  describe("isPeriodValid", () => {
    it("validates current period", () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      expect(server.isPeriodValid("56802240")).toBe(true); // current
      expect(server.isPeriodValid("56802241")).toBe(true); // next
      expect(server.isPeriodValid("56802239")).toBe(true); // previous
      expect(server.isPeriodValid("56802238")).toBe(false); // too old
    });
  });

  describe("unlockForUser", () => {
    it("unlocks with period key", async () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      // Create a wrapped content key using the current period key
      const contentKey = generateContentKey();
      const periodKey = await server.getPeriodKey("premium", "56802240");
      const wrappedContentKeyBuffer = await wrapContentKey(contentKey, periodKey);

      const wrappedKey = {
        keyId: "premium:56802240",
        wrappedContentKey: toBase64(wrappedContentKeyBuffer),
      };

      const result = await server.unlockForUser(
        wrappedKey,
        testKeyPair.publicKeyB64
      );

      expect(result.keyId).toBe("premium:56802240");
      expect(result.periodId).toBe("56802240");
      expect(typeof result.encryptedContentKey).toBe("string");
      expect(typeof result.expiresAt).toBe("string");
    });

    it("unlocks with static key via staticKeyLookup", async () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      // Create a static key for an article
      const staticKey = generateContentKey();
      const contentKey = generateContentKey();
      const wrappedContentKeyBuffer = await wrapContentKey(contentKey, staticKey);

      const wrappedKey = {
        keyId: "article:my-article",
        wrappedContentKey: toBase64(wrappedContentKeyBuffer),
      };

      const staticKeyLookup = vi.fn().mockReturnValue(staticKey);

      const result = await server.unlockForUser(
        wrappedKey,
        testKeyPair.publicKeyB64,
        staticKeyLookup
      );

      expect(staticKeyLookup).toHaveBeenCalledWith("article:my-article");
      expect(result.keyId).toBe("article:my-article");
      expect(result.periodId).toBeUndefined(); // Static keys don't have periodId
    });

    it("supports async staticKeyLookup", async () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const staticKey = generateContentKey();
      const contentKey = generateContentKey();
      const wrappedContentKeyBuffer = await wrapContentKey(contentKey, staticKey);

      const wrappedKey = {
        keyId: "article:async-article",
        wrappedContentKey: toBase64(wrappedContentKeyBuffer),
      };

      // Async lookup
      const staticKeyLookup = vi.fn().mockResolvedValue(staticKey);

      const result = await server.unlockForUser(
        wrappedKey,
        testKeyPair.publicKeyB64,
        staticKeyLookup
      );

      expect(result.keyId).toBe("article:async-article");
    });

    it("throws for expired period", async () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const contentKey = generateContentKey();
      const oldPeriodKey = await server.getPeriodKey("premium", "56802230"); // Old period
      const wrappedContentKeyBuffer = await wrapContentKey(contentKey, oldPeriodKey);

      const wrappedKey = {
        keyId: "premium:56802230",
        wrappedContentKey: toBase64(wrappedContentKeyBuffer),
      };

      await expect(
        server.unlockForUser(wrappedKey, testKeyPair.publicKeyB64)
      ).rejects.toThrow("expired or invalid");
    });

    it("throws for static key without lookup function", async () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const wrappedKey = {
        keyId: "article:no-lookup",
        wrappedContentKey: "dummydata",
      };

      await expect(
        server.unlockForUser(wrappedKey, testKeyPair.publicKeyB64)
      ).rejects.toThrow("not a valid period ID");
    });

    it("falls back to period key when staticKeyLookup returns null", async () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const contentKey = generateContentKey();
      const periodKey = await server.getPeriodKey("premium", "56802240");
      const wrappedContentKeyBuffer = await wrapContentKey(contentKey, periodKey);

      const wrappedKey = {
        keyId: "premium:56802240",
        wrappedContentKey: toBase64(wrappedContentKeyBuffer),
      };

      // Lookup returns null - should fall back to period key
      const staticKeyLookup = vi.fn().mockReturnValue(null);

      const result = await server.unlockForUser(
        wrappedKey,
        testKeyPair.publicKeyB64,
        staticKeyLookup
      );

      expect(result.keyId).toBe("premium:56802240");
      expect(result.periodId).toBe("56802240");
    });
  });

  describe("wrapContentKeyForUser", () => {
    it("wraps content key with user public key", async () => {
      const server = createSubscriptionServer({ periodSecret });

      const contentKey = generateContentKey();
      const expiresAt = new Date(Date.now() + 60000);

      const result = await server.wrapContentKeyForUser(
        contentKey,
        testKeyPair.publicKeyB64,
        "premium:56802240",
        expiresAt
      );

      expect(result.keyId).toBe("premium:56802240");
      expect(result.periodId).toBe("56802240");
      expect(typeof result.encryptedContentKey).toBe("string");
    });

    it("handles static key IDs correctly (no periodId)", async () => {
      const server = createSubscriptionServer({ periodSecret });

      const contentKey = generateContentKey();
      const expiresAt = new Date(Date.now() + 60000);

      const result = await server.wrapContentKeyForUser(
        contentKey,
        testKeyPair.publicKeyB64,
        "article:my-guide",
        expiresAt
      );

      expect(result.keyId).toBe("article:my-guide");
      expect(result.periodId).toBeUndefined();
    });
  });

  describe("getSharedKeyForUser", () => {
    it("returns KEK wrapped with user public key", async () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const result = await server.getSharedKeyForUser(
        "premium",
        "56802240",
        testKeyPair.publicKeyB64
      );

      expect(result.keyId).toBe("premium:56802240");
      expect(result.periodId).toBe("56802240");
      expect(typeof result.encryptedContentKey).toBe("string");
    });

    it("throws for invalid period", async () => {
      const server = createSubscriptionServer({
        periodSecret,
        periodDurationSeconds: 30,
      });

      await expect(
        server.getSharedKeyForUser(
          "premium",
          "56802230",
          testKeyPair.publicKeyB64
        )
      ).rejects.toThrow("expired or invalid");
    });
  });

  describe("getPeriodKey", () => {
    it("returns the derived period key", async () => {
      const server = createSubscriptionServer({ periodSecret });

      const key = await server.getPeriodKey("premium", "12345");

      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32);
    });

    it("returns same key for same inputs", async () => {
      const server = createSubscriptionServer({ periodSecret });

      const key1 = await server.getPeriodKey("premium", "12345");
      const key2 = await server.getPeriodKey("premium", "12345");

      expect(arraysEqual(key1, key2)).toBe(true);
    });
  });
});
