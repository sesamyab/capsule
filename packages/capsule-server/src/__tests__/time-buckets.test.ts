import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  getBucketId,
  getCurrentBucket,
  getNextBucket,
  getPreviousBucket,
  getBucketExpiration,
  isBucketValid,
  deriveBucketKey,
  getBucketKey,
  getBucketKeys,
  hkdf,
} from "../time-buckets";

// Helper to compare Uint8Arrays
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Helper to convert string to Uint8Array
function encodeUtf8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

describe("time-buckets", () => {
  describe("hkdf", () => {
    it("derives deterministic keys", async () => {
      const secret = encodeUtf8("master-secret");
      const salt = "test-salt";
      const info = "test-info";

      const key1 = await hkdf(secret, salt, info, 32);
      const key2 = await hkdf(secret, salt, info, 32);

      expect(arraysEqual(key1, key2)).toBe(true);
    });

    it("produces different keys with different salts", async () => {
      const secret = encodeUtf8("master-secret");
      const info = "test-info";

      const key1 = await hkdf(secret, "salt1", info, 32);
      const key2 = await hkdf(secret, "salt2", info, 32);

      expect(arraysEqual(key1, key2)).toBe(false);
    });

    it("produces different keys with different info", async () => {
      const secret = encodeUtf8("master-secret");
      const salt = "test-salt";

      const key1 = await hkdf(secret, salt, "info1", 32);
      const key2 = await hkdf(secret, salt, "info2", 32);

      expect(arraysEqual(key1, key2)).toBe(false);
    });

    it("produces keys of requested length", async () => {
      const secret = encodeUtf8("master-secret");

      expect((await hkdf(secret, "salt", "info", 16)).length).toBe(16);
      expect((await hkdf(secret, "salt", "info", 32)).length).toBe(32);
      expect((await hkdf(secret, "salt", "info", 64)).length).toBe(64);
    });

    it("accepts Uint8Array for salt and info", async () => {
      const secret = encodeUtf8("master-secret");
      const salt = encodeUtf8("salt");
      const info = encodeUtf8("info");

      const key = await hkdf(secret, salt, info, 32);
      expect(key.length).toBe(32);
    });
  });

  describe("getBucketId", () => {
    it("calculates bucket ID from timestamp", () => {
      // Timestamp: 1704067200000 = 2024-01-01T00:00:00Z
      // With 30s buckets: 1704067200000 / 1000 / 30 = 56802240
      const bucketId = getBucketId(1704067200000, 30);
      expect(bucketId).toBe("56802240");
    });

    it("uses default period when not specified", () => {
      const bucketId = getBucketId(1704067200000);
      expect(bucketId).toBe("56802240"); // Same as with explicit 30
    });

    it("returns same bucket for times within same period", () => {
      const t1 = 1704067200000;
      const t2 = 1704067200000 + 29 * 1000; // 29 seconds later

      expect(getBucketId(t1, 30)).toBe(getBucketId(t2, 30));
    });

    it("returns different bucket after period boundary", () => {
      const t1 = 1704067200000;
      const t2 = 1704067200000 + 30 * 1000; // Exactly 30 seconds later

      expect(getBucketId(t1, 30)).not.toBe(getBucketId(t2, 30));
    });

    it("respects custom bucket period", () => {
      // With 60s buckets: 1704067200000 / 1000 / 60 = 28401120
      const bucketId = getBucketId(1704067200000, 60);
      expect(bucketId).toBe("28401120");
    });
  });

  describe("getCurrentBucket / getNextBucket / getPreviousBucket", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("getCurrentBucket returns current bucket", () => {
      vi.setSystemTime(1704067200000);

      const current = getCurrentBucket(30);
      expect(current).toBe("56802240");
    });

    it("getNextBucket returns bucket after current", () => {
      vi.setSystemTime(1704067200000);

      const next = getNextBucket(30);
      expect(next).toBe("56802241");
    });

    it("getPreviousBucket returns bucket before current", () => {
      vi.setSystemTime(1704067200000);

      const prev = getPreviousBucket(30);
      expect(prev).toBe("56802239");
    });
  });

  describe("getBucketExpiration", () => {
    it("returns when bucket expires", () => {
      // Bucket 56802240 with 30s period expires at (56802240 + 1) * 30 * 1000
      const expiration = getBucketExpiration("56802240", 30);
      expect(expiration.getTime()).toBe(56802241 * 30 * 1000);
    });
  });

  describe("isBucketValid", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("accepts current bucket", () => {
      vi.setSystemTime(1704067200000);

      expect(isBucketValid("56802240", 30)).toBe(true);
    });

    it("accepts next bucket (for grace period)", () => {
      vi.setSystemTime(1704067200000);

      expect(isBucketValid("56802241", 30)).toBe(true);
    });

    it("accepts previous bucket (for grace period)", () => {
      vi.setSystemTime(1704067200000);

      expect(isBucketValid("56802239", 30)).toBe(true);
    });

    it("rejects old bucket", () => {
      vi.setSystemTime(1704067200000);

      expect(isBucketValid("56802238", 30)).toBe(false);
    });

    it("rejects future bucket", () => {
      vi.setSystemTime(1704067200000);

      expect(isBucketValid("56802242", 30)).toBe(false);
    });
  });

  describe("deriveBucketKey", () => {
    it("derives deterministic keys", async () => {
      const secret = encodeUtf8("master-secret-for-testing");

      const key1 = await deriveBucketKey(secret, "premium", "12345");
      const key2 = await deriveBucketKey(secret, "premium", "12345");

      expect(arraysEqual(key1, key2)).toBe(true);
    });

    it("produces 256-bit keys", async () => {
      const secret = encodeUtf8("master-secret");

      const key = await deriveBucketKey(secret, "premium", "12345");
      expect(key.length).toBe(32);
    });

    it("produces different keys for different tiers", async () => {
      const secret = encodeUtf8("master-secret");

      const premiumKey = await deriveBucketKey(secret, "premium", "12345");
      const basicKey = await deriveBucketKey(secret, "basic", "12345");

      expect(arraysEqual(premiumKey, basicKey)).toBe(false);
    });

    it("produces different keys for different buckets", async () => {
      const secret = encodeUtf8("master-secret");

      const key1 = await deriveBucketKey(secret, "premium", "12345");
      const key2 = await deriveBucketKey(secret, "premium", "12346");

      expect(arraysEqual(key1, key2)).toBe(false);
    });

    it("produces different keys for different secrets", async () => {
      const secret1 = encodeUtf8("secret1");
      const secret2 = encodeUtf8("secret2");

      const key1 = await deriveBucketKey(secret1, "premium", "12345");
      const key2 = await deriveBucketKey(secret2, "premium", "12345");

      expect(arraysEqual(key1, key2)).toBe(false);
    });
  });

  describe("getBucketKey", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(1704067200000);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("returns key with metadata", async () => {
      const secret = encodeUtf8("master-secret");

      const bucketKey = await getBucketKey(secret, "premium", "56802240", 30);

      expect(bucketKey.bucketId).toBe("56802240");
      expect(bucketKey.key).toBeInstanceOf(Uint8Array);
      expect(bucketKey.key.length).toBe(32);
      expect(bucketKey.expiresAt).toBeInstanceOf(Date);
    });
  });

  describe("getBucketKeys", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(1704067200000);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("returns current and next bucket keys", async () => {
      const secret = encodeUtf8("master-secret");

      const { current, next } = await getBucketKeys(secret, "premium", 30);

      expect(current.bucketId).toBe("56802240");
      expect(next.bucketId).toBe("56802241");
      expect(arraysEqual(current.key, next.key)).toBe(false);
    });

    it("uses default period when not specified", async () => {
      const secret = encodeUtf8("master-secret");

      const { current, next } = await getBucketKeys(secret, "premium");

      expect(parseInt(next.bucketId)).toBe(parseInt(current.bucketId) + 1);
    });
  });
});
