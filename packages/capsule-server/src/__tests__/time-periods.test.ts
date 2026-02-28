import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  getPeriodId,
  getCurrentPeriod,
  getNextPeriod,
  getPreviousPeriod,
  getPeriodExpiration,
  isPeriodValid,
  derivePeriodKey,
  getPeriodKey,
  getPeriodKeys,
  hkdf,
} from "../time-periods";

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

describe("time-periods", () => {
  describe("hkdf", () => {
    it("derives deterministic keys", async () => {
      const secret = encodeUtf8("period-secret");
      const salt = "test-salt";
      const info = "test-info";

      const key1 = await hkdf(secret, salt, info, 32);
      const key2 = await hkdf(secret, salt, info, 32);

      expect(arraysEqual(key1, key2)).toBe(true);
    });

    it("produces different keys with different salts", async () => {
      const secret = encodeUtf8("period-secret");
      const info = "test-info";

      const key1 = await hkdf(secret, "salt1", info, 32);
      const key2 = await hkdf(secret, "salt2", info, 32);

      expect(arraysEqual(key1, key2)).toBe(false);
    });

    it("produces different keys with different info", async () => {
      const secret = encodeUtf8("period-secret");
      const salt = "test-salt";

      const key1 = await hkdf(secret, salt, "info1", 32);
      const key2 = await hkdf(secret, salt, "info2", 32);

      expect(arraysEqual(key1, key2)).toBe(false);
    });

    it("produces keys of requested length", async () => {
      const secret = encodeUtf8("period-secret");

      expect((await hkdf(secret, "salt", "info", 16)).length).toBe(16);
      expect((await hkdf(secret, "salt", "info", 32)).length).toBe(32);
      expect((await hkdf(secret, "salt", "info", 64)).length).toBe(64);
    });

    it("accepts Uint8Array for salt and info", async () => {
      const secret = encodeUtf8("period-secret");
      const salt = encodeUtf8("salt");
      const info = encodeUtf8("info");

      const key = await hkdf(secret, salt, info, 32);
      expect(key.length).toBe(32);
    });
  });

  describe("getPeriodId", () => {
    it("calculates period ID from timestamp", () => {
      // Timestamp: 1704067200000 = 2024-01-01T00:00:00Z
      // With 30s periods: 1704067200000 / 1000 / 30 = 56802240
      const periodId = getPeriodId(1704067200000, 30);
      expect(periodId).toBe("56802240");
    });

    it("uses default period when not specified", () => {
      const periodId = getPeriodId(1704067200000);
      expect(periodId).toBe("56802240"); // Same as with explicit 30
    });

    it("returns same period for times within same period", () => {
      const t1 = 1704067200000;
      const t2 = 1704067200000 + 29 * 1000; // 29 seconds later

      expect(getPeriodId(t1, 30)).toBe(getPeriodId(t2, 30));
    });

    it("returns different period after period boundary", () => {
      const t1 = 1704067200000;
      const t2 = 1704067200000 + 30 * 1000; // Exactly 30 seconds later

      expect(getPeriodId(t1, 30)).not.toBe(getPeriodId(t2, 30));
    });

    it("respects custom period duration", () => {
      // With 60s periods: 1704067200000 / 1000 / 60 = 28401120
      const periodId = getPeriodId(1704067200000, 60);
      expect(periodId).toBe("28401120");
    });
  });

  describe("getCurrentPeriod / getNextPeriod / getPreviousPeriod", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("getCurrentPeriod returns current period", () => {
      vi.setSystemTime(1704067200000);

      const current = getCurrentPeriod(30);
      expect(current).toBe("56802240");
    });

    it("getNextPeriod returns period after current", () => {
      vi.setSystemTime(1704067200000);

      const next = getNextPeriod(30);
      expect(next).toBe("56802241");
    });

    it("getPreviousPeriod returns period before current", () => {
      vi.setSystemTime(1704067200000);

      const prev = getPreviousPeriod(30);
      expect(prev).toBe("56802239");
    });
  });

  describe("getPeriodExpiration", () => {
    it("returns when period expires", () => {
      // Period 56802240 with 30s period expires at (56802240 + 1) * 30 * 1000
      const expiration = getPeriodExpiration("56802240", 30);
      expect(expiration.getTime()).toBe(56802241 * 30 * 1000);
    });
  });

  describe("isPeriodValid", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("accepts current period", () => {
      vi.setSystemTime(1704067200000);

      expect(isPeriodValid("56802240", 30)).toBe(true);
    });

    it("accepts next period (for grace period)", () => {
      vi.setSystemTime(1704067200000);

      expect(isPeriodValid("56802241", 30)).toBe(true);
    });

    it("accepts previous period (for grace period)", () => {
      vi.setSystemTime(1704067200000);

      expect(isPeriodValid("56802239", 30)).toBe(true);
    });

    it("rejects old period", () => {
      vi.setSystemTime(1704067200000);

      expect(isPeriodValid("56802238", 30)).toBe(false);
    });

    it("rejects future period", () => {
      vi.setSystemTime(1704067200000);

      expect(isPeriodValid("56802242", 30)).toBe(false);
    });
  });

  describe("derivePeriodKey", () => {
    it("derives deterministic keys", async () => {
      const secret = encodeUtf8("period-secret-for-testing");

      const key1 = await derivePeriodKey(secret, "premium", "12345");
      const key2 = await derivePeriodKey(secret, "premium", "12345");

      expect(arraysEqual(key1, key2)).toBe(true);
    });

    it("produces 256-bit keys", async () => {
      const secret = encodeUtf8("period-secret");

      const key = await derivePeriodKey(secret, "premium", "12345");
      expect(key.length).toBe(32);
    });

    it("produces different keys for different content IDs", async () => {
      const secret = encodeUtf8("period-secret");

      const premiumKey = await derivePeriodKey(secret, "premium", "12345");
      const basicKey = await derivePeriodKey(secret, "basic", "12345");

      expect(arraysEqual(premiumKey, basicKey)).toBe(false);
    });

    it("produces different keys for different periods", async () => {
      const secret = encodeUtf8("period-secret");

      const key1 = await derivePeriodKey(secret, "premium", "12345");
      const key2 = await derivePeriodKey(secret, "premium", "12346");

      expect(arraysEqual(key1, key2)).toBe(false);
    });

    it("produces different keys for different secrets", async () => {
      const secret1 = encodeUtf8("secret1");
      const secret2 = encodeUtf8("secret2");

      const key1 = await derivePeriodKey(secret1, "premium", "12345");
      const key2 = await derivePeriodKey(secret2, "premium", "12345");

      expect(arraysEqual(key1, key2)).toBe(false);
    });
  });

  describe("getPeriodKey", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(1704067200000);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("returns key with metadata", async () => {
      const secret = encodeUtf8("period-secret");

      const periodKey = await getPeriodKey(secret, "premium", "56802240", 30);

      expect(periodKey.periodId).toBe("56802240");
      expect(periodKey.key).toBeInstanceOf(Uint8Array);
      expect(periodKey.key.length).toBe(32);
      expect(periodKey.expiresAt).toBeInstanceOf(Date);
    });
  });

  describe("getPeriodKeys", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(1704067200000);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("returns current and next period keys", async () => {
      const secret = encodeUtf8("period-secret");

      const { current, next } = await getPeriodKeys(secret, "premium", 30);

      expect(current.periodId).toBe("56802240");
      expect(next.periodId).toBe("56802241");
      expect(arraysEqual(current.key, next.key)).toBe(false);
    });

    it("uses default period when not specified", async () => {
      const secret = encodeUtf8("period-secret");

      const { current, next } = await getPeriodKeys(secret, "premium");

      expect(parseInt(next.periodId)).toBe(parseInt(current.periodId) + 1);
    });
  });
});
