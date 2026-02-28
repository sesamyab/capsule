import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  CmsServer,
  createCmsServer,
  PeriodKeyProvider,
  createPeriodKeyProvider,
} from "../capsule";
import { unwrapContentKey, decryptContent } from "../encryption";
import { fromBase64, toBase64, decodeUtf8 } from "../web-crypto";

// Helper to compare Uint8Arrays
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

describe("CmsServer", () => {
  const mockKeyProvider = vi.fn();

  beforeEach(() => {
    mockKeyProvider.mockReset();
  });

  describe("createCmsServer", () => {
    it("creates a CmsServer instance", () => {
      const cms = createCmsServer({
        getKeys: mockKeyProvider,
      });
      expect(cms).toBeInstanceOf(CmsServer);
    });

    it("throws if getKeys is not provided", () => {
      // @ts-expect-error - Testing invalid input
      expect(() => createCmsServer({})).toThrow("requires a getKeys function");
    });
  });

  describe("encrypt", () => {
    it("encrypts content with provided keys", async () => {
      const testKey = new Uint8Array(32).fill(1); // Dummy 256-bit key
      mockKeyProvider.mockResolvedValue([{ keyId: "test-key", key: testKey }]);

      const cms = createCmsServer({ getKeys: mockKeyProvider });
      const content = "Hello, World!";

      const result = await cms.encrypt("article-123", content, {
        keyIds: ["test-key"],
      });

      expect(result.resourceId).toBe("article-123");
      expect(typeof result.encryptedContent).toBe("string"); // Base64
      expect(typeof result.iv).toBe("string"); // Base64
      expect(result.wrappedKeys).toHaveLength(1);
      expect(result.wrappedKeys[0].keyId).toBe("test-key");
    });

    it("encrypts with multiple keys", async () => {
      const key1 = new Uint8Array(32).fill(1);
      const key2 = new Uint8Array(32).fill(2);
      mockKeyProvider.mockResolvedValue([
        { keyId: "premium", key: key1 },
        { keyId: "enterprise", key: key2 },
      ]);

      const cms = createCmsServer({ getKeys: mockKeyProvider });

      const result = await cms.encrypt("article-123", "Content", {
        keyIds: ["premium", "enterprise"],
      });

      expect(result.wrappedKeys).toHaveLength(2);
      expect(result.wrappedKeys.map((wk) => wk.keyId)).toContain("premium");
      expect(result.wrappedKeys.map((wk) => wk.keyId)).toContain("enterprise");
    });

    it("includes expiresAt when provided by key provider", async () => {
      const expiresAt = new Date(Date.now() + 60000);
      mockKeyProvider.mockResolvedValue([
        { keyId: "test-key", key: new Uint8Array(32).fill(1), expiresAt },
      ]);

      const cms = createCmsServer({ getKeys: mockKeyProvider });

      const result = await cms.encrypt("article-123", "Content", {
        keyIds: ["test-key"],
      });

      expect(result.wrappedKeys[0].expiresAt).toBe(expiresAt.toISOString());
    });

    it("can decrypt content with the wrapped content key", async () => {
      const wrappingKey = new Uint8Array(32).fill(1);
      mockKeyProvider.mockResolvedValue([
        { keyId: "test-key", key: wrappingKey },
      ]);

      const cms = createCmsServer({ getKeys: mockKeyProvider });
      const originalContent = "Secret premium content here!";

      const encrypted = await cms.encrypt("article-123", originalContent, {
        keyIds: ["test-key"],
      });

      // Verify we can decrypt
      const wrappedContentKey = fromBase64(encrypted.wrappedKeys[0].wrappedContentKey);
      const contentKey = await unwrapContentKey(wrappedContentKey, wrappingKey);

      const iv = fromBase64(encrypted.iv);
      const ciphertext = fromBase64(encrypted.encryptedContent);
      const decrypted = await decryptContent(ciphertext, contentKey, iv);

      expect(decodeUtf8(decrypted)).toBe(originalContent);
    });

    it("produces different ciphertext for same content (random content key and IV)", async () => {
      mockKeyProvider.mockResolvedValue([
        { keyId: "test-key", key: new Uint8Array(32).fill(1) },
      ]);

      const cms = createCmsServer({ getKeys: mockKeyProvider });
      const content = "Same content";

      const result1 = await cms.encrypt("article-1", content, {
        keyIds: ["test-key"],
      });
      const result2 = await cms.encrypt("article-2", content, {
        keyIds: ["test-key"],
      });

      expect(result1.encryptedContent).not.toBe(result2.encryptedContent);
      expect(result1.iv).not.toBe(result2.iv);
    });

    it("returns HTML format when specified", async () => {
      mockKeyProvider.mockResolvedValue([
        { keyId: "test-key", key: new Uint8Array(32).fill(1) },
      ]);

      const cms = createCmsServer({ getKeys: mockKeyProvider });

      const result = await cms.encrypt("article-123", "Content", {
        keyIds: ["test-key"],
        format: "html",
      });

      expect(typeof result).toBe("string");
      expect(result).toContain("data-capsule");
      expect(result).toContain("article-123");
    });

    it("returns HTML template format when specified", async () => {
      mockKeyProvider.mockResolvedValue([
        { keyId: "test-key", key: new Uint8Array(32).fill(1) },
      ]);

      const cms = createCmsServer({ getKeys: mockKeyProvider });

      const result = await cms.encrypt("article-123", "Content", {
        keyIds: ["test-key"],
        format: "html-template",
      });

      expect(typeof result).toBe("string");
      // Should be valid JSON
      expect(() => JSON.parse(result)).not.toThrow();
    });

    it("accepts base64 keys from provider", async () => {
      const wrappingKey = new Uint8Array(32).fill(1);
      mockKeyProvider.mockResolvedValue([
        { keyId: "test-key", key: toBase64(wrappingKey) },
      ]);

      const cms = createCmsServer({ getKeys: mockKeyProvider });
      const originalContent = "Test content";

      const encrypted = await cms.encrypt("article-123", originalContent, {
        keyIds: ["test-key"],
      });

      // Verify we can decrypt with the original key
      const wrappedContentKey = fromBase64(encrypted.wrappedKeys[0].wrappedContentKey);
      const contentKey = await unwrapContentKey(wrappedContentKey, wrappingKey);

      const iv = fromBase64(encrypted.iv);
      const ciphertext = fromBase64(encrypted.encryptedContent);
      const decrypted = await decryptContent(ciphertext, contentKey, iv);

      expect(decodeUtf8(decrypted)).toBe(originalContent);
    });

    it("handles unicode content correctly", async () => {
      mockKeyProvider.mockResolvedValue([
        { keyId: "test-key", key: new Uint8Array(32).fill(1) },
      ]);

      const cms = createCmsServer({ getKeys: mockKeyProvider });
      const originalContent = "你好世界 🌍 مرحبا العالم";

      const encrypted = await cms.encrypt("article-123", originalContent, {
        keyIds: ["test-key"],
      });

      const wrappedContentKey = fromBase64(encrypted.wrappedKeys[0].wrappedContentKey);
      const contentKey = await unwrapContentKey(wrappedContentKey, new Uint8Array(32).fill(1));
      const decrypted = await decryptContent(
        fromBase64(encrypted.encryptedContent),
        contentKey,
        fromBase64(encrypted.iv)
      );

      expect(decodeUtf8(decrypted)).toBe(originalContent);
    });
  });
});

describe("PeriodKeyProvider", () => {
  const periodSecret = new TextEncoder().encode(
    "test-period-secret-for-capsule-tests"
  );

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(1704067200000); // 2024-01-01T00:00:00Z
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("createPeriodKeyProvider", () => {
    it("creates a PeriodKeyProvider instance", () => {
      const keyProvider = createPeriodKeyProvider({ periodSecret });
      expect(keyProvider).toBeInstanceOf(PeriodKeyProvider);
    });

    it("accepts base64 encoded period secret", () => {
      const keyProvider = createPeriodKeyProvider({
        periodSecret: toBase64(periodSecret),
      });
      expect(keyProvider).toBeInstanceOf(PeriodKeyProvider);
    });
  });

  describe("getKeys", () => {
    it("returns keys for requested keyIds", async () => {
      const keyProvider = createPeriodKeyProvider({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const keys = await keyProvider.getKeys(["premium", "basic"]);

      // Should get current and next period for each tier
      expect(keys.length).toBe(4);

      const keyIds = keys.map((k) => k.keyId);
      expect(keyIds).toContain("premium:56802240");
      expect(keyIds).toContain("premium:56802241");
      expect(keyIds).toContain("basic:56802240");
      expect(keyIds).toContain("basic:56802241");
    });

    it("returns keys with expiration times", async () => {
      const keyProvider = createPeriodKeyProvider({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const keys = await keyProvider.getKeys(["premium"]);

      for (const key of keys) {
        expect(key.expiresAt).toBeInstanceOf(Date);
      }
    });

    it("returns 256-bit keys", async () => {
      const keyProvider = createPeriodKeyProvider({ periodSecret });

      const keys = await keyProvider.getKeys(["premium"]);

      for (const key of keys) {
        expect(key.key.length).toBe(32);
      }
    });

    it("returns deterministic keys", async () => {
      const period1 = createPeriodKeyProvider({
        periodSecret,
        periodDurationSeconds: 30,
      });
      const period2 = createPeriodKeyProvider({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const keys1 = await period1.getKeys(["premium"]);
      const keys2 = await period2.getKeys(["premium"]);

      expect(keys1.length).toBe(keys2.length);
      for (let i = 0; i < keys1.length; i++) {
        expect(keys1[i].keyId).toBe(keys2[i].keyId);
        // Keys from PeriodKeyProvider are always Uint8Array
        expect(arraysEqual(keys1[i].key as Uint8Array, keys2[i].key as Uint8Array)).toBe(true);
      }
    });

    it("produces different keys for different tiers", async () => {
      const keyProvider = createPeriodKeyProvider({
        periodSecret,
        periodDurationSeconds: 30,
      });

      const premiumKeys = await keyProvider.getKeys(["premium"]);
      const basicKeys = await keyProvider.getKeys(["basic"]);

      const premiumKey = premiumKeys.find((k) =>
        k.keyId.startsWith("premium:")
      )!;
      const basicKey = basicKeys.find((k) => k.keyId.startsWith("basic:"))!;

      // Keys from PeriodKeyProvider are always Uint8Array
      expect(arraysEqual(premiumKey.key as Uint8Array, basicKey.key as Uint8Array)).toBe(false);
    });
  });

  describe("integration with CmsServer", () => {
    it("works as key provider for CmsServer", async () => {
      const keyProvider = createPeriodKeyProvider({
        periodSecret,
        periodDurationSeconds: 30,
      });
      const cms = createCmsServer({
        getKeys: (keyIds) => keyProvider.getKeys(keyIds),
      });

      const content = "Premium article content";
      const encrypted = await cms.encrypt("article-123", content, {
        keyIds: ["premium"],
      });

      expect(encrypted.resourceId).toBe("article-123");
      // Should have current and next period keys
      expect(encrypted.wrappedKeys.length).toBeGreaterThanOrEqual(2);

      // Verify one of the wrapped keys can decrypt
      const currentPeriodKey = await keyProvider
        .getKeys(["premium"])
        .then((keys) => keys.find((k) => k.keyId === "premium:56802240")!);

      const wrappedKey = encrypted.wrappedKeys.find(
        (wk) => wk.keyId === "premium:56802240"
      )!;

      const wrappedContentKey = fromBase64(wrappedKey.wrappedContentKey);
      // Keys from PeriodKeyProvider are always Uint8Array
      const contentKey = await unwrapContentKey(wrappedContentKey, currentPeriodKey.key as Uint8Array);

      const decrypted = await decryptContent(
        fromBase64(encrypted.encryptedContent),
        contentKey,
        fromBase64(encrypted.iv)
      );

      expect(decodeUtf8(decrypted)).toBe(content);
    });
  });
});
