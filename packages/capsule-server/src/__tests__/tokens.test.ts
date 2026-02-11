import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { TokenManager, createTokenManager } from "../tokens";

describe("TokenManager", () => {
  let tokens: TokenManager;
  const testSecret = "test-secret-key-that-is-at-least-32-bytes-long";

  beforeEach(() => {
    tokens = createTokenManager({
      secret: testSecret,
      issuer: "test-issuer",
      keyId: "key-2026-01",
    });
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-02-09T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("generate", () => {
    it("should generate a valid token", () => {
      const token = tokens.generate({
        tier: "premium",
        contentId: "article-123",
        expiresIn: "24h",
      });

      expect(token).toBeTruthy();
      expect(typeof token).toBe("string");
      expect(token.split(".")).toHaveLength(2);
    });

    it("should include all specified options in the payload", () => {
      const token = tokens.generate({
        tier: "premium",
        contentId: "test-article",
        expiresIn: "7d",
        url: "https://example.com/article/test-article",
        userId: "user-123",
        maxUses: 100,
        meta: { campaign: "twitter" },
      });

      const result = tokens.validate(token);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.payload.tier).toBe("premium");
        expect(result.payload.iss).toBe("test-issuer");
        expect(result.payload.kid).toBe("key-2026-01");
        expect(result.payload.contentId).toBe("test-article");
        expect(result.payload.url).toBe(
          "https://example.com/article/test-article",
        );
        expect(result.payload.userId).toBe("user-123");
        expect(result.payload.maxUses).toBe(100);
        expect(result.payload.meta).toEqual({ campaign: "twitter" });
      }
    });

    it("should generate unique token IDs", () => {
      const token1 = tokens.generate({
        tier: "premium",
        contentId: "article-1",
        expiresIn: "1h",
      });
      const token2 = tokens.generate({
        tier: "premium",
        contentId: "article-2",
        expiresIn: "1h",
      });

      const payload1 = tokens.peek(token1);
      const payload2 = tokens.peek(token2);

      expect(payload1?.tid).not.toBe(payload2?.tid);
    });

    it("should set correct expiration for various duration formats", () => {
      const now = Math.floor(Date.now() / 1000);

      const token1h = tokens.generate({
        tier: "test",
        contentId: "art-1",
        expiresIn: "1h",
      });
      expect(tokens.peek(token1h)?.exp).toBe(now + 3600);

      const token24h = tokens.generate({
        tier: "test",
        contentId: "art-2",
        expiresIn: "24h",
      });
      expect(tokens.peek(token24h)?.exp).toBe(now + 86400);

      const token7d = tokens.generate({
        tier: "test",
        contentId: "art-3",
        expiresIn: "7d",
      });
      expect(tokens.peek(token7d)?.exp).toBe(now + 604800);

      const token30s = tokens.generate({
        tier: "test",
        contentId: "art-4",
        expiresIn: "30s",
      });
      expect(tokens.peek(token30s)?.exp).toBe(now + 30);

      const token5m = tokens.generate({
        tier: "test",
        contentId: "art-5",
        expiresIn: "5m",
      });
      expect(tokens.peek(token5m)?.exp).toBe(now + 300);

      const tokenNumeric = tokens.generate({
        tier: "test",
        contentId: "art-6",
        expiresIn: 3600,
      });
      expect(tokens.peek(tokenNumeric)?.exp).toBe(now + 3600);
    });

    it("should throw for invalid duration format", () => {
      expect(() =>
        tokens.generate({
          tier: "test",
          contentId: "art",
          expiresIn: "invalid",
        }),
      ).toThrow("Invalid duration format");

      expect(() =>
        tokens.generate({ tier: "test", contentId: "art", expiresIn: "1w" }),
      ).toThrow("Invalid duration format");
    });
  });

  describe("validate", () => {
    it("should validate a valid token", () => {
      const token = tokens.generate({
        tier: "premium",
        contentId: "article-123",
        expiresIn: "24h",
      });

      const result = tokens.validate(token);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.payload.tier).toBe("premium");
        expect(result.payload.iss).toBe("test-issuer");
        expect(result.payload.kid).toBe("key-2026-01");
        expect(result.payload.v).toBe(1);
      }
    });

    it("should reject an expired token", () => {
      const token = tokens.generate({
        tier: "premium",
        contentId: "article-123",
        expiresIn: "1h",
      });

      // Advance time past expiration
      vi.advanceTimersByTime(2 * 60 * 60 * 1000); // 2 hours

      const result = tokens.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("expired");
        expect(result.message).toBe("Token has expired");
      }
    });

    it("should reject a token with invalid signature", () => {
      const token = tokens.generate({
        tier: "premium",
        contentId: "article-123",
        expiresIn: "24h",
      });

      // Tamper with the signature
      const [payload] = token.split(".");
      const tamperedToken = `${payload}.invalidsignature`;

      const result = tokens.validate(tamperedToken);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid");
        expect(result.message).toBe("Invalid signature");
      }
    });

    it("should reject a token signed with a different secret", () => {
      const otherTokens = createTokenManager({
        secret: "different-secret-that-is-also-32-bytes",
        issuer: "other-issuer",
        keyId: "other-key",
      });

      const token = otherTokens.generate({
        tier: "premium",
        contentId: "article-123",
        expiresIn: "24h",
      });

      const result = tokens.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid");
      }
    });

    it("should reject a malformed token", () => {
      const result1 = tokens.validate("not-a-valid-token");
      expect(result1.valid).toBe(false);
      if (!result1.valid) {
        expect(result1.error).toBe("malformed");
      }

      const result2 = tokens.validate("also.invalid.token.format");
      expect(result2.valid).toBe(false);

      const result3 = tokens.validate("");
      expect(result3.valid).toBe(false);
    });

    it("should reject a token with tampered payload", () => {
      const token = tokens.generate({
        tier: "premium",
        contentId: "article-123",
        expiresIn: "24h",
      });

      const [, signature] = token.split(".");
      // Create a tampered payload
      const tamperedPayload = Buffer.from(
        JSON.stringify({ tier: "enterprise", exp: 9999999999 }),
      ).toString("base64url");
      const tamperedToken = `${tamperedPayload}.${signature}`;

      const result = tokens.validate(tamperedToken);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid");
      }
    });
  });

  describe("peek", () => {
    it("should return payload without validation", () => {
      const token = tokens.generate({
        tier: "premium",
        expiresIn: "1h",
        contentId: "test-article",
      });

      // Advance time past expiration
      vi.advanceTimersByTime(2 * 60 * 60 * 1000);

      // validate should fail
      expect(tokens.validate(token).valid).toBe(false);

      // But peek should still work
      const payload = tokens.peek(token);
      expect(payload).not.toBeNull();
      expect(payload?.tier).toBe("premium");
      expect(payload?.contentId).toBe("test-article");
    });

    it("should return null for invalid tokens", () => {
      expect(tokens.peek("invalid")).toBeNull();
      expect(tokens.peek("")).toBeNull();
      expect(tokens.peek("no-dot")).toBeNull();
    });

    it("should return null for tokens with invalid payload encoding", () => {
      expect(tokens.peek("not-valid-base64.signature")).toBeNull();
    });
  });

  describe("security", () => {
    it("should warn about short secrets", () => {
      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      createTokenManager({ secret: "short", issuer: "test", keyId: "key-1" });

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("should be at least 32 bytes"),
      );

      consoleSpy.mockRestore();
    });

    it("should accept Buffer as secret", () => {
      const bufferTokens = createTokenManager({
        secret: Buffer.from(testSecret, "utf-8"),
        issuer: "buffer-issuer",
        keyId: "buffer-key",
      });

      const token = bufferTokens.generate({
        tier: "premium",
        contentId: "article-123",
        expiresIn: "1h",
      });

      const result = bufferTokens.validate(token);
      expect(result.valid).toBe(true);
    });

    it("should generate URL-safe tokens", () => {
      const token = tokens.generate({
        tier: "premium",
        contentId: "article-123",
        expiresIn: "24h",
        meta: { special: "chars+/=" },
      });

      // Token should be URL-safe (base64url encoding)
      expect(token).not.toMatch(/[+/=]/);
      expect(encodeURIComponent(token)).toBe(token);
    });
  });
});
