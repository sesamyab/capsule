import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { TokenManager, createTokenManager } from "../tokens";
import { toBase64Url } from "../web-crypto";

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
    it("should generate a valid token", async () => {
      const token = await tokens.generate({
        contentId: "premium",

        expiresIn: "24h",
      });

      expect(token).toBeTruthy();
      expect(typeof token).toBe("string");
      expect(token.split(".")).toHaveLength(2);
    });

    it("should include all specified options in the payload", async () => {
      const token = await tokens.generate({
        contentId: "premium",

        expiresIn: "7d",
        url: "https://example.com/article/test-article",
        userId: "user-123",
        maxUses: 100,
        meta: { campaign: "twitter" },
      });

      const result = await tokens.validate(token);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.payload.contentId).toBe("premium");
        expect(result.payload.iss).toBe("test-issuer");
        expect(result.payload.kid).toBe("key-2026-01");
        expect(result.payload.url).toBe(
          "https://example.com/article/test-article",
        );
        expect(result.payload.userId).toBe("user-123");
        expect(result.payload.maxUses).toBe(100);
        expect(result.payload.meta).toEqual({ campaign: "twitter" });
      }
    });

    it("should generate unique token IDs", async () => {
      const token1 = await tokens.generate({
        contentId: "premium",

        expiresIn: "1h",
      });
      const token2 = await tokens.generate({
        contentId: "premium",

        expiresIn: "1h",
      });

      const payload1 = tokens.peek(token1);
      const payload2 = tokens.peek(token2);

      expect(payload1?.tid).not.toBe(payload2?.tid);
    });

    it("should set correct expiration for various duration formats", async () => {
      const now = Math.floor(Date.now() / 1000);

      const token1h = await tokens.generate({
        contentId: "test",

        expiresIn: "1h",
      });
      expect(tokens.peek(token1h)?.exp).toBe(now + 3600);

      const token24h = await tokens.generate({
        contentId: "test",

        expiresIn: "24h",
      });
      expect(tokens.peek(token24h)?.exp).toBe(now + 86400);

      const token7d = await tokens.generate({
        contentId: "test",

        expiresIn: "7d",
      });
      expect(tokens.peek(token7d)?.exp).toBe(now + 604800);

      const token30s = await tokens.generate({
        contentId: "test",

        expiresIn: "30s",
      });
      expect(tokens.peek(token30s)?.exp).toBe(now + 30);

      const token5m = await tokens.generate({
        contentId: "test",

        expiresIn: "5m",
      });
      expect(tokens.peek(token5m)?.exp).toBe(now + 300);

      const tokenNumeric = await tokens.generate({
        contentId: "test",

        expiresIn: 3600,
      });
      expect(tokens.peek(tokenNumeric)?.exp).toBe(now + 3600);
    });

    it("should throw for invalid duration format", async () => {
      await expect(
        tokens.generate({
          contentId: "test",

          expiresIn: "invalid",
        }),
      ).rejects.toThrow("Invalid duration format");

      await expect(
        tokens.generate({ contentId: "test", expiresIn: "1w" }),
      ).rejects.toThrow("Invalid duration format");
    });
  });

  describe("validate", () => {
    it("should validate a valid token", async () => {
      const token = await tokens.generate({
        contentId: "premium",

        expiresIn: "24h",
      });

      const result = await tokens.validate(token);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.payload.contentId).toBe("premium");
        expect(result.payload.iss).toBe("test-issuer");
        expect(result.payload.kid).toBe("key-2026-01");
        expect(result.payload.v).toBe(1);
      }
    });

    it("should reject an expired token", async () => {
      const token = await tokens.generate({
        contentId: "premium",

        expiresIn: "1h",
      });

      // Advance time past expiration
      vi.advanceTimersByTime(2 * 60 * 60 * 1000); // 2 hours

      const result = await tokens.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("expired");
        expect(result.message).toBe("Token has expired");
      }
    });

    it("should reject a token with invalid signature", async () => {
      const token = await tokens.generate({
        contentId: "premium",

        expiresIn: "24h",
      });

      // Tamper with the signature
      const [payload] = token.split(".");
      const tamperedToken = `${payload}.invalidsignature`;

      const result = await tokens.validate(tamperedToken);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid");
        expect(result.message).toBe("Invalid signature");
      }
    });

    it("should reject a token signed with a different secret", async () => {
      const otherTokens = createTokenManager({
        secret: "different-secret-that-is-also-32-bytes",
        issuer: "other-issuer",
        keyId: "other-key",
      });

      const token = await otherTokens.generate({
        contentId: "premium",

        expiresIn: "24h",
      });

      const result = await tokens.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid");
      }
    });

    it("should reject a malformed token", async () => {
      const result1 = await tokens.validate("not-a-valid-token");
      expect(result1.valid).toBe(false);
      if (!result1.valid) {
        expect(result1.error).toBe("malformed");
      }

      const result2 = await tokens.validate("also.invalid.token.format");
      expect(result2.valid).toBe(false);

      const result3 = await tokens.validate("");
      expect(result3.valid).toBe(false);
    });

    it("should reject a token with tampered payload", async () => {
      const token = await tokens.generate({
        contentId: "premium",

        expiresIn: "24h",
      });

      const [, signature] = token.split(".");
      // Create a tampered payload (use base64url encoding)
      const tamperedPayload = toBase64Url(
        new TextEncoder().encode(
          JSON.stringify({ contentId: "enterprise", exp: 9999999999 }),
        ),
      );
      const tamperedToken = `${tamperedPayload}.${signature}`;

      const result = await tokens.validate(tamperedToken);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid");
      }
    });
  });

  describe("peek", () => {
    it("should return payload without validation", async () => {
      const token = await tokens.generate({
        contentId: "premium",
        expiresIn: "1h",
      });

      // Advance time past expiration
      vi.advanceTimersByTime(2 * 60 * 60 * 1000);

      // validate should fail
      expect((await tokens.validate(token)).valid).toBe(false);

      // But peek should still work
      const payload = tokens.peek(token);
      expect(payload).not.toBeNull();
      expect(payload?.contentId).toBe("premium");
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

    it("should accept Uint8Array as secret", async () => {
      const bufferTokens = createTokenManager({
        secret: new TextEncoder().encode(testSecret),
        issuer: "buffer-issuer",
        keyId: "buffer-key",
      });

      const token = await bufferTokens.generate({
        contentId: "premium",

        expiresIn: "1h",
      });

      const result = await bufferTokens.validate(token);
      expect(result.valid).toBe(true);
    });

    it("should generate URL-safe tokens", async () => {
      const token = await tokens.generate({
        contentId: "premium",

        expiresIn: "24h",
        meta: { special: "chars+/=" },
      });

      // Token should be URL-safe (base64url encoding)
      expect(token).not.toMatch(/[+/=]/);
      expect(encodeURIComponent(token)).toBe(token);
    });
  });
});
