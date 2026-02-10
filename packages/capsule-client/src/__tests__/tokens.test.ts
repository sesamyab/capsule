import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  parseShareToken,
  getShareTokenFromUrl,
  validateTokenForContent,
  TokenValidator,
  createTokenValidator,
  ParsedToken,
} from "../tokens";

describe("parseShareToken", () => {
  // Create a valid token payload
  const createMockPayload = (overrides = {}) => ({
    v: 1,
    tid: "test-token-id",
    iss: "test-issuer",
    kid: "key-2026-01",
    tier: "premium",
    contentId: "article-123",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
    ...overrides,
  });

  // Create a token string (without real signature)
  const createToken = (payload: object) => {
    const payloadB64 = btoa(JSON.stringify(payload))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    return `${payloadB64}.fake-signature`;
  };

  it("should parse a valid token", () => {
    const payload = createMockPayload();
    const token = createToken(payload);

    const result = parseShareToken(token);

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.payload.iss).toBe("test-issuer");
      expect(result.payload.kid).toBe("key-2026-01");
      expect(result.payload.tier).toBe("premium");
      expect(result.payload.contentId).toBe("article-123");
      expect(result.expired).toBe(false);
      expect(result.expiresIn).toBeGreaterThan(0);
    }
  });

  it("should detect expired tokens", () => {
    const payload = createMockPayload({
      exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
    });
    const token = createToken(payload);

    const result = parseShareToken(token);

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.expired).toBe(true);
      expect(result.expiresIn).toBeLessThan(0);
    }
  });

  it("should include optional fields when present", () => {
    const payload = createMockPayload({
      url: "https://example.com/article/123",
      userId: "user-456",
      maxUses: 100,
      meta: { campaign: "twitter" },
    });
    const token = createToken(payload);

    const result = parseShareToken(token);

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.payload.url).toBe("https://example.com/article/123");
      expect(result.payload.userId).toBe("user-456");
      expect(result.payload.maxUses).toBe(100);
      expect(result.payload.meta).toEqual({ campaign: "twitter" });
    }
  });

  it("should reject tokens without separator", () => {
    const result = parseShareToken("no-separator-token");

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("invalid_format");
    }
  });

  it("should reject tokens with invalid base64", () => {
    const result = parseShareToken("!!!invalid-base64!!!.signature");

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("malformed");
    }
  });

  it("should reject tokens missing required fields", () => {
    const incompletePayload = { v: 1, tier: "premium" }; // Missing iss, kid, contentId, exp
    const token = createToken(incompletePayload);

    const result = parseShareToken(token);

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error).toBe("malformed");
      expect(result.message).toContain("required fields");
    }
  });
});

describe("validateTokenForContent", () => {
  const createParsedToken = (overrides = {}): ParsedToken => ({
    valid: true,
    expired: false,
    expiresIn: 3600,
    payload: {
      v: 1,
      tid: "test-id",
      iss: "test-issuer",
      kid: "key-1",
      tier: "premium",
      contentId: "article-123",
      iat: Date.now() / 1000,
      exp: Date.now() / 1000 + 3600,
      ...overrides,
    },
  });

  it("should validate when contentId matches", () => {
    const tokenResult = createParsedToken({ contentId: "article-123" });

    const result = validateTokenForContent(tokenResult, "article-123");

    expect(result.valid).toBe(true);
  });

  it("should reject when contentId doesn't match", () => {
    const tokenResult = createParsedToken({ contentId: "article-123" });

    const result = validateTokenForContent(tokenResult, "different-article");

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain("article-123");
      expect(result.reason).toContain("different-article");
    }
  });

  it("should reject expired tokens", () => {
    const tokenResult: ParsedToken = {
      valid: true,
      expired: true,
      expiresIn: -3600,
      payload: createParsedToken().payload,
    };

    const result = validateTokenForContent(tokenResult, "article-123");

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toContain("expired");
    }
  });
});

describe("getShareTokenFromUrl", () => {
  const originalWindow = global.window;

  beforeEach(() => {
    // Mock window for browser environment
    global.window = {
      location: {
        search: "",
      },
    } as typeof window;
  });

  afterEach(() => {
    global.window = originalWindow;
  });

  it("should return null when no token in URL", () => {
    global.window.location.search = "";

    const result = getShareTokenFromUrl();

    expect(result).toBeNull();
  });

  it("should return null when window is undefined (SSR)", () => {
    delete (global as any).window;

    const result = getShareTokenFromUrl();

    expect(result).toBeNull();

    // Restore
    global.window = originalWindow;
  });

  it("should parse token from URL", () => {
    const payload = {
      v: 1,
      tid: "url-token-id",
      iss: "url-issuer",
      kid: "key-url",
      tier: "premium",
      contentId: "url-article",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    const payloadB64 = btoa(JSON.stringify(payload))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    const token = `${payloadB64}.signature`;

    global.window.location.search = `?token=${encodeURIComponent(token)}`;

    const result = getShareTokenFromUrl();

    expect(result).not.toBeNull();
    if (result && result.valid) {
      expect(result.token).toBe(token);
      expect(result.payload.contentId).toBe("url-article");
      expect(result.payload.iss).toBe("url-issuer");
    }
  });

  it("should return error for invalid token in URL", () => {
    global.window.location.search = "?token=invalid-token";

    const result = getShareTokenFromUrl();

    expect(result).not.toBeNull();
    expect(result?.valid).toBe(false);
  });
});

// Helper to create HMAC-SHA256 signed tokens (matching server implementation)
async function createSignedToken(
  payload: object,
  secret: string
): Promise<string> {
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = btoa(payloadJson)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(payloadB64);

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, messageData);
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return `${payloadB64}.${signatureB64}`;
}

describe("TokenValidator", () => {
  const testSecret = "test-secret-for-signing-tokens-32-bytes";
  const testIssuer = "test-publisher";
  const testKeyId = "key-2026-01";

  const createValidPayload = (overrides = {}) => ({
    v: 1,
    tid: "test-token-id",
    iss: testIssuer,
    kid: testKeyId,
    tier: "premium",
    contentId: "article-123",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  });

  describe("validate with provided secret", () => {
    it("should validate a correctly signed token", async () => {
      const validator = new TokenValidator();
      const payload = createValidPayload();
      const token = await createSignedToken(payload, testSecret);

      const result = await validator.validate(token, { secret: testSecret });

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.trusted).toBe(false); // No trusted keys configured
        expect(result.expired).toBe(false);
        expect(result.payload.contentId).toBe("article-123");
      }
    });

    it("should reject a token with wrong signature", async () => {
      const validator = new TokenValidator();
      const payload = createValidPayload();
      const token = await createSignedToken(payload, testSecret);

      const result = await validator.validate(token, {
        secret: "wrong-secret",
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid_signature");
      }
    });

    it("should reject expired tokens", async () => {
      const validator = new TokenValidator();
      const payload = createValidPayload({
        exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
      });
      const token = await createSignedToken(payload, testSecret);

      const result = await validator.validate(token, { secret: testSecret });

      expect(result.valid).toBe(true); // Signature is valid
      if (result.valid) {
        expect(result.expired).toBe(true);
        expect(result.expiresIn).toBeLessThan(0);
      }
    });

    it("should fail without secret", async () => {
      const validator = new TokenValidator();
      const payload = createValidPayload();
      const token = await createSignedToken(payload, testSecret);

      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("no_secret");
      }
    });
  });

  describe("validate with trusted keys", () => {
    it("should validate token from trusted issuer", async () => {
      const validator = new TokenValidator({
        trustedKeys: {
          [`${testIssuer}:${testKeyId}`]: testSecret,
        },
      });
      const payload = createValidPayload();
      const token = await createSignedToken(payload, testSecret);

      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.trusted).toBe(true);
        expect(result.payload.iss).toBe(testIssuer);
      }
    });

    it("should reject unknown issuer when requireTrustedIssuer is true", async () => {
      const validator = new TokenValidator({
        trustedKeys: {
          "other-issuer:key-1": "other-secret",
        },
        requireTrustedIssuer: true,
      });
      const payload = createValidPayload();
      const token = await createSignedToken(payload, testSecret);

      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("untrusted_issuer");
        expect(result.message).toContain(testIssuer);
      }
    });

    it("should accept unknown issuer with provided secret when requireTrustedIssuer is false", async () => {
      const validator = new TokenValidator({
        trustedKeys: {
          "other-issuer:key-1": "other-secret",
        },
        requireTrustedIssuer: false,
      });
      const payload = createValidPayload();
      const token = await createSignedToken(payload, testSecret);

      const result = await validator.validate(token, { secret: testSecret });

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.trusted).toBe(false); // Not from trusted list
      }
    });
  });

  describe("isTrusted", () => {
    it("should return true for trusted issuer/key", () => {
      const validator = new TokenValidator({
        trustedKeys: {
          "my-publisher:key-v1": "secret",
        },
      });

      expect(validator.isTrusted("my-publisher", "key-v1")).toBe(true);
      expect(validator.isTrusted("my-publisher", "key-v2")).toBe(false);
      expect(validator.isTrusted("other-publisher", "key-v1")).toBe(false);
    });
  });

  describe("addTrustedKey / removeTrustedKey", () => {
    it("should add and remove trusted keys at runtime", async () => {
      const validator = new TokenValidator();

      expect(validator.isTrusted(testIssuer, testKeyId)).toBe(false);

      validator.addTrustedKey(testIssuer, testKeyId, testSecret);
      expect(validator.isTrusted(testIssuer, testKeyId)).toBe(true);

      // Should now validate without providing secret
      const payload = createValidPayload();
      const token = await createSignedToken(payload, testSecret);
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);

      validator.removeTrustedKey(testIssuer, testKeyId);
      expect(validator.isTrusted(testIssuer, testKeyId)).toBe(false);
    });
  });

  describe("validate with contentId", () => {
    it("should pass when contentId matches", async () => {
      const validator = new TokenValidator();
      const payload = createValidPayload({ contentId: "my-article" });
      const token = await createSignedToken(payload, testSecret);

      const result = await validator.validate(token, {
        secret: testSecret,
        contentId: "my-article",
      });

      expect(result.valid).toBe(true);
    });

    it("should fail when contentId doesn't match", async () => {
      const validator = new TokenValidator();
      const payload = createValidPayload({ contentId: "my-article" });
      const token = await createSignedToken(payload, testSecret);

      const result = await validator.validate(token, {
        secret: testSecret,
        contentId: "different-article",
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.message).toContain("my-article");
        expect(result.message).toContain("different-article");
      }
    });
  });

  describe("malformed tokens", () => {
    it("should reject token without separator", async () => {
      const validator = new TokenValidator();

      const result = await validator.validate("no-separator-token", {
        secret: testSecret,
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid_format");
      }
    });

    it("should reject token with invalid base64", async () => {
      const validator = new TokenValidator();

      const result = await validator.validate("!!!invalid!!!.signature", {
        secret: testSecret,
      });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("malformed");
      }
    });

    it("should reject token missing required fields", async () => {
      const validator = new TokenValidator();
      const incompletePayload = { v: 1, tier: "premium" };
      const payloadB64 = btoa(JSON.stringify(incompletePayload))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
      const token = `${payloadB64}.fake-signature`;

      const result = await validator.validate(token, { secret: testSecret });

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("malformed");
        expect(result.message).toContain("required fields");
      }
    });
  });
});

describe("createTokenValidator", () => {
  it("should create a TokenValidator instance", () => {
    const validator = createTokenValidator({
      trustedKeys: { "issuer:key": "secret" },
    });

    expect(validator).toBeInstanceOf(TokenValidator);
    expect(validator.isTrusted("issuer", "key")).toBe(true);
  });
});
