/**
 * Tests for JwksTokenValidator - Ed25519 signature validation with JWKS discovery
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  JwksTokenValidator,
  createJwksTokenValidator,
  type JwkKey,
} from "../tokens";

// Ed25519 test key pair (pre-generated for deterministic tests)
// In a real scenario, these would be generated with crypto.subtle.generateKey
const TEST_ISSUER = "https://api.example.com";
const TEST_KEY_ID = "key-2025-01";

// Helper to create base64url encoding
function base64url(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Helper to create a mock JWKS response
function createMockJwks(keys: JwkKey[]) {
  return { keys };
}

// Helper to sign a payload with Ed25519
async function signPayload(
  privateKey: CryptoKey,
  payloadB64: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const signature = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    encoder.encode(payloadB64),
  );
  return base64url(new Uint8Array(signature));
}

// Helper to create a token
async function createToken(
  privateKey: CryptoKey,
  payload: Record<string, unknown>,
): Promise<string> {
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = btoa(payloadJson)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const signature = await signPayload(privateKey, payloadB64);
  return `${payloadB64}.${signature}`;
}

describe("JwksTokenValidator", () => {
  let keyPair: CryptoKeyPair;
  let publicKeyJwk: JwkKey;

  beforeEach(async () => {
    // Generate Ed25519 key pair for testing
    keyPair = await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ]);

    // Export public key as JWK
    const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    publicKeyJwk = {
      kty: "OKP",
      crv: "Ed25519",
      kid: TEST_KEY_ID,
      x: jwk.x!,
      use: "sig",
      alg: "EdDSA",
    };
  });

  describe("constructor", () => {
    it("creates validator with trusted issuers", () => {
      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
      });
      expect(validator.isTrustedIssuer(TEST_ISSUER)).toBe(true);
    });

    it("normalizes issuer URLs by removing trailing slashes", () => {
      const validator = new JwksTokenValidator({
        trustedIssuers: [`${TEST_ISSUER}/`],
      });
      expect(validator.isTrustedIssuer(TEST_ISSUER)).toBe(true);
      expect(validator.isTrustedIssuer(`${TEST_ISSUER}/`)).toBe(true);
    });
  });

  describe("issuer management", () => {
    it("adds trusted issuer", () => {
      const validator = new JwksTokenValidator({ trustedIssuers: [] });
      expect(validator.isTrustedIssuer(TEST_ISSUER)).toBe(false);

      validator.addTrustedIssuer(TEST_ISSUER);
      expect(validator.isTrustedIssuer(TEST_ISSUER)).toBe(true);
    });

    it("removes trusted issuer", () => {
      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
      });
      expect(validator.isTrustedIssuer(TEST_ISSUER)).toBe(true);

      validator.removeTrustedIssuer(TEST_ISSUER);
      expect(validator.isTrustedIssuer(TEST_ISSUER)).toBe(false);
    });
  });

  describe("validate", () => {
    it("rejects malformed tokens without signature", async () => {
      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
      });

      const result = await validator.validate("not-a-valid-token");
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid_format");
      }
    });

    it("rejects tokens from untrusted issuers", async () => {
      const mockFetch = vi.fn();
      const validator = new JwksTokenValidator({
        trustedIssuers: ["https://trusted.example.com"],
        fetch: mockFetch,
      });

      const token = await createToken(keyPair.privateKey, {
        v: 1,
        tid: "test-123",
        iss: "https://untrusted.example.com",
        kid: TEST_KEY_ID,
        alg: "EdDSA",
        tier: "premium",
        contentId: "article-1",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("untrusted_issuer");
      }
      expect(mockFetch).not.toHaveBeenCalled(); // Should reject before fetching
    });

    it("rejects unsupported algorithms", async () => {
      const mockFetch = vi.fn();
      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
        fetch: mockFetch,
      });

      const token = await createToken(keyPair.privateKey, {
        v: 1,
        tid: "test-123",
        iss: TEST_ISSUER,
        kid: TEST_KEY_ID,
        alg: "RS256", // Not supported
        tier: "premium",
        contentId: "article-1",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("unsupported_algorithm");
      }
    });

    it("validates a correctly signed token", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => createMockJwks([publicKeyJwk]),
      });

      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
        fetch: mockFetch,
      });

      const now = Math.floor(Date.now() / 1000);
      const token = await createToken(keyPair.privateKey, {
        v: 1,
        tid: "test-123",
        iss: TEST_ISSUER,
        kid: TEST_KEY_ID,
        alg: "EdDSA",
        tier: "premium",
        contentId: "article-1",
        exp: now + 3600,
        iat: now,
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.issuer).toBe(TEST_ISSUER);
        expect(result.keyId).toBe(TEST_KEY_ID);
        expect(result.expired).toBe(false);
        expect(result.payload.tier).toBe("premium");
        expect(result.payload.contentId).toBe("article-1");
      }
    });

    it("detects expired tokens", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => createMockJwks([publicKeyJwk]),
      });

      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
        fetch: mockFetch,
      });

      const now = Math.floor(Date.now() / 1000);
      const token = await createToken(keyPair.privateKey, {
        v: 1,
        tid: "test-123",
        iss: TEST_ISSUER,
        kid: TEST_KEY_ID,
        alg: "EdDSA",
        tier: "premium",
        contentId: "article-1",
        exp: now - 100, // Expired 100 seconds ago
        iat: now - 3700,
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.expired).toBe(true);
        expect(result.expiresIn).toBeLessThan(0);
      }
    });

    it("rejects invalid signatures", async () => {
      // Generate a different key pair
      const otherKeyPair = await crypto.subtle.generateKey("Ed25519", true, [
        "sign",
        "verify",
      ]);

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => createMockJwks([publicKeyJwk]), // Original public key
      });

      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
        fetch: mockFetch,
      });

      // Sign with a different private key
      const token = await createToken(otherKeyPair.privateKey, {
        v: 1,
        tid: "test-123",
        iss: TEST_ISSUER,
        kid: TEST_KEY_ID,
        alg: "EdDSA",
        tier: "premium",
        contentId: "article-1",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid_signature");
      }
    });

    it("rejects tokens with unknown key ID", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => createMockJwks([publicKeyJwk]),
      });

      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
        fetch: mockFetch,
      });

      const token = await createToken(keyPair.privateKey, {
        v: 1,
        tid: "test-123",
        iss: TEST_ISSUER,
        kid: "unknown-key-id", // Not in JWKS
        alg: "EdDSA",
        tier: "premium",
        contentId: "article-1",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("unknown_key");
      }
    });

    it("handles JWKS fetch failures", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });

      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
        fetch: mockFetch,
      });

      const token = await createToken(keyPair.privateKey, {
        v: 1,
        tid: "test-123",
        iss: TEST_ISSUER,
        kid: TEST_KEY_ID,
        alg: "EdDSA",
        tier: "premium",
        contentId: "article-1",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("jwks_fetch_failed");
      }
    });

    it("validates content ID when provided", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => createMockJwks([publicKeyJwk]),
      });

      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
        fetch: mockFetch,
      });

      const token = await createToken(keyPair.privateKey, {
        v: 1,
        tid: "test-123",
        iss: TEST_ISSUER,
        kid: TEST_KEY_ID,
        alg: "EdDSA",
        tier: "premium",
        contentId: "article-1",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      });

      const wrongContentResult = await validator.validate(token, {
        contentId: "different-article",
      });
      expect(wrongContentResult.valid).toBe(false);

      const correctContentResult = await validator.validate(token, {
        contentId: "article-1",
      });
      expect(correctContentResult.valid).toBe(true);
    });
  });

  describe("JWKS caching", () => {
    it("caches JWKS responses", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => createMockJwks([publicKeyJwk]),
      });

      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
        fetch: mockFetch,
      });

      const token = await createToken(keyPair.privateKey, {
        v: 1,
        tid: "test-123",
        iss: TEST_ISSUER,
        kid: TEST_KEY_ID,
        alg: "EdDSA",
        tier: "premium",
        contentId: "article-1",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      });

      // First validation
      await validator.validate(token);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second validation - should use cache
      await validator.validate(token);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("clears cache for specific issuer", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => createMockJwks([publicKeyJwk]),
      });

      const validator = new JwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
        fetch: mockFetch,
      });

      const token = await createToken(keyPair.privateKey, {
        v: 1,
        tid: "test-123",
        iss: TEST_ISSUER,
        kid: TEST_KEY_ID,
        alg: "EdDSA",
        tier: "premium",
        contentId: "article-1",
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      });

      await validator.validate(token);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      validator.clearCache(TEST_ISSUER);

      await validator.validate(token);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe("createJwksTokenValidator", () => {
    it("creates a validator instance", () => {
      const validator = createJwksTokenValidator({
        trustedIssuers: [TEST_ISSUER],
      });
      expect(validator).toBeInstanceOf(JwksTokenValidator);
    });
  });
});
