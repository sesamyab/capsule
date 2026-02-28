import { describe, it, expect } from "vitest";
import {
  AsymmetricTokenManager,
  generateSigningKeyPair,
} from "../asymmetric-tokens";
import { toBase64Url, fromBase64Url } from "../web-crypto";

// Helper to decode UTF-8 from Uint8Array
function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// Helper to encode string to Uint8Array
function encodeUtf8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

describe("AsymmetricTokenManager", () => {
  describe("generateSigningKeyPair", () => {
    it("generates valid Ed25519 key pair", async () => {
      const keyPair = await generateSigningKeyPair();

      expect(keyPair.privateKey).toContain("-----BEGIN PRIVATE KEY-----");
      expect(keyPair.publicKey).toContain("-----BEGIN PUBLIC KEY-----");
      expect(keyPair.keyId).toMatch(/^key-\d+-[a-f0-9]+$/);
    });

    it("uses custom keyId when provided", async () => {
      const keyPair = await generateSigningKeyPair("my-custom-key");
      expect(keyPair.keyId).toBe("my-custom-key");
    });
  });

  describe("token generation and validation", () => {
    it("generates and validates a token", async () => {
      const keyPair = await generateSigningKeyPair("test-key");
      const manager = new AsymmetricTokenManager({
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        keyId: keyPair.keyId,
        issuer: "https://test.example.com",
      });

      const token = await manager.generate({
        contentId: "premium",

        expiresIn: "1h",
      });

      const result = await manager.validate(token);

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.payload.contentId).toBe("premium");
        expect(result.payload.iss).toBe("https://test.example.com");
        expect(result.payload.kid).toBe("test-key");
        expect(result.payload.alg).toBe("EdDSA");
      }
    });

    it("includes optional fields in token", async () => {
      const keyPair = await generateSigningKeyPair();
      const manager = new AsymmetricTokenManager({
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        keyId: keyPair.keyId,
        issuer: "https://test.example.com",
      });

      const token = await manager.generate({
        contentId: "premium",

        url: "https://example.com/article/123",
        userId: "user-456",
        maxUses: 5,
        expiresIn: "7d",
        meta: { campaign: "summer2026" },
      });

      const result = await manager.validate(token);

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.payload.url).toBe("https://example.com/article/123");
        expect(result.payload.userId).toBe("user-456");
        expect(result.payload.maxUses).toBe(5);
        expect(result.payload.meta).toEqual({ campaign: "summer2026" });
      }
    });

    it("rejects tampered tokens", async () => {
      const keyPair = await generateSigningKeyPair();
      const manager = new AsymmetricTokenManager({
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        keyId: keyPair.keyId,
        issuer: "https://test.example.com",
      });

      const token = await manager.generate({
        contentId: "premium",

        expiresIn: "1h",
      });

      // Tamper with the payload
      const [payloadB64, sig] = token.split(".");
      const payload = JSON.parse(decodeUtf8(fromBase64Url(payloadB64)));
      payload.contentId = "enterprise"; // Attempt to upgrade content access
      const tamperedPayload = toBase64Url(
        encodeUtf8(JSON.stringify(payload)),
      );
      const tamperedToken = `${tamperedPayload}.${sig}`;

      const result = await manager.validate(tamperedToken);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("invalid");
      }
    });

    it("rejects expired tokens", async () => {
      const keyPair = await generateSigningKeyPair();
      const manager = new AsymmetricTokenManager({
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        keyId: keyPair.keyId,
        issuer: "https://test.example.com",
      });

      // Generate token that expires in 1 second
      const token = await manager.generate({
        contentId: "premium",

        expiresIn: -1, // Already expired
      });

      const result = await manager.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("expired");
      }
    });

    it("rejects malformed tokens", async () => {
      const keyPair = await generateSigningKeyPair();
      const manager = new AsymmetricTokenManager({
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        keyId: keyPair.keyId,
        issuer: "https://test.example.com",
      });

      const result1 = await manager.validate("not-a-token");
      expect(result1.valid).toBe(false);
      if (!result1.valid) {
        expect(result1.error).toBe("malformed");
      }

      const result2 = await manager.validate("invalid.base64!!!");
      expect(result2.valid).toBe(false);
    });
  });

  describe("key rotation", () => {
    it("validates tokens signed with rotated keys", async () => {
      // Generate two key pairs - simulating key rotation
      const oldKey = await generateSigningKeyPair("key-2025");
      const newKey = await generateSigningKeyPair("key-2026");

      // Old manager signs a token
      const oldManager = new AsymmetricTokenManager({
        privateKey: oldKey.privateKey,
        publicKey: oldKey.publicKey,
        keyId: oldKey.keyId,
        issuer: "https://test.example.com",
      });
      const oldToken = await oldManager.generate({
        contentId: "premium",

        expiresIn: "30d",
      });

      // New manager with old key in additionalPublicKeys
      const newManager = new AsymmetricTokenManager({
        privateKey: newKey.privateKey,
        publicKey: newKey.publicKey,
        keyId: newKey.keyId,
        issuer: "https://test.example.com",
        additionalPublicKeys: [
          { publicKey: oldKey.publicKey, keyId: oldKey.keyId },
        ],
      });

      // New manager should validate old tokens
      const result = await newManager.validate(oldToken);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.payload.kid).toBe("key-2025");
      }

      // New manager should also validate new tokens
      const newToken = await newManager.generate({
        contentId: "basic",

        expiresIn: "7d",
      });

      const newResult = await newManager.validate(newToken);
      expect(newResult.valid).toBe(true);
      if (newResult.valid) {
        expect(newResult.payload.kid).toBe("key-2026");
      }
    });

    it("rejects tokens signed with unknown keys", async () => {
      const keyPair1 = await generateSigningKeyPair("key-1");
      const keyPair2 = await generateSigningKeyPair("key-2");
      const unknownKey = await generateSigningKeyPair("unknown-key");

      // Manager only knows about key-1 and key-2
      const manager = new AsymmetricTokenManager({
        privateKey: keyPair1.privateKey,
        publicKey: keyPair1.publicKey,
        keyId: keyPair1.keyId,
        issuer: "https://test.example.com",
        additionalPublicKeys: [
          { publicKey: keyPair2.publicKey, keyId: keyPair2.keyId },
        ],
      });

      // Token signed with unknown key
      const unknownManager = new AsymmetricTokenManager({
        privateKey: unknownKey.privateKey,
        publicKey: unknownKey.publicKey,
        keyId: unknownKey.keyId,
        issuer: "https://test.example.com",
      });
      const unknownToken = await unknownManager.generate({
        contentId: "premium",

        expiresIn: "1h",
      });

      const result = await manager.validate(unknownToken);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error).toBe("unknown_key");
        expect(result.message).toContain("unknown-key");
      }
    });

    it("includes all keys in JWKS", async () => {
      const key1 = await generateSigningKeyPair("key-2025");
      const key2 = await generateSigningKeyPair("key-2026");
      const key3 = await generateSigningKeyPair("key-2027");

      const manager = new AsymmetricTokenManager({
        privateKey: key3.privateKey,
        publicKey: key3.publicKey,
        keyId: key3.keyId,
        issuer: "https://test.example.com",
        additionalPublicKeys: [
          { publicKey: key1.publicKey, keyId: key1.keyId },
          { publicKey: key2.publicKey, keyId: key2.keyId },
        ],
      });

      const jwks = await manager.getJwks();
      expect(jwks.keys).toHaveLength(3);

      const kids = jwks.keys.map((k) => k.kid);
      expect(kids).toContain("key-2025");
      expect(kids).toContain("key-2026");
      expect(kids).toContain("key-2027");

      // All keys should have proper JWK format
      for (const key of jwks.keys) {
        expect(key.kty).toBe("OKP");
        expect(key.crv).toBe("Ed25519");
        expect(key.alg).toBe("EdDSA");
        expect(key.use).toBe("sig");
        expect(key.x).toBeDefined();
      }
    });
  });

  describe("peek", () => {
    it("peeks at token payload without validation", async () => {
      const keyPair = await generateSigningKeyPair();
      const manager = new AsymmetricTokenManager({
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        keyId: keyPair.keyId,
        issuer: "https://test.example.com",
      });

      const token = await manager.generate({
        contentId: "premium",

        expiresIn: "1h",
      });

      const payload = manager.peek(token);
      expect(payload).not.toBeNull();
      expect(payload?.contentId).toBe("premium");
    });

    it("returns null for invalid tokens", async () => {
      const keyPair = await generateSigningKeyPair();
      const manager = new AsymmetricTokenManager({
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        keyId: keyPair.keyId,
        issuer: "https://test.example.com",
      });

      expect(manager.peek("not-a-token")).toBeNull();
      expect(manager.peek("invalid.base64!!!")).toBeNull();
    });
  });
});
