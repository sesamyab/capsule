import { describe, it, expect } from "vitest";
import {
  encryptContent,
  decryptContent,
  wrapContentKey,
  unwrapContentKey,
  generateContentKey,
  generateIv,
  GCM_IV_SIZE,
  GCM_TAG_LENGTH,
  AES_KEY_SIZE,
} from "../encryption";

// Helper to compare Uint8Arrays
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Helper to decode UTF-8
function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

describe("encryption", () => {
  describe("generateContentKey", () => {
    it("generates a 256-bit key", () => {
      const contentKey = generateContentKey();
      expect(contentKey).toBeInstanceOf(Uint8Array);
      expect(contentKey.length).toBe(AES_KEY_SIZE);
    });

    it("generates unique keys", () => {
      const contentKey1 = generateContentKey();
      const contentKey2 = generateContentKey();
      expect(arraysEqual(contentKey1, contentKey2)).toBe(false);
    });
  });

  describe("generateIv", () => {
    it("generates a 96-bit IV", () => {
      const iv = generateIv();
      expect(iv).toBeInstanceOf(Uint8Array);
      expect(iv.length).toBe(GCM_IV_SIZE);
    });

    it("generates unique IVs", () => {
      const iv1 = generateIv();
      const iv2 = generateIv();
      expect(arraysEqual(iv1, iv2)).toBe(false);
    });
  });

  describe("encryptContent / decryptContent", () => {
    it("encrypts and decrypts string content", async () => {
      const contentKey = generateContentKey();
      const plaintext = "Hello, World! This is a test message.";

      const { encryptedContent, iv } = await encryptContent(plaintext, contentKey);

      expect(encryptedContent).toBeInstanceOf(Uint8Array);
      expect(iv.length).toBe(GCM_IV_SIZE);
      // Encrypted content should be plaintext length + auth tag
      expect(encryptedContent.length).toBe(
        new TextEncoder().encode(plaintext).length + GCM_TAG_LENGTH,
      );

      const decrypted = await decryptContent(encryptedContent, contentKey, iv);
      expect(decodeUtf8(decrypted)).toBe(plaintext);
    });

    it("encrypts and decrypts Uint8Array content", async () => {
      const contentKey = generateContentKey();
      const plaintext = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);

      const { encryptedContent, iv } = await encryptContent(plaintext, contentKey);
      const decrypted = await decryptContent(encryptedContent, contentKey, iv);

      expect(arraysEqual(decrypted, plaintext)).toBe(true);
    });

    it("uses provided IV when given", async () => {
      const contentKey = generateContentKey();
      const customIv = generateIv();
      const plaintext = "Test message";

      const { iv } = await encryptContent(plaintext, contentKey, customIv);

      expect(arraysEqual(iv, customIv)).toBe(true);
    });

    it("produces different ciphertext with different IVs", async () => {
      const contentKey = generateContentKey();
      const plaintext = "Same message";

      const result1 = await encryptContent(plaintext, contentKey);
      const result2 = await encryptContent(plaintext, contentKey);

      expect(arraysEqual(result1.encryptedContent, result2.encryptedContent)).toBe(
        false,
      );
    });

    it("fails to decrypt with wrong key", async () => {
      const dek1 = generateContentKey();
      const dek2 = generateContentKey();
      const plaintext = "Secret message";

      const { encryptedContent, iv } = await encryptContent(plaintext, dek1);

      await expect(decryptContent(encryptedContent, dek2, iv)).rejects.toThrow();
    });

    it("fails to decrypt with wrong IV", async () => {
      const contentKey = generateContentKey();
      const plaintext = "Secret message";

      const { encryptedContent } = await encryptContent(plaintext, contentKey);
      const wrongIv = generateIv();

      await expect(decryptContent(encryptedContent, contentKey, wrongIv)).rejects.toThrow();
    });

    it("fails to decrypt tampered ciphertext", async () => {
      const contentKey = generateContentKey();
      const plaintext = "Secret message";

      const { encryptedContent, iv } = await encryptContent(plaintext, contentKey);

      // Tamper with the ciphertext
      encryptedContent[0] ^= 0xff;

      await expect(decryptContent(encryptedContent, contentKey, iv)).rejects.toThrow();
    });

    it("handles empty content", async () => {
      const contentKey = generateContentKey();
      const plaintext = "";

      const { encryptedContent, iv } = await encryptContent(plaintext, contentKey);
      const decrypted = await decryptContent(encryptedContent, contentKey, iv);

      expect(decodeUtf8(decrypted)).toBe(plaintext);
    });

    it("handles large content", async () => {
      const contentKey = generateContentKey();
      const plaintext = "x".repeat(100000); // 100KB

      const { encryptedContent, iv } = await encryptContent(plaintext, contentKey);
      const decrypted = await decryptContent(encryptedContent, contentKey, iv);

      expect(decodeUtf8(decrypted)).toBe(plaintext);
    });

    it("handles unicode content", async () => {
      const contentKey = generateContentKey();
      const plaintext = "你好世界 🌍 مرحبا العالم";

      const { encryptedContent, iv } = await encryptContent(plaintext, contentKey);
      const decrypted = await decryptContent(encryptedContent, contentKey, iv);

      expect(decodeUtf8(decrypted)).toBe(plaintext);
    });
  });

  describe("wrapContentKey / unwrapContentKey", () => {
    it("wraps and unwraps a content key", async () => {
      const contentKey = generateContentKey();
      const wrappingKey = generateContentKey();

      const wrapped = await wrapContentKey(contentKey, wrappingKey);

      // Wrapped DEK should be IV + encrypted DEK + auth tag
      expect(wrapped.length).toBe(GCM_IV_SIZE + AES_KEY_SIZE + GCM_TAG_LENGTH);

      const unwrapped = await unwrapContentKey(wrapped, wrappingKey);
      expect(arraysEqual(unwrapped, contentKey)).toBe(true);
    });

    it("produces different wrapped output each time due to random IV", async () => {
      const contentKey = generateContentKey();
      const wrappingKey = generateContentKey();

      const wrapped1 = await wrapContentKey(contentKey, wrappingKey);
      const wrapped2 = await wrapContentKey(contentKey, wrappingKey);

      expect(arraysEqual(wrapped1, wrapped2)).toBe(false);

      // But both unwrap to the same content key
      const unwrapped1 = await unwrapContentKey(wrapped1, wrappingKey);
      const unwrapped2 = await unwrapContentKey(wrapped2, wrappingKey);
      expect(arraysEqual(unwrapped1, contentKey)).toBe(true);
      expect(arraysEqual(unwrapped2, contentKey)).toBe(true);
    });

    it("fails to unwrap with wrong key", async () => {
      const contentKey = generateContentKey();
      const wrappingKey1 = generateContentKey();
      const wrappingKey2 = generateContentKey();

      const wrapped = await wrapContentKey(contentKey, wrappingKey1);

      await expect(unwrapContentKey(wrapped, wrappingKey2)).rejects.toThrow();
    });

    it("fails to unwrap tampered wrapped content key", async () => {
      const contentKey = generateContentKey();
      const wrappingKey = generateContentKey();

      const wrapped = await wrapContentKey(contentKey, wrappingKey);
      // Tamper with the wrapped content
      wrapped[GCM_IV_SIZE + 5] ^= 0xff;

      await expect(unwrapContentKey(wrapped, wrappingKey)).rejects.toThrow();
    });
  });
});
