import { describe, it, expect } from "vitest";
import {
  encryptContent,
  decryptContent,
  wrapDek,
  unwrapDek,
  generateDek,
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
  describe("generateDek", () => {
    it("generates a 256-bit key", () => {
      const dek = generateDek();
      expect(dek).toBeInstanceOf(Uint8Array);
      expect(dek.length).toBe(AES_KEY_SIZE);
    });

    it("generates unique keys", () => {
      const dek1 = generateDek();
      const dek2 = generateDek();
      expect(arraysEqual(dek1, dek2)).toBe(false);
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
      const dek = generateDek();
      const plaintext = "Hello, World! This is a test message.";

      const { encryptedContent, iv } = await encryptContent(plaintext, dek);

      expect(encryptedContent).toBeInstanceOf(Uint8Array);
      expect(iv.length).toBe(GCM_IV_SIZE);
      // Encrypted content should be plaintext length + auth tag
      expect(encryptedContent.length).toBe(
        new TextEncoder().encode(plaintext).length + GCM_TAG_LENGTH,
      );

      const decrypted = await decryptContent(encryptedContent, dek, iv);
      expect(decodeUtf8(decrypted)).toBe(plaintext);
    });

    it("encrypts and decrypts Uint8Array content", async () => {
      const dek = generateDek();
      const plaintext = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);

      const { encryptedContent, iv } = await encryptContent(plaintext, dek);
      const decrypted = await decryptContent(encryptedContent, dek, iv);

      expect(arraysEqual(decrypted, plaintext)).toBe(true);
    });

    it("uses provided IV when given", async () => {
      const dek = generateDek();
      const customIv = generateIv();
      const plaintext = "Test message";

      const { iv } = await encryptContent(plaintext, dek, customIv);

      expect(arraysEqual(iv, customIv)).toBe(true);
    });

    it("produces different ciphertext with different IVs", async () => {
      const dek = generateDek();
      const plaintext = "Same message";

      const result1 = await encryptContent(plaintext, dek);
      const result2 = await encryptContent(plaintext, dek);

      expect(arraysEqual(result1.encryptedContent, result2.encryptedContent)).toBe(
        false,
      );
    });

    it("fails to decrypt with wrong key", async () => {
      const dek1 = generateDek();
      const dek2 = generateDek();
      const plaintext = "Secret message";

      const { encryptedContent, iv } = await encryptContent(plaintext, dek1);

      await expect(decryptContent(encryptedContent, dek2, iv)).rejects.toThrow();
    });

    it("fails to decrypt with wrong IV", async () => {
      const dek = generateDek();
      const plaintext = "Secret message";

      const { encryptedContent } = await encryptContent(plaintext, dek);
      const wrongIv = generateIv();

      await expect(decryptContent(encryptedContent, dek, wrongIv)).rejects.toThrow();
    });

    it("fails to decrypt tampered ciphertext", async () => {
      const dek = generateDek();
      const plaintext = "Secret message";

      const { encryptedContent, iv } = await encryptContent(plaintext, dek);

      // Tamper with the ciphertext
      encryptedContent[0] ^= 0xff;

      await expect(decryptContent(encryptedContent, dek, iv)).rejects.toThrow();
    });

    it("handles empty content", async () => {
      const dek = generateDek();
      const plaintext = "";

      const { encryptedContent, iv } = await encryptContent(plaintext, dek);
      const decrypted = await decryptContent(encryptedContent, dek, iv);

      expect(decodeUtf8(decrypted)).toBe(plaintext);
    });

    it("handles large content", async () => {
      const dek = generateDek();
      const plaintext = "x".repeat(100000); // 100KB

      const { encryptedContent, iv } = await encryptContent(plaintext, dek);
      const decrypted = await decryptContent(encryptedContent, dek, iv);

      expect(decodeUtf8(decrypted)).toBe(plaintext);
    });

    it("handles unicode content", async () => {
      const dek = generateDek();
      const plaintext = "你好世界 🌍 مرحبا العالم";

      const { encryptedContent, iv } = await encryptContent(plaintext, dek);
      const decrypted = await decryptContent(encryptedContent, dek, iv);

      expect(decodeUtf8(decrypted)).toBe(plaintext);
    });
  });

  describe("wrapDek / unwrapDek", () => {
    it("wraps and unwraps a DEK", async () => {
      const dek = generateDek();
      const wrappingKey = generateDek();

      const wrapped = await wrapDek(dek, wrappingKey);

      // Wrapped DEK should be IV + encrypted DEK + auth tag
      expect(wrapped.length).toBe(GCM_IV_SIZE + AES_KEY_SIZE + GCM_TAG_LENGTH);

      const unwrapped = await unwrapDek(wrapped, wrappingKey);
      expect(arraysEqual(unwrapped, dek)).toBe(true);
    });

    it("produces different wrapped output each time due to random IV", async () => {
      const dek = generateDek();
      const wrappingKey = generateDek();

      const wrapped1 = await wrapDek(dek, wrappingKey);
      const wrapped2 = await wrapDek(dek, wrappingKey);

      expect(arraysEqual(wrapped1, wrapped2)).toBe(false);

      // But both unwrap to the same DEK
      const unwrapped1 = await unwrapDek(wrapped1, wrappingKey);
      const unwrapped2 = await unwrapDek(wrapped2, wrappingKey);
      expect(arraysEqual(unwrapped1, dek)).toBe(true);
      expect(arraysEqual(unwrapped2, dek)).toBe(true);
    });

    it("fails to unwrap with wrong key", async () => {
      const dek = generateDek();
      const wrappingKey1 = generateDek();
      const wrappingKey2 = generateDek();

      const wrapped = await wrapDek(dek, wrappingKey1);

      await expect(unwrapDek(wrapped, wrappingKey2)).rejects.toThrow();
    });

    it("fails to unwrap tampered wrapped DEK", async () => {
      const dek = generateDek();
      const wrappingKey = generateDek();

      const wrapped = await wrapDek(dek, wrappingKey);
      // Tamper with the wrapped content
      wrapped[GCM_IV_SIZE + 5] ^= 0xff;

      await expect(unwrapDek(wrapped, wrappingKey)).rejects.toThrow();
    });
  });
});
