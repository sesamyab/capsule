import { describe, it, expect } from 'vitest';
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
} from '../encryption';

describe('encryption', () => {
  describe('generateDek', () => {
    it('generates a 256-bit key', () => {
      const dek = generateDek();
      expect(dek).toBeInstanceOf(Buffer);
      expect(dek.length).toBe(AES_KEY_SIZE);
    });

    it('generates unique keys', () => {
      const dek1 = generateDek();
      const dek2 = generateDek();
      expect(dek1.equals(dek2)).toBe(false);
    });
  });

  describe('generateIv', () => {
    it('generates a 96-bit IV', () => {
      const iv = generateIv();
      expect(iv).toBeInstanceOf(Buffer);
      expect(iv.length).toBe(GCM_IV_SIZE);
    });

    it('generates unique IVs', () => {
      const iv1 = generateIv();
      const iv2 = generateIv();
      expect(iv1.equals(iv2)).toBe(false);
    });
  });

  describe('encryptContent / decryptContent', () => {
    it('encrypts and decrypts string content', () => {
      const dek = generateDek();
      const plaintext = 'Hello, World! This is a test message.';
      
      const { encryptedContent, iv } = encryptContent(plaintext, dek);
      
      expect(encryptedContent).toBeInstanceOf(Buffer);
      expect(iv.length).toBe(GCM_IV_SIZE);
      // Encrypted content should be plaintext length + auth tag
      expect(encryptedContent.length).toBe(Buffer.from(plaintext).length + GCM_TAG_LENGTH);
      
      const decrypted = decryptContent(encryptedContent, dek, iv);
      expect(decrypted.toString('utf-8')).toBe(plaintext);
    });

    it('encrypts and decrypts Buffer content', () => {
      const dek = generateDek();
      const plaintext = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
      
      const { encryptedContent, iv } = encryptContent(plaintext, dek);
      const decrypted = decryptContent(encryptedContent, dek, iv);
      
      expect(decrypted.equals(plaintext)).toBe(true);
    });

    it('uses provided IV when given', () => {
      const dek = generateDek();
      const customIv = generateIv();
      const plaintext = 'Test message';
      
      const { iv } = encryptContent(plaintext, dek, customIv);
      
      expect(iv.equals(customIv)).toBe(true);
    });

    it('produces different ciphertext with different IVs', () => {
      const dek = generateDek();
      const plaintext = 'Same message';
      
      const result1 = encryptContent(plaintext, dek);
      const result2 = encryptContent(plaintext, dek);
      
      expect(result1.encryptedContent.equals(result2.encryptedContent)).toBe(false);
    });

    it('fails to decrypt with wrong key', () => {
      const dek1 = generateDek();
      const dek2 = generateDek();
      const plaintext = 'Secret message';
      
      const { encryptedContent, iv } = encryptContent(plaintext, dek1);
      
      expect(() => decryptContent(encryptedContent, dek2, iv)).toThrow();
    });

    it('fails to decrypt with wrong IV', () => {
      const dek = generateDek();
      const plaintext = 'Secret message';
      
      const { encryptedContent } = encryptContent(plaintext, dek);
      const wrongIv = generateIv();
      
      expect(() => decryptContent(encryptedContent, dek, wrongIv)).toThrow();
    });

    it('fails to decrypt tampered ciphertext', () => {
      const dek = generateDek();
      const plaintext = 'Secret message';
      
      const { encryptedContent, iv } = encryptContent(plaintext, dek);
      
      // Tamper with the ciphertext
      encryptedContent[0] ^= 0xff;
      
      expect(() => decryptContent(encryptedContent, dek, iv)).toThrow();
    });

    it('handles empty content', () => {
      const dek = generateDek();
      const plaintext = '';
      
      const { encryptedContent, iv } = encryptContent(plaintext, dek);
      const decrypted = decryptContent(encryptedContent, dek, iv);
      
      expect(decrypted.toString('utf-8')).toBe(plaintext);
    });

    it('handles large content', () => {
      const dek = generateDek();
      const plaintext = 'x'.repeat(100000); // 100KB
      
      const { encryptedContent, iv } = encryptContent(plaintext, dek);
      const decrypted = decryptContent(encryptedContent, dek, iv);
      
      expect(decrypted.toString('utf-8')).toBe(plaintext);
    });

    it('handles unicode content', () => {
      const dek = generateDek();
      const plaintext = '你好世界 🌍 مرحبا العالم';
      
      const { encryptedContent, iv } = encryptContent(plaintext, dek);
      const decrypted = decryptContent(encryptedContent, dek, iv);
      
      expect(decrypted.toString('utf-8')).toBe(plaintext);
    });
  });

  describe('wrapDek / unwrapDek', () => {
    it('wraps and unwraps a DEK', () => {
      const dek = generateDek();
      const wrappingKey = generateDek();
      
      const wrapped = wrapDek(dek, wrappingKey);
      
      // Wrapped DEK should be IV + encrypted DEK + auth tag
      expect(wrapped.length).toBe(GCM_IV_SIZE + AES_KEY_SIZE + GCM_TAG_LENGTH);
      
      const unwrapped = unwrapDek(wrapped, wrappingKey);
      expect(unwrapped.equals(dek)).toBe(true);
    });

    it('produces different wrapped output each time due to random IV', () => {
      const dek = generateDek();
      const wrappingKey = generateDek();
      
      const wrapped1 = wrapDek(dek, wrappingKey);
      const wrapped2 = wrapDek(dek, wrappingKey);
      
      expect(wrapped1.equals(wrapped2)).toBe(false);
      
      // But both unwrap to the same DEK
      const unwrapped1 = unwrapDek(wrapped1, wrappingKey);
      const unwrapped2 = unwrapDek(wrapped2, wrappingKey);
      expect(unwrapped1.equals(dek)).toBe(true);
      expect(unwrapped2.equals(dek)).toBe(true);
    });

    it('fails to unwrap with wrong key', () => {
      const dek = generateDek();
      const wrappingKey1 = generateDek();
      const wrappingKey2 = generateDek();
      
      const wrapped = wrapDek(dek, wrappingKey1);
      
      expect(() => unwrapDek(wrapped, wrappingKey2)).toThrow();
    });

    it('fails to unwrap tampered wrapped DEK', () => {
      const dek = generateDek();
      const wrappingKey = generateDek();
      
      const wrapped = wrapDek(dek, wrappingKey);
      // Tamper with the wrapped content
      wrapped[GCM_IV_SIZE + 5] ^= 0xff;
      
      expect(() => unwrapDek(wrapped, wrappingKey)).toThrow();
    });
  });
});
