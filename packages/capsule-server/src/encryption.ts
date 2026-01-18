/**
 * AES-256-GCM encryption utilities.
 * 
 * Provides content encryption with unique DEKs and key wrapping.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

/** GCM IV size in bytes (96 bits as recommended by NIST) */
export const GCM_IV_SIZE = 12;

/** GCM authentication tag length in bytes */
export const GCM_TAG_LENGTH = 16;

/** AES-256 key size in bytes */
export const AES_KEY_SIZE = 32;

/**
 * Generate a random 256-bit AES key (DEK).
 */
export function generateDek(): Buffer {
  return randomBytes(AES_KEY_SIZE);
}

/**
 * Generate a random IV for AES-GCM.
 */
export function generateIv(): Buffer {
  return randomBytes(GCM_IV_SIZE);
}

/**
 * Encrypt content with AES-256-GCM.
 * 
 * @param content - Plaintext content to encrypt
 * @param dek - 256-bit AES key
 * @param iv - 96-bit initialization vector (generated if not provided)
 * @returns Encrypted content (ciphertext + auth tag) and IV
 */
export function encryptContent(
  content: string | Buffer,
  dek: Buffer,
  iv?: Buffer
): { encryptedContent: Buffer; iv: Buffer } {
  const actualIv = iv ?? generateIv();
  const plaintext = typeof content === "string" ? Buffer.from(content, "utf-8") : content;
  
  const cipher = createCipheriv("aes-256-gcm", dek, actualIv, {
    authTagLength: GCM_TAG_LENGTH,
  });
  
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  // Combine ciphertext and auth tag (same format as Web Crypto API)
  const combined = Buffer.concat([encrypted, authTag]);
  
  return {
    encryptedContent: combined,
    iv: actualIv,
  };
}

/**
 * Decrypt content with AES-256-GCM.
 * 
 * @param encryptedContent - Ciphertext + auth tag
 * @param dek - 256-bit AES key
 * @param iv - Initialization vector used for encryption
 * @returns Decrypted plaintext
 */
export function decryptContent(
  encryptedContent: Buffer,
  dek: Buffer,
  iv: Buffer
): Buffer {
  // Split ciphertext and auth tag
  const ciphertext = encryptedContent.subarray(0, -GCM_TAG_LENGTH);
  const authTag = encryptedContent.subarray(-GCM_TAG_LENGTH);
  
  const decipher = createDecipheriv("aes-256-gcm", dek, iv, {
    authTagLength: GCM_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);
  
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Wrap (encrypt) a DEK with a key-wrapping key using AES-256-GCM.
 * 
 * This is used to create multiple wrapped versions of the same DEK,
 * each encrypted with a different key-wrapping key.
 * 
 * @param dek - The data encryption key to wrap
 * @param wrappingKey - The key-wrapping key (256-bit AES)
 * @returns Wrapped DEK (IV + ciphertext + auth tag)
 */
export function wrapDek(dek: Buffer, wrappingKey: Buffer): Buffer {
  const iv = generateIv();
  const { encryptedContent } = encryptContent(dek, wrappingKey, iv);
  
  // Prepend IV so it can be extracted during unwrap
  return Buffer.concat([iv, encryptedContent]);
}

/**
 * Unwrap (decrypt) a DEK with a key-wrapping key.
 * 
 * @param wrappedDek - The wrapped DEK (IV + ciphertext + auth tag)
 * @param wrappingKey - The key-wrapping key used to wrap
 * @returns The unwrapped DEK
 */
export function unwrapDek(wrappedDek: Buffer, wrappingKey: Buffer): Buffer {
  const iv = wrappedDek.subarray(0, GCM_IV_SIZE);
  const encryptedContent = wrappedDek.subarray(GCM_IV_SIZE);
  
  return decryptContent(encryptedContent, wrappingKey, iv);
}
