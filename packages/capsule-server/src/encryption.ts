/**
 * AES-256-GCM encryption utilities.
 *
 * Provides content encryption with unique DEKs and key wrapping.
 * Uses Web Crypto API for cross-platform compatibility (Node.js, Cloudflare Workers, browsers).
 */

import {
  generateAesKeyBytes,
  generateIv as generateIvBytes,
  aesGcmEncrypt,
  aesGcmDecrypt,
  GCM_IV_SIZE as WC_GCM_IV_SIZE,
  GCM_TAG_LENGTH as WC_GCM_TAG_LENGTH,
  AES_KEY_SIZE as WC_AES_KEY_SIZE,
} from "./web-crypto";

/** GCM IV size in bytes (96 bits as recommended by NIST) */
export const GCM_IV_SIZE = WC_GCM_IV_SIZE;

/** GCM authentication tag length in bytes */
export const GCM_TAG_LENGTH = WC_GCM_TAG_LENGTH;

/** AES-256 key size in bytes */
export const AES_KEY_SIZE = WC_AES_KEY_SIZE;

/**
 * Generate a random 256-bit AES key (DEK).
 */
export function generateDek(): Uint8Array {
  return generateAesKeyBytes();
}

/**
 * Generate a random IV for AES-GCM.
 */
export function generateIv(): Uint8Array {
  return generateIvBytes();
}

/**
 * Encrypt content with AES-256-GCM.
 *
 * @param content - Plaintext content to encrypt
 * @param dek - 256-bit AES key
 * @param iv - 96-bit initialization vector (generated if not provided)
 * @returns Encrypted content (ciphertext + auth tag) and IV
 */
export async function encryptContent(
  content: string | Uint8Array,
  dek: Uint8Array,
  iv?: Uint8Array,
): Promise<{ encryptedContent: Uint8Array; iv: Uint8Array }> {
  const plaintext =
    typeof content === "string" ? new TextEncoder().encode(content) : content;

  return aesGcmEncrypt(plaintext, dek, iv);
}

/**
 * Decrypt content with AES-256-GCM.
 *
 * @param encryptedContent - Ciphertext + auth tag
 * @param dek - 256-bit AES key
 * @param iv - Initialization vector used for encryption
 * @returns Decrypted plaintext
 */
export async function decryptContent(
  encryptedContent: Uint8Array,
  dek: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  return aesGcmDecrypt(encryptedContent, dek, iv);
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
export async function wrapDek(
  dek: Uint8Array,
  wrappingKey: Uint8Array,
): Promise<Uint8Array> {
  const iv = generateIv();
  const { encryptedContent } = await encryptContent(dek, wrappingKey, iv);

  // Prepend IV so it can be extracted during unwrap
  const result = new Uint8Array(iv.length + encryptedContent.length);
  result.set(iv, 0);
  result.set(encryptedContent, iv.length);
  return result;
}

/**
 * Unwrap (decrypt) a DEK with a key-wrapping key.
 *
 * @param wrappedDek - The wrapped DEK (IV + ciphertext + auth tag)
 * @param wrappingKey - The key-wrapping key used to wrap
 * @returns The unwrapped DEK
 */
export async function unwrapDek(
  wrappedDek: Uint8Array,
  wrappingKey: Uint8Array,
): Promise<Uint8Array> {
  const iv = wrappedDek.subarray(0, GCM_IV_SIZE);
  const encryptedContent = wrappedDek.subarray(GCM_IV_SIZE);

  return decryptContent(encryptedContent, wrappingKey, iv);
}
