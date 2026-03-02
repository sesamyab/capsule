/**
 * AES-256-GCM encryption utilities.
 *
 * Provides content encryption with unique content keys and key wrapping.
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
export function generateContentKey(): Uint8Array {
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
 * @param contentKey - 256-bit AES key
 * @param iv - 96-bit initialization vector (generated if not provided)
 * @param aad - Optional additional authenticated data (binds ciphertext to context)
 * @returns Encrypted content (ciphertext + auth tag) and IV
 */
export async function encryptContent(
  content: string | Uint8Array,
  contentKey: Uint8Array,
  iv?: Uint8Array,
  aad?: Uint8Array,
): Promise<{ encryptedContent: Uint8Array; iv: Uint8Array }> {
  const plaintext =
    typeof content === "string" ? new TextEncoder().encode(content) : content;

  return aesGcmEncrypt(plaintext, contentKey, iv, aad);
}

/**
 * Decrypt content with AES-256-GCM.
 *
 * @param encryptedContent - Ciphertext + auth tag
 * @param contentKey - 256-bit AES key
 * @param iv - Initialization vector used for encryption
 * @param aad - Optional additional authenticated data (must match encryption)
 * @returns Decrypted plaintext
 */
export async function decryptContent(
  encryptedContent: Uint8Array,
  contentKey: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  return aesGcmDecrypt(encryptedContent, contentKey, iv, aad);
}

/**
 * Wrap (encrypt) a content key with a key-wrapping key using AES-256-GCM.
 *
 * This is used to create multiple wrapped versions of the same content key,
 * each encrypted with a different key-wrapping key.
 *
 * @param contentKey - The content key to wrap
 * @param wrappingKey - The key-wrapping key (256-bit AES)
 * @returns Wrapped DEK (IV + ciphertext + auth tag)
 */
export async function wrapContentKey(
  contentKey: Uint8Array,
  wrappingKey: Uint8Array,
): Promise<Uint8Array> {
  const iv = generateIv();
  const { encryptedContent } = await encryptContent(contentKey, wrappingKey, iv);

  // Prepend IV so it can be extracted during unwrap
  const result = new Uint8Array(iv.length + encryptedContent.length);
  result.set(iv, 0);
  result.set(encryptedContent, iv.length);
  return result;
}

/**
 * Unwrap (decrypt) a content key with a key-wrapping key.
 *
 * @param wrappedContentKey - The wrapped content key (IV + ciphertext + auth tag)
 * @param wrappingKey - The key-wrapping key used to wrap
 * @returns The unwrapped content key
 */
export async function unwrapContentKey(
  wrappedContentKey: Uint8Array,
  wrappingKey: Uint8Array,
): Promise<Uint8Array> {
  const iv = wrappedContentKey.subarray(0, GCM_IV_SIZE);
  const encryptedContent = wrappedContentKey.subarray(GCM_IV_SIZE);

  return decryptContent(encryptedContent, wrappingKey, iv);
}
