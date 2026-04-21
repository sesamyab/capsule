/**
 * Web Crypto API utilities for cross-platform compatibility.
 *
 * Works with:
 * - Node.js 18+
 * - Cloudflare Workers
 * - Deno
 * - Modern browsers
 */

// Type aliases for Web Crypto API (for cross-platform DTS compatibility)
type WebCrypto = typeof globalThis.crypto;
type WebSubtleCrypto = WebCrypto["subtle"];
export type WebCryptoKey = Awaited<ReturnType<WebSubtleCrypto["importKey"]>>;
type WebKeyUsage =
    | "decrypt"
    | "deriveBits"
    | "deriveKey"
    | "encrypt"
    | "sign"
    | "unwrapKey"
    | "verify"
    | "wrapKey";
// Simplified JWK type for Ed25519 public keys
type WebJsonWebKey = {
    kty?: string;
    crv?: string;
    x?: string;
    y?: string;
    d?: string;
    [key: string]: unknown;
};

/** Get the global crypto object (works in Node.js, CF Workers, browsers) */
function getCrypto(): WebCrypto {
    if (typeof globalThis.crypto !== "undefined") {
        return globalThis.crypto;
    }
    // Fallback for Node.js 18+ (requires explicit import)
    try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        return require("node:crypto").webcrypto;
    } catch {
        throw new Error(
            "Web Crypto API not available. Ensure you're running Node.js 18+ or a modern runtime.",
        );
    }
}

/**
 * Generate cryptographically secure random bytes.
 */
export function getRandomBytes(length: number): Uint8Array {
    const crypto = getCrypto();
    return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Convert Uint8Array to hex string.
 */
export function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Convert hex string to Uint8Array.
 * @throws Error if hex string has odd length or contains non-hex characters
 */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string: length must be even");
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Invalid hex string: contains non-hex characters");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to base64.
 */
export function toBase64(bytes: Uint8Array): string {
  // Works in both Node.js and browsers
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  // Chunk to avoid exceeding max call stack size with spread operator
  const CHUNK_SIZE = 0x8000; // 32KB chunks
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK_SIZE));
  }
  return btoa(binary);
}

/**
 * Convert base64 to Uint8Array.
 */
export function fromBase64(base64: string): Uint8Array {
    if (typeof Buffer !== "undefined") {
        return new Uint8Array(Buffer.from(base64, "base64"));
    }
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

/**
 * Convert Uint8Array to base64url.
 */
export function toBase64Url(bytes: Uint8Array): string {
    return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Convert base64url to Uint8Array.
 */
export function fromBase64Url(base64url: string): Uint8Array {
    // Pad with = to make it valid base64
    const padded = base64url.replace(/-/g, "+").replace(/_/g, "/");
    const padding = (4 - (padded.length % 4)) % 4;
    const base64 = padded + "=".repeat(padding);
    return fromBase64(base64);
}

/**
 * Convert string to Uint8Array (UTF-8).
 */
export function encodeUtf8(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

/**
 * Convert Uint8Array to string (UTF-8).
 */
export function decodeUtf8(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
}

/**
 * Concatenate multiple Uint8Arrays.
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

// ============================================================================
// AES-256-GCM Operations
// ============================================================================

/** GCM IV size in bytes (96 bits as recommended by NIST) */
export const GCM_IV_SIZE = 12;

/** GCM authentication tag length in bytes */
export const GCM_TAG_LENGTH = 16;

/** AES-256 key size in bytes */
export const AES_KEY_SIZE = 32;

/**
 * Import raw bytes as an AES-GCM key.
 */
export async function importAesKey(
    keyBytes: Uint8Array,
    usages: WebKeyUsage[] = ["encrypt", "decrypt"],
): Promise<WebCryptoKey> {
    const crypto = getCrypto();
    return crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM", length: 256 },
        false,
        usages,
    );
}

/**
 * Generate a random 256-bit AES key.
 */
export function generateAesKeyBytes(): Uint8Array {
    return getRandomBytes(AES_KEY_SIZE);
}

/**
 * Generate a random IV for AES-GCM.
 */
export function generateIv(): Uint8Array {
    return getRandomBytes(GCM_IV_SIZE);
}

/**
 * Encrypt content with AES-256-GCM.
 *
 * @param content - Plaintext content to encrypt
 * @param key - 256-bit AES key (raw bytes or WebCryptoKey)
 * @param iv - 96-bit initialization vector (generated if not provided)
 * @param aad - Optional additional authenticated data (integrity-bound but not encrypted)
 * @returns Encrypted content (ciphertext + auth tag) and IV
 */
export async function aesGcmEncrypt(
    content: Uint8Array,
    key: Uint8Array | WebCryptoKey,
    iv?: Uint8Array,
    aad?: Uint8Array,
): Promise<{ encryptedContent: Uint8Array; iv: Uint8Array }> {
    const crypto = getCrypto();
    const actualIv = iv ?? generateIv();
    const cryptoKey =
        typeof key === "object" && "algorithm" in key
            ? key
            : await importAesKey(key as Uint8Array, ["encrypt"]);

    const params = {
        name: "AES-GCM" as const,
        iv: actualIv,
        tagLength: GCM_TAG_LENGTH * 8,
        ...(aad ? { additionalData: aad } : {}),
    };

    const encrypted = await crypto.subtle.encrypt(
        params,
        cryptoKey,
        content,
    );

    return {
        encryptedContent: new Uint8Array(encrypted),
        iv: actualIv,
    };
}

/**
 * Decrypt content with AES-256-GCM.
 *
 * @param encryptedContent - Ciphertext + auth tag
 * @param key - 256-bit AES key (raw bytes or WebCryptoKey)
 * @param iv - Initialization vector used for encryption
 * @param aad - Optional additional authenticated data (must match what was used for encryption)
 * @returns Decrypted plaintext
 */
export async function aesGcmDecrypt(
    encryptedContent: Uint8Array,
    key: Uint8Array | WebCryptoKey,
    iv: Uint8Array,
    aad?: Uint8Array,
): Promise<Uint8Array> {
    const crypto = getCrypto();
    const cryptoKey =
        typeof key === "object" && "algorithm" in key
            ? key
            : await importAesKey(key as Uint8Array, ["decrypt"]);

    const params = {
        name: "AES-GCM" as const,
        iv,
        tagLength: GCM_TAG_LENGTH * 8,
        ...(aad ? { additionalData: aad } : {}),
    };

    const decrypted = await crypto.subtle.decrypt(
        params,
        cryptoKey,
        encryptedContent,
    );

    return new Uint8Array(decrypted);
}

// ============================================================================
// HMAC-SHA256 Operations
// ============================================================================

/**
 * Import raw bytes as an HMAC-SHA256 key.
 */
export async function importHmacKey(keyBytes: Uint8Array): Promise<WebCryptoKey> {
    const crypto = getCrypto();
    return crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"],
    );
}

/**
 * Compute HMAC-SHA256.
 */
export async function hmacSha256(
    key: Uint8Array | WebCryptoKey,
    data: Uint8Array,
): Promise<Uint8Array> {
    const crypto = getCrypto();
    const cryptoKey =
        typeof key === "object" && "algorithm" in key
            ? key
            : await importHmacKey(key as Uint8Array);

    const signature = await crypto.subtle.sign("HMAC", cryptoKey, data);
    return new Uint8Array(signature);
}

/**
 * Constant-time comparison of two byte arrays.
 * Returns true if equal, false otherwise.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}

// ============================================================================
// HKDF (RFC 5869)
// ============================================================================

/**
 * HKDF-Extract: Extract a pseudorandom key from input keying material.
 */
async function hkdfExtract(ikm: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
    return hmacSha256(salt, ikm);
}

/**
 * HKDF-Expand: Expand a pseudorandom key into output keying material.
 */
async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const hashLen = 32; // SHA-256 output length
  const n = Math.ceil(length / hashLen);

  // RFC 5869: output length must be <= 255 * HashLen
  if (n > 255) {
    throw new Error(
      `HKDF output length ${length} exceeds maximum ${255 * hashLen} bytes (RFC 5869)`,
    );
  }

  const okm = new Uint8Array(n * hashLen);

  let t: Uint8Array = new Uint8Array(0);
  for (let i = 1; i <= n; i++) {
    const input = concatBytes(t, info, new Uint8Array([i]));
    t = await hmacSha256(prk, input);
    okm.set(t, (i - 1) * hashLen);
  }

  return okm.subarray(0, length);
}

/**
 * HKDF key derivation function (RFC 5869).
 * Derives a key from input keying material using HMAC-SHA256.
 */
export async function hkdf(
    ikm: Uint8Array,
    salt: Uint8Array | string,
    info: Uint8Array | string,
    length: number,
): Promise<Uint8Array> {
    const saltBytes = typeof salt === "string" ? encodeUtf8(salt) : salt;
    const infoBytes = typeof info === "string" ? encodeUtf8(info) : info;

    const prk = await hkdfExtract(ikm, saltBytes);
    return hkdfExpand(prk, infoBytes, length);
}

// ============================================================================
// RSA-OAEP Operations
// ============================================================================

/**
 * Import an RSA public key from SPKI format (DER bytes or PEM string).
 */
export async function importRsaPublicKey(
    key: Uint8Array | string,
): Promise<WebCryptoKey> {
    const crypto = getCrypto();

    let keyData: Uint8Array;
    if (typeof key === "string") {
        // Parse PEM format
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";

        if (key.includes(pemHeader)) {
            const pemContent = key
                .replace(pemHeader, "")
                .replace(pemFooter, "")
                .replace(/\s/g, "");
            keyData = fromBase64(pemContent);
        } else {
            // Assume base64-encoded SPKI
            keyData = fromBase64(key);
        }
    } else {
        keyData = key;
    }

    return crypto.subtle.importKey(
        "spki",
        keyData,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"],
    );
}

/**
 * Encrypt data with RSA-OAEP.
 */
export async function rsaOaepEncrypt(
    publicKey: WebCryptoKey,
    data: Uint8Array,
    label?: Uint8Array,
): Promise<Uint8Array> {
    const crypto = getCrypto();
    const encrypted = await crypto.subtle.encrypt(
        { name: "RSA-OAEP", ...(label ? { label } : {}) },
        publicKey,
        data,
    );
    return new Uint8Array(encrypted);
}

// ============================================================================
// Ed25519 Operations
// ============================================================================

/** Ed25519 key pair */
export type Ed25519KeyPair = {
    /** Private key in PKCS8 DER format */
    privateKey: Uint8Array;
    /** Public key in SPKI DER format */
    publicKey: Uint8Array;
};

/**
 * Generate an Ed25519 key pair.
 */
export async function generateEd25519KeyPair(): Promise<Ed25519KeyPair> {
    const crypto = getCrypto();

    const keyPair = (await crypto.subtle.generateKey(
        { name: "Ed25519" },
        true, // extractable
        ["sign", "verify"],
    )) as { privateKey: WebCryptoKey; publicKey: WebCryptoKey };

    const privateKey = new Uint8Array(
        await crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
    );
    const publicKey = new Uint8Array(
        await crypto.subtle.exportKey("spki", keyPair.publicKey),
    );

    return { privateKey, publicKey };
}

/**
 * Import an Ed25519 private key from PKCS8 format.
 */
export async function importEd25519PrivateKey(
    key: Uint8Array | string,
): Promise<WebCryptoKey> {
    const crypto = getCrypto();

    let keyData: Uint8Array;
    if (typeof key === "string") {
        // Parse PEM format
        const pemHeader = "-----BEGIN PRIVATE KEY-----";
        const pemFooter = "-----END PRIVATE KEY-----";

        if (key.includes(pemHeader)) {
            const pemContent = key
                .replace(pemHeader, "")
                .replace(pemFooter, "")
                .replace(/\s/g, "");
            keyData = fromBase64(pemContent);
        } else {
            keyData = fromBase64(key);
        }
    } else {
        keyData = key;
    }

    return crypto.subtle.importKey(
        "pkcs8",
        keyData,
        { name: "Ed25519" },
        false,
        ["sign"],
    );
}

/**
 * Import an Ed25519 public key from SPKI format.
 */
export async function importEd25519PublicKey(
    key: Uint8Array | string,
): Promise<WebCryptoKey> {
    const crypto = getCrypto();

    let keyData: Uint8Array;
    if (typeof key === "string") {
        // Parse PEM format
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";

        if (key.includes(pemHeader)) {
            const pemContent = key
                .replace(pemHeader, "")
                .replace(pemFooter, "")
                .replace(/\s/g, "");
            keyData = fromBase64(pemContent);
        } else {
            keyData = fromBase64(key);
        }
    } else {
        keyData = key;
    }

    return crypto.subtle.importKey(
        "spki",
        keyData,
        { name: "Ed25519" },
        true, // extractable for JWK export
        ["verify"],
    );
}

/**
 * Sign data with Ed25519.
 */
export async function ed25519Sign(
    privateKey: WebCryptoKey,
    data: Uint8Array,
): Promise<Uint8Array> {
    const crypto = getCrypto();
    const signature = await crypto.subtle.sign("Ed25519", privateKey, data);
    return new Uint8Array(signature);
}

/**
 * Verify an Ed25519 signature.
 */
export async function ed25519Verify(
    publicKey: WebCryptoKey,
    signature: Uint8Array,
    data: Uint8Array,
): Promise<boolean> {
    const crypto = getCrypto();
    return crypto.subtle.verify("Ed25519", publicKey, signature, data);
}

/**
 * Export an Ed25519 public key as JWK.
 */
export async function exportEd25519PublicKeyAsJwk(
    publicKey: WebCryptoKey,
): Promise<WebJsonWebKey> {
    const crypto = getCrypto();
    return crypto.subtle.exportKey("jwk", publicKey) as Promise<WebJsonWebKey>;
}

/**
 * Convert PKCS8 private key to PEM format.
 */
export function privateKeyToPem(pkcs8: Uint8Array): string {
    const base64 = toBase64(pkcs8);
    const lines: string[] = [];
    for (let i = 0; i < base64.length; i += 64) {
        lines.push(base64.slice(i, i + 64));
    }
    return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----`;
}

/**
 * Convert SPKI public key to PEM format.
 */
export function publicKeyToPem(spki: Uint8Array): string {
    const base64 = toBase64(spki);
    const lines: string[] = [];
    for (let i = 0; i < base64.length; i += 64) {
        lines.push(base64.slice(i, i + 64));
    }
    return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----`;
}

/**
 * Parse a PEM-encoded key into raw DER bytes.
 */
export function parsePem(pem: string): Uint8Array {
    const pemHeader = /-----BEGIN [A-Z ]+-----/;
    const pemFooter = /-----END [A-Z ]+-----/;
    const b64 = pem.replace(pemHeader, "").replace(pemFooter, "").replace(/\s/g, "");
    return fromBase64(b64);
}

// ============================================================================
// SHA-256
// ============================================================================

/**
 * Compute SHA-256 hash of data.
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
    const crypto = getCrypto();
    const hash = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(hash);
}

// ============================================================================
// ECDH P-256 Operations (for DCA issuer key sealing)
// ============================================================================

/**
 * Generate an ECDH P-256 key pair.
 * Returns extractable keys so the public key can be exported.
 */
export async function generateEcdhP256KeyPair(): Promise<{
    privateKey: WebCryptoKey;
    publicKey: WebCryptoKey;
}> {
    const crypto = getCrypto();
    const keyPair = (await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"],
    )) as { privateKey: WebCryptoKey; publicKey: WebCryptoKey };
    return keyPair;
}

/**
 * Export an ECDH P-256 public key as uncompressed raw bytes (65 bytes: 0x04 || x || y).
 */
export async function exportEcdhP256PublicKeyRaw(key: WebCryptoKey): Promise<Uint8Array> {
    const crypto = getCrypto();
    const raw = await crypto.subtle.exportKey("raw", key);
    return new Uint8Array(raw);
}

/**
 * Import an ECDH P-256 public key from uncompressed raw bytes (65 bytes).
 */
export async function importEcdhP256PublicKeyRaw(raw: Uint8Array): Promise<WebCryptoKey> {
    const crypto = getCrypto();
    return crypto.subtle.importKey(
        "raw",
        raw,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        [],
    );
}

/**
 * Import an ECDH P-256 public key from SPKI PEM or DER.
 */
export async function importEcdhP256PublicKey(key: Uint8Array | string): Promise<WebCryptoKey> {
    const crypto = getCrypto();
    const keyData = typeof key === "string" ? parsePem(key) : key;
    return crypto.subtle.importKey(
        "spki",
        keyData,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        [],
    );
}

/**
 * Export an ECDH P-256 public key as a JWK (RFC 7517).
 */
export async function exportEcdhP256PublicKeyAsJwk(
    publicKey: WebCryptoKey,
): Promise<WebJsonWebKey> {
    const crypto = getCrypto();
    return crypto.subtle.exportKey("jwk", publicKey) as Promise<WebJsonWebKey>;
}

/**
 * Import an ECDH P-256 public key from a JWK (RFC 7517).
 */
export async function importEcdhP256PublicKeyFromJwk(jwk: WebJsonWebKey): Promise<WebCryptoKey> {
    const crypto = getCrypto();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (crypto.subtle.importKey as any)(
        "jwk",
        jwk,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        [],
    );
}

/**
 * Import an RSA-OAEP public key from a JWK (RFC 7517).
 */
export async function importRsaPublicKeyFromJwk(jwk: WebJsonWebKey): Promise<WebCryptoKey> {
    const crypto = getCrypto();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (crypto.subtle.importKey as any)(
        "jwk",
        jwk,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"],
    );
}

/**
 * Import an ECDH P-256 private key from PKCS8 PEM or DER.
 */
export async function importEcdhP256PrivateKey(key: Uint8Array | string): Promise<WebCryptoKey> {
    const crypto = getCrypto();
    const keyData = typeof key === "string" ? parsePem(key) : key;
    return crypto.subtle.importKey(
        "pkcs8",
        keyData,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
    );
}

/**
 * Derive the raw ECDH shared secret (x-coordinate, 32 bytes for P-256).
 */
export async function ecdhDeriveBits(
    privateKey: WebCryptoKey,
    publicKey: WebCryptoKey,
): Promise<Uint8Array> {
    const crypto = getCrypto();
    const bits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: publicKey },
        privateKey,
        256,
    );
    return new Uint8Array(bits);
}

// ============================================================================
// ECDSA P-256 Operations (ES256 for DCA JWTs)
// ============================================================================

/**
 * Generate an ECDSA P-256 key pair for ES256 signing.
 */
export async function generateEcdsaP256KeyPair(): Promise<{
    privateKey: WebCryptoKey;
    publicKey: WebCryptoKey;
}> {
    const crypto = getCrypto();
    const keyPair = (await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
    )) as { privateKey: WebCryptoKey; publicKey: WebCryptoKey };
    return keyPair;
}

/**
 * Import an ECDSA P-256 private key from PKCS8 PEM or DER.
 */
export async function importEcdsaP256PrivateKey(key: Uint8Array | string): Promise<WebCryptoKey> {
    const crypto = getCrypto();
    const keyData = typeof key === "string" ? parsePem(key) : key;
    return crypto.subtle.importKey(
        "pkcs8",
        keyData,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
    );
}

/**
 * Import an ECDSA P-256 public key from SPKI PEM or DER.
 */
export async function importEcdsaP256PublicKey(key: Uint8Array | string): Promise<WebCryptoKey> {
    const crypto = getCrypto();
    const keyData = typeof key === "string" ? parsePem(key) : key;
    return crypto.subtle.importKey(
        "spki",
        keyData,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"],
    );
}

/**
 * Sign data with ECDSA P-256 (ES256). Returns 64-byte IEEE P1363 signature (r || s).
 */
export async function ecdsaP256Sign(
    privateKey: WebCryptoKey,
    data: Uint8Array,
): Promise<Uint8Array> {
    const crypto = getCrypto();
    const sig = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        data,
    );
    return new Uint8Array(sig);
}

/**
 * Verify an ECDSA P-256 (ES256) signature.
 */
export async function ecdsaP256Verify(
    publicKey: WebCryptoKey,
    signature: Uint8Array,
    data: Uint8Array,
): Promise<boolean> {
    const crypto = getCrypto();
    return crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        signature,
        data,
    );
}

/**
 * Export an ECDSA/ECDH P-256 key pair to PEM format.
 */
export async function exportP256KeyPairPem(
    privateKey: WebCryptoKey,
    publicKey: WebCryptoKey,
): Promise<{ privateKeyPem: string; publicKeyPem: string }> {
    const crypto = getCrypto();
    const privDer = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
    const pubDer = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
    return {
        privateKeyPem: privateKeyToPem(privDer),
        publicKeyPem: publicKeyToPem(pubDer),
    };
}

/**
 * Import an RSA-OAEP private key from PKCS8 PEM or DER.
 */
export async function importRsaPrivateKey(
    key: Uint8Array | string,
): Promise<WebCryptoKey> {
    const crypto = getCrypto();
    const keyData = typeof key === "string" ? parsePem(key) : key;
    return crypto.subtle.importKey(
        "pkcs8",
        keyData,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"],
    );
}

/**
 * Decrypt data with RSA-OAEP.
 */
export async function rsaOaepDecrypt(
    privateKey: WebCryptoKey,
    data: Uint8Array,
    label?: Uint8Array,
): Promise<Uint8Array> {
    const crypto = getCrypto();
    const decrypted = await crypto.subtle.decrypt(
        { name: "RSA-OAEP", ...(label ? { label } : {}) },
        privateKey,
        data,
    );
    return new Uint8Array(decrypted);
}
