/**
 * DCA Wrap — ECDH P-256 and RSA-OAEP key wrapping for issuer delivery.
 *
 * Wraps key material (contentKey or wrapKey) so only the issuer holding the
 * matching private key can unwrap it. This is WebCrypto-style key wrapping
 * (the wrapping key is a public key), analogous to HPKE's Seal/Open.
 *
 * ECDH P-256 blob format (self-contained, no length prefixes):
 *   | Offset | Length    | Field                                    |
 *   |--------|-----------|------------------------------------------|
 *   | 0      | 65 bytes  | Ephemeral public key (uncompressed P-256)|
 *   | 65     | 12 bytes  | IV (AES-256-GCM nonce)                   |
 *   | 77     | remaining | Ciphertext + 16-byte GCM auth tag        |
 *
 * RSA-OAEP: plain RSA-OAEP ciphertext (SHA-256). No internal structure.
 */

import {
    generateEcdhP256KeyPair,
    exportEcdhP256PublicKeyRaw,
    importEcdhP256PublicKeyRaw,
    importEcdhP256PublicKey,
    importEcdhP256PrivateKey,
    ecdhDeriveBits,
    importAesKey,
    aesGcmEncrypt,
    aesGcmDecrypt,
    generateIv,
    importRsaPublicKey,
    rsaOaepEncrypt,
    importRsaPrivateKey,
    rsaOaepDecrypt,
    toBase64Url,
    fromBase64Url,
    concatBytes,
    hkdf,
    type WebCryptoKey,
} from "./web-crypto";

/** ECDH P-256 ephemeral public key length (uncompressed) */
const ECDH_PUB_LEN = 65;
/** AES-GCM IV length */
const IV_LEN = 12;
/** AES-GCM authentication tag length */
const GCM_TAG_LEN = 16;
/** Minimum wrapped blob size: ephemeralPub + IV + GCM tag (zero-length plaintext) */
const MIN_ECDH_BLOB_LEN = ECDH_PUB_LEN + IV_LEN + GCM_TAG_LEN;

// ============================================================================
// ECDH P-256 wrap
// ============================================================================

/** HKDF salt for ECDH wrap key derivation (domain separation) */
const WRAP_HKDF_SALT = "dca-wrap";
/** HKDF info for ECDH wrap key derivation */
const WRAP_HKDF_INFO = "dca-wrap-aes256gcm";

/**
 * Wrap (encrypt) key material with an issuer's ECDH P-256 public key.
 *
 * For each wrap, a fresh ephemeral keypair is generated. The raw ECDH
 * shared secret is run through HKDF-SHA256 to derive the AES-256-GCM key
 * (NIST SP 800-56C compliant).
 *
 * @param plaintext - Key material to wrap (e.g., a 32-byte AES key)
 * @param issuerPublicKey - Issuer's ECDH P-256 public key (CryptoKey)
 * @returns Self-contained wrapped blob (base64url-encoded)
 */
export async function wrapEcdhP256(
    plaintext: Uint8Array,
    issuerPublicKey: WebCryptoKey,
    aad?: Uint8Array,
): Promise<string> {
    const ephemeral = await generateEcdhP256KeyPair();

    const sharedSecret = await ecdhDeriveBits(ephemeral.privateKey, issuerPublicKey);
    const derivedKey = await hkdf(sharedSecret, WRAP_HKDF_SALT, WRAP_HKDF_INFO, 32);
    const aesKey = await importAesKey(derivedKey, ["encrypt"]);

    const iv = generateIv();
    const { encryptedContent } = await aesGcmEncrypt(plaintext, aesKey, iv, aad);

    const ephemeralPubRaw = await exportEcdhP256PublicKeyRaw(ephemeral.publicKey);

    const blob = concatBytes(ephemeralPubRaw, iv, encryptedContent);
    return toBase64Url(blob);
}

/**
 * Unwrap (decrypt) an ECDH P-256 wrapped blob with the issuer's private key.
 *
 * @param wrappedBlob - base64url-encoded wrapped blob
 * @param issuerPrivateKey - Issuer's ECDH P-256 private key (CryptoKey)
 * @returns Decrypted key material
 */
export async function unwrapEcdhP256(
    wrappedBlob: string,
    issuerPrivateKey: WebCryptoKey,
    aad?: Uint8Array,
): Promise<Uint8Array> {
    const blob = fromBase64Url(wrappedBlob);

    if (blob.length < MIN_ECDH_BLOB_LEN) {
        throw new Error(
            `Invalid ECDH-P256 wrapped blob: expected at least ${MIN_ECDH_BLOB_LEN} bytes, got ${blob.length}`,
        );
    }

    const ephemeralPubRaw = blob.slice(0, ECDH_PUB_LEN);
    const iv = blob.slice(ECDH_PUB_LEN, ECDH_PUB_LEN + IV_LEN);
    const ciphertext = blob.slice(ECDH_PUB_LEN + IV_LEN);

    const ephemeralPubKey = await importEcdhP256PublicKeyRaw(ephemeralPubRaw);

    const sharedSecret = await ecdhDeriveBits(issuerPrivateKey, ephemeralPubKey);
    const derivedKey = await hkdf(sharedSecret, WRAP_HKDF_SALT, WRAP_HKDF_INFO, 32);
    const aesKey = await importAesKey(derivedKey, ["decrypt"]);

    return aesGcmDecrypt(ciphertext, aesKey, iv, aad);
}

// ============================================================================
// RSA-OAEP wrap
// ============================================================================

/**
 * Wrap key material with an issuer's RSA-OAEP public key.
 */
export async function wrapRsaOaep(
    plaintext: Uint8Array,
    issuerPublicKey: WebCryptoKey,
    aad?: Uint8Array,
): Promise<string> {
    const encrypted = await rsaOaepEncrypt(issuerPublicKey, plaintext, aad);
    return toBase64Url(encrypted);
}

/**
 * Unwrap RSA-OAEP wrapped key material with the issuer's private key.
 */
export async function unwrapRsaOaep(
    wrappedBlob: string,
    issuerPrivateKey: WebCryptoKey,
    aad?: Uint8Array,
): Promise<Uint8Array> {
    const ciphertext = fromBase64Url(wrappedBlob);
    return rsaOaepDecrypt(issuerPrivateKey, ciphertext, aad);
}

// ============================================================================
// Unified interface
// ============================================================================

export type DcaWrapAlgorithm = "ECDH-P256" | "RSA-OAEP";

/**
 * Wrap key material with an issuer's public key (auto-dispatches by algorithm).
 */
export async function wrap(
    plaintext: Uint8Array,
    issuerPublicKey: WebCryptoKey,
    algorithm: DcaWrapAlgorithm,
    aad?: Uint8Array,
): Promise<string> {
    if (algorithm === "ECDH-P256") {
        return wrapEcdhP256(plaintext, issuerPublicKey, aad);
    }
    return wrapRsaOaep(plaintext, issuerPublicKey, aad);
}

/**
 * Unwrap key material with an issuer's private key (auto-dispatches by algorithm).
 */
export async function unwrap(
    wrappedBlob: string,
    issuerPrivateKey: WebCryptoKey,
    algorithm: DcaWrapAlgorithm,
    aad?: Uint8Array,
): Promise<Uint8Array> {
    if (algorithm === "ECDH-P256") {
        return unwrapEcdhP256(wrappedBlob, issuerPrivateKey, aad);
    }
    return unwrapRsaOaep(wrappedBlob, issuerPrivateKey, aad);
}

/**
 * Import an issuer public key from PEM, detecting algorithm from key type.
 *
 * @returns The imported CryptoKey and detected algorithm
 */
export async function importIssuerPublicKey(
    pem: string,
    algorithmHint?: DcaWrapAlgorithm,
): Promise<{ key: WebCryptoKey; algorithm: DcaWrapAlgorithm }> {
    if (algorithmHint === "RSA-OAEP") {
        const key = await importRsaPublicKey(pem);
        return { key, algorithm: "RSA-OAEP" };
    }
    if (algorithmHint === "ECDH-P256") {
        const key = await importEcdhP256PublicKey(pem);
        return { key, algorithm: "ECDH-P256" };
    }

    try {
        const key = await importEcdhP256PublicKey(pem);
        return { key, algorithm: "ECDH-P256" };
    } catch {
        const key = await importRsaPublicKey(pem);
        return { key, algorithm: "RSA-OAEP" };
    }
}

/**
 * Import an issuer private key from PEM, detecting algorithm from key type.
 */
export async function importIssuerPrivateKey(
    pem: string,
    algorithmHint?: DcaWrapAlgorithm,
): Promise<{ key: WebCryptoKey; algorithm: DcaWrapAlgorithm }> {
    if (algorithmHint === "RSA-OAEP") {
        const key = await importRsaPrivateKey(pem);
        return { key, algorithm: "RSA-OAEP" };
    }
    if (algorithmHint === "ECDH-P256") {
        const key = await importEcdhP256PrivateKey(pem);
        return { key, algorithm: "ECDH-P256" };
    }

    try {
        const key = await importEcdhP256PrivateKey(pem);
        return { key, algorithm: "ECDH-P256" };
    } catch {
        const key = await importRsaPrivateKey(pem);
        return { key, algorithm: "RSA-OAEP" };
    }
}
