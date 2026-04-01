/**
 * DCA Seal — ECDH P-256 and RSA-OAEP key sealing / unsealing.
 *
 * Sealing wraps key material (contentKey or periodKey) so only the issuer
 * holding the matching private key can unseal it.
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
/** Minimum sealed blob size: ephemeralPub + IV + GCM tag (zero-length plaintext) */
const MIN_ECDH_BLOB_LEN = ECDH_PUB_LEN + IV_LEN + GCM_TAG_LEN;

// ============================================================================
// ECDH P-256 sealing
// ============================================================================

/** HKDF salt for ECDH seal key derivation (domain separation) */
const SEAL_HKDF_SALT = "dca-seal";
/** HKDF info for ECDH seal key derivation */
const SEAL_HKDF_INFO = "dca-seal-aes256gcm";

/**
 * Seal (encrypt) key material with an issuer's ECDH P-256 public key.
 *
 * For each seal, a fresh ephemeral keypair is generated. The raw ECDH
 * shared secret is run through HKDF-SHA256 to derive the AES-256-GCM key
 * (NIST SP 800-56C compliant).
 *
 * @param plaintext - Key material to seal (e.g., a 32-byte AES key)
 * @param issuerPublicKey - Issuer's ECDH P-256 public key (CryptoKey)
 * @returns Self-contained sealed blob (base64url-encoded)
 */
export async function sealEcdhP256(
    plaintext: Uint8Array,
    issuerPublicKey: WebCryptoKey,
    aad?: Uint8Array,
): Promise<string> {
    // Generate fresh ephemeral keypair
    const ephemeral = await generateEcdhP256KeyPair();

    // ECDH shared secret → HKDF → AES-256-GCM key
    const sharedSecret = await ecdhDeriveBits(ephemeral.privateKey, issuerPublicKey);
    const derivedKey = await hkdf(sharedSecret, SEAL_HKDF_SALT, SEAL_HKDF_INFO, 32);
    const aesKey = await importAesKey(derivedKey, ["encrypt"]);

    // Encrypt key material
    const iv = generateIv();
    const { encryptedContent } = await aesGcmEncrypt(plaintext, aesKey, iv, aad);

    // Export ephemeral public key as raw 65 bytes
    const ephemeralPubRaw = await exportEcdhP256PublicKeyRaw(ephemeral.publicKey);

    // Assemble blob: ephemeralPub(65) || IV(12) || ciphertext+tag
    const blob = concatBytes(ephemeralPubRaw, iv, encryptedContent);
    return toBase64Url(blob);
}

/**
 * Unseal (decrypt) an ECDH P-256 sealed blob with the issuer's private key.
 *
 * @param sealedBlob - base64url-encoded sealed blob
 * @param issuerPrivateKey - Issuer's ECDH P-256 private key (CryptoKey)
 * @returns Decrypted key material
 */
export async function unsealEcdhP256(
    sealedBlob: string,
    issuerPrivateKey: WebCryptoKey,
    aad?: Uint8Array,
): Promise<Uint8Array> {
    const blob = fromBase64Url(sealedBlob);

    // Validate blob length before parsing fixed-offset fields
    if (blob.length < MIN_ECDH_BLOB_LEN) {
        throw new Error(
            `Invalid ECDH-P256 sealed blob: expected at least ${MIN_ECDH_BLOB_LEN} bytes, got ${blob.length}`,
        );
    }

    // Parse blob
    const ephemeralPubRaw = blob.slice(0, ECDH_PUB_LEN);
    const iv = blob.slice(ECDH_PUB_LEN, ECDH_PUB_LEN + IV_LEN);
    const ciphertext = blob.slice(ECDH_PUB_LEN + IV_LEN);

    // Import ephemeral public key
    const ephemeralPubKey = await importEcdhP256PublicKeyRaw(ephemeralPubRaw);

    // ECDH shared secret → HKDF → AES-256-GCM key
    const sharedSecret = await ecdhDeriveBits(issuerPrivateKey, ephemeralPubKey);
    const derivedKey = await hkdf(sharedSecret, SEAL_HKDF_SALT, SEAL_HKDF_INFO, 32);
    const aesKey = await importAesKey(derivedKey, ["decrypt"]);

    // Decrypt
    return aesGcmDecrypt(ciphertext, aesKey, iv, aad);
}

// ============================================================================
// RSA-OAEP sealing
// ============================================================================

/**
 * Seal key material with an issuer's RSA-OAEP public key.
 *
 * @param plaintext - Key material to seal
 * @param issuerPublicKey - Issuer's RSA-OAEP public key (CryptoKey)
 * @returns base64url-encoded RSA-OAEP ciphertext
 */
export async function sealRsaOaep(
    plaintext: Uint8Array,
    issuerPublicKey: WebCryptoKey,
    aad?: Uint8Array,
): Promise<string> {
    const encrypted = await rsaOaepEncrypt(issuerPublicKey, plaintext, aad);
    return toBase64Url(encrypted);
}

/**
 * Unseal RSA-OAEP sealed key material with the issuer's private key.
 *
 * @param sealedBlob - base64url-encoded RSA-OAEP ciphertext
 * @param issuerPrivateKey - Issuer's RSA-OAEP private key (CryptoKey)
 * @returns Decrypted key material
 */
export async function unsealRsaOaep(
    sealedBlob: string,
    issuerPrivateKey: WebCryptoKey,
    aad?: Uint8Array,
): Promise<Uint8Array> {
    const ciphertext = fromBase64Url(sealedBlob);
    return rsaOaepDecrypt(issuerPrivateKey, ciphertext, aad);
}

// ============================================================================
// Unified interface
// ============================================================================

export type DcaSealAlgorithm = "ECDH-P256" | "RSA-OAEP";

/**
 * Seal key material with an issuer's public key (auto-dispatches by algorithm).
 */
export async function seal(
    plaintext: Uint8Array,
    issuerPublicKey: WebCryptoKey,
    algorithm: DcaSealAlgorithm,
    aad?: Uint8Array,
): Promise<string> {
    if (algorithm === "ECDH-P256") {
        return sealEcdhP256(plaintext, issuerPublicKey, aad);
    }
    return sealRsaOaep(plaintext, issuerPublicKey, aad);
}

/**
 * Unseal key material with an issuer's private key (auto-dispatches by algorithm).
 */
export async function unseal(
    sealedBlob: string,
    issuerPrivateKey: WebCryptoKey,
    algorithm: DcaSealAlgorithm,
    aad?: Uint8Array,
): Promise<Uint8Array> {
    if (algorithm === "ECDH-P256") {
        return unsealEcdhP256(sealedBlob, issuerPrivateKey, aad);
    }
    return unsealRsaOaep(sealedBlob, issuerPrivateKey, aad);
}

/**
 * Import an issuer public key from PEM, detecting algorithm from key type.
 *
 * @returns The imported CryptoKey and detected algorithm
 */
export async function importIssuerPublicKey(
    pem: string,
    algorithmHint?: DcaSealAlgorithm,
): Promise<{ key: WebCryptoKey; algorithm: DcaSealAlgorithm }> {
    // If hint provided, use it
    if (algorithmHint === "RSA-OAEP") {
        const key = await importRsaPublicKey(pem);
        return { key, algorithm: "RSA-OAEP" };
    }
    if (algorithmHint === "ECDH-P256") {
        const key = await importEcdhP256PublicKey(pem);
        return { key, algorithm: "ECDH-P256" };
    }

    // Auto-detect: RSA keys have "RSA" in the DER or are much larger
    // Try ECDH first (smaller, more likely for DCA), fall back to RSA
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
    algorithmHint?: DcaSealAlgorithm,
): Promise<{ key: WebCryptoKey; algorithm: DcaSealAlgorithm }> {
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
