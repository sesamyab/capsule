<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Dca;

use Sesamy\Capsule\Publisher\Crypto\Aes;
use Sesamy\Capsule\Publisher\Crypto\EcdhP256;
use Sesamy\Capsule\Publisher\Crypto\Encoding;
use Sesamy\Capsule\Publisher\Crypto\Hkdf;
use Sesamy\Capsule\Publisher\Crypto\Random;
use Sesamy\Capsule\Publisher\Crypto\RsaOaep;

/**
 * DCA key wrapping for issuer delivery.
 *
 * Mirrors packages/capsule-server/src/dca-wrap.ts. ECDH wrap blob layout
 * (self-contained, no length prefixes):
 *
 *   | Offset | Length    | Field                                    |
 *   |--------|-----------|------------------------------------------|
 *   | 0      | 65 bytes  | Ephemeral public key (uncompressed P-256)|
 *   | 65     | 12 bytes  | IV (AES-256-GCM nonce)                   |
 *   | 77     | remaining | Ciphertext + 16-byte GCM auth tag        |
 *
 * RSA-OAEP: plain RSA-OAEP-SHA256 ciphertext, base64url-encoded. AAD becomes
 * the OAEP `label`.
 */
final class Wrap
{
    public const ALG_ECDH_P256 = 'ECDH-P256';
    public const ALG_RSA_OAEP = 'RSA-OAEP';

    private const WRAP_HKDF_SALT = 'dca-wrap';
    private const WRAP_HKDF_INFO = 'dca-wrap-aes256gcm';

    /**
     * Wrap key material for an issuer.
     *
     * @param string      $plaintext     raw bytes (e.g., a 32-byte AES key)
     * @param string      $issuerKeyPem  issuer public key PEM
     * @param string      $algorithm     ALG_ECDH_P256 or ALG_RSA_OAEP
     * @param string|null $aad           optional AAD (scope bytes)
     * @return string base64url-encoded wrapped blob
     */
    public static function wrap(string $plaintext, string $issuerKeyPem, string $algorithm, ?string $aad = null): string
    {
        return match ($algorithm) {
            self::ALG_ECDH_P256 => self::wrapEcdhP256($plaintext, $issuerKeyPem, $aad),
            self::ALG_RSA_OAEP => self::wrapRsaOaep($plaintext, $issuerKeyPem, $aad),
            default => throw new \InvalidArgumentException("Unknown wrap algorithm: $algorithm"),
        };
    }

    /**
     * Auto-detect the algorithm from a public key PEM.
     */
    public static function detectAlgorithm(string $publicKeyPem): string
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            throw new \InvalidArgumentException('Could not import public key');
        }
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new \InvalidArgumentException('Could not read public key details');
        }
        $type = $details['type'] ?? null;
        if ($type === OPENSSL_KEYTYPE_EC) {
            $curve = $details['ec']['curve_name'] ?? null;
            if ($curve !== 'prime256v1') {
                throw new \InvalidArgumentException("EC curve $curve is not supported (need prime256v1)");
            }
            return self::ALG_ECDH_P256;
        }
        if ($type === OPENSSL_KEYTYPE_RSA) {
            return self::ALG_RSA_OAEP;
        }
        throw new \InvalidArgumentException('Unsupported issuer key type');
    }

    public static function wrapEcdhP256(string $plaintext, string $issuerPublicKeyPem, ?string $aad = null): string
    {
        $issuerPub = EcdhP256::importPublicKey($issuerPublicKeyPem);
        $ephemeral = EcdhP256::generateEphemeral();

        $sharedSecret = EcdhP256::deriveSharedSecret($ephemeral['privateKey'], $issuerPub);
        $derivedKey = Hkdf::sha256($sharedSecret, self::WRAP_HKDF_SALT, self::WRAP_HKDF_INFO, 32);

        $iv = Random::iv();
        $ciphertext = Aes::gcmEncrypt($plaintext, $derivedKey, $iv, $aad);

        $blob = $ephemeral['publicKeyRaw'] . $iv . $ciphertext;
        return Encoding::toBase64Url($blob);
    }

    /**
     * Unwrap an ECDH-P256 blob with the issuer's private key. Used by tests
     * (the publisher itself never unwraps).
     */
    public static function unwrapEcdhP256(string $blobBase64Url, string $issuerPrivateKeyPem, ?string $aad = null): string
    {
        $blob = Encoding::fromBase64Url($blobBase64Url);
        if (strlen($blob) < EcdhP256::RAW_PUBKEY_LEN + Random::GCM_IV_SIZE + Random::GCM_TAG_LENGTH) {
            throw new \InvalidArgumentException('ECDH-P256 wrapped blob too short');
        }
        $ephemeralPubRaw = substr($blob, 0, EcdhP256::RAW_PUBKEY_LEN);
        $iv = substr($blob, EcdhP256::RAW_PUBKEY_LEN, Random::GCM_IV_SIZE);
        $ciphertext = substr($blob, EcdhP256::RAW_PUBKEY_LEN + Random::GCM_IV_SIZE);

        $issuerPriv = openssl_pkey_get_private($issuerPrivateKeyPem);
        if ($issuerPriv === false) {
            throw new \InvalidArgumentException('Invalid issuer ECDH private key');
        }
        $ephemeralPub = EcdhP256::importPublicKeyRaw($ephemeralPubRaw);

        $sharedSecret = EcdhP256::deriveSharedSecret($issuerPriv, $ephemeralPub);
        $derivedKey = Hkdf::sha256($sharedSecret, self::WRAP_HKDF_SALT, self::WRAP_HKDF_INFO, 32);

        return Aes::gcmDecrypt($ciphertext, $derivedKey, $iv, $aad);
    }

    public static function wrapRsaOaep(string $plaintext, string $issuerPublicKeyPem, ?string $aad = null): string
    {
        $ciphertext = RsaOaep::encrypt($plaintext, $issuerPublicKeyPem, $aad);
        return Encoding::toBase64Url($ciphertext);
    }

    public static function unwrapRsaOaep(string $blobBase64Url, string $issuerPrivateKeyPem, ?string $aad = null): string
    {
        $ciphertext = Encoding::fromBase64Url($blobBase64Url);
        return RsaOaep::decrypt($ciphertext, $issuerPrivateKeyPem, $aad);
    }
}
