<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Crypto;

use OpenSSLAsymmetricKey;
use Sesamy\Capsule\Publisher\Exceptions\PublisherException;

/**
 * ECDH on the NIST P-256 curve (prime256v1).
 *
 * Wraps PHP's openssl ECDH so the rest of the codebase can speak in raw
 * 65-byte uncompressed public keys (`0x04 || x || y`) and 32-byte shared
 * secrets — matching the ECDH wrap blob layout the JS publisher emits.
 */
final class EcdhP256
{
    public const RAW_PUBKEY_LEN = 65;
    public const SHARED_SECRET_LEN = 32;
    private const COORD_LEN = 32;
    private const SPKI_HEADER_HEX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    /**
     * Generate a fresh ephemeral P-256 keypair.
     *
     * @return array{privateKey: OpenSSLAsymmetricKey, publicKeyRaw: string}
     */
    public static function generateEphemeral(): array
    {
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        if ($privateKey === false) {
            throw new PublisherException('Failed to generate ECDH P-256 keypair');
        }
        $details = openssl_pkey_get_details($privateKey);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
            throw new PublisherException('Generated key is not EC');
        }
        $x = self::leftPad((string) ($details['ec']['x'] ?? ''), self::COORD_LEN);
        $y = self::leftPad((string) ($details['ec']['y'] ?? ''), self::COORD_LEN);

        return [
            'privateKey' => $privateKey,
            'publicKeyRaw' => "\x04" . $x . $y,
        ];
    }

    /**
     * Import an issuer's P-256 public key from SPKI PEM (or SPKI DER bytes).
     */
    public static function importPublicKey(string $pemOrDer): OpenSSLAsymmetricKey
    {
        // Try PEM first, fall back to wrapping raw DER as PEM if needed.
        $key = openssl_pkey_get_public($pemOrDer);
        if ($key === false) {
            $der = self::looksLikePem($pemOrDer) ? Pem::parse($pemOrDer) : $pemOrDer;
            $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
            $key = openssl_pkey_get_public($pem);
        }
        if ($key === false) {
            throw new \InvalidArgumentException('Failed to import ECDH P-256 public key');
        }
        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
            throw new \InvalidArgumentException('Provided key is not EC');
        }
        if (($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            throw new \InvalidArgumentException('ECDH key must be on the P-256 (prime256v1) curve');
        }
        return $key;
    }

    /**
     * Build an EC P-256 public key from a raw uncompressed point (65 bytes,
     * 0x04 || x || y) by wrapping it in a synthetic SPKI structure. Used
     * primarily on the unwrap side (tests).
     */
    public static function importPublicKeyRaw(string $rawUncompressed): OpenSSLAsymmetricKey
    {
        if (strlen($rawUncompressed) !== self::RAW_PUBKEY_LEN || $rawUncompressed[0] !== "\x04") {
            throw new \InvalidArgumentException('raw EC point must be 65 bytes starting with 0x04');
        }
        $der = hex2bin(self::SPKI_HEADER_HEX) . $rawUncompressed;
        return self::importPublicKey($der);
    }

    /**
     * Derive a 32-byte ECDH shared secret (the x-coordinate of $priv * $pub).
     */
    public static function deriveSharedSecret(OpenSSLAsymmetricKey $privateKey, OpenSSLAsymmetricKey $issuerPublicKey): string
    {
        $secret = openssl_pkey_derive($issuerPublicKey, $privateKey, self::SHARED_SECRET_LEN);
        if ($secret === false) {
            throw new PublisherException('ECDH derivation failed');
        }
        // Some openssl builds may return the secret without left-padding when
        // the leading byte is zero. Normalise to a fixed 32 bytes.
        return self::leftPad($secret, self::SHARED_SECRET_LEN);
    }

    /**
     * Extract the 32-byte x-coordinate from a P-256 SPKI/raw public key.
     * Used by tests; not on the publisher hot path.
     */
    public static function rawFromKey(OpenSSLAsymmetricKey $key): string
    {
        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
            throw new \InvalidArgumentException('Key is not EC');
        }
        $x = self::leftPad((string) ($details['ec']['x'] ?? ''), self::COORD_LEN);
        $y = self::leftPad((string) ($details['ec']['y'] ?? ''), self::COORD_LEN);
        return "\x04" . $x . $y;
    }

    private static function looksLikePem(string $input): bool
    {
        return str_contains($input, '-----BEGIN ');
    }

    private static function leftPad(string $bytes, int $length): string
    {
        if (strlen($bytes) === $length) {
            return $bytes;
        }
        if (strlen($bytes) > $length) {
            // Some builds return secrets longer than expected when leading byte represents sign — never expected for P-256 but handle defensively.
            throw new \InvalidArgumentException('value longer than target length');
        }
        return str_repeat("\x00", $length - strlen($bytes)) . $bytes;
    }
}
