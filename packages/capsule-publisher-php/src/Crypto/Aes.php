<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Crypto;

use Sesamy\Capsule\Publisher\Exceptions\PublisherException;

/**
 * AES-256-GCM encryption.
 *
 * Output layout matches WebCrypto: ciphertext is `body || tag` (16-byte tag appended).
 */
final class Aes
{
    /**
     * Encrypt with AES-256-GCM.
     *
     * @param string      $plaintext raw bytes
     * @param string      $key       32 raw bytes (AES-256)
     * @param string      $iv        12 raw bytes
     * @param string|null $aad       optional additional authenticated data (raw bytes)
     * @return string ciphertext || tag (length = strlen($plaintext) + 16)
     */
    public static function gcmEncrypt(string $plaintext, string $key, string $iv, ?string $aad = null): string
    {
        if (strlen($key) !== Random::AES_KEY_SIZE) {
            throw new \InvalidArgumentException('AES-256-GCM key must be 32 bytes');
        }
        if (strlen($iv) !== Random::GCM_IV_SIZE) {
            throw new \InvalidArgumentException('AES-GCM IV must be 12 bytes');
        }

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad ?? '',
            Random::GCM_TAG_LENGTH,
        );
        if ($ciphertext === false) {
            throw new PublisherException('AES-256-GCM encryption failed: ' . self::lastOpensslError());
        }
        return $ciphertext . $tag;
    }

    /**
     * Decrypt AES-256-GCM (used in tests for round-trip).
     */
    public static function gcmDecrypt(string $ciphertextWithTag, string $key, string $iv, ?string $aad = null): string
    {
        if (strlen($key) !== Random::AES_KEY_SIZE) {
            throw new \InvalidArgumentException('AES-256-GCM key must be 32 bytes');
        }
        if (strlen($iv) !== Random::GCM_IV_SIZE) {
            throw new \InvalidArgumentException('AES-GCM IV must be 12 bytes');
        }
        if (strlen($ciphertextWithTag) < Random::GCM_TAG_LENGTH) {
            throw new \InvalidArgumentException('ciphertext shorter than GCM tag');
        }
        $tag = substr($ciphertextWithTag, -Random::GCM_TAG_LENGTH);
        $body = substr($ciphertextWithTag, 0, -Random::GCM_TAG_LENGTH);

        $plaintext = openssl_decrypt(
            $body,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad ?? '',
        );
        if ($plaintext === false) {
            throw new PublisherException('AES-256-GCM decryption failed: ' . self::lastOpensslError());
        }
        return $plaintext;
    }

    private static function lastOpensslError(): string
    {
        $msg = '';
        while (($err = openssl_error_string()) !== false) {
            $msg = $err;
        }
        return $msg;
    }
}
