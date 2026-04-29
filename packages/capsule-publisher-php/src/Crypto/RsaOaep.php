<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Crypto;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PublicKey as RsaPublicKey;
use Sesamy\Capsule\Publisher\Exceptions\PublisherException;

/**
 * RSA-OAEP-SHA256 encryption.
 *
 * PHP's openssl_public_encrypt() with OPENSSL_PKCS1_OAEP_PADDING is hardcoded
 * to OAEP-SHA1, which does not match WebCrypto's RSA-OAEP-SHA256 default. We
 * use phpseclib3 — the standard pure-PHP crypto library — so the wrap blob
 * decrypts byte-for-byte against `crypto.subtle.decrypt({name:"RSA-OAEP"})`.
 *
 * The optional $label argument matches WebCrypto's `label` parameter (used by
 * the publisher to bind RSA-OAEP wrap blobs to the scope AAD).
 */
final class RsaOaep
{
    public static function encrypt(string $plaintext, string $publicKeyPem, ?string $label = null): string
    {
        $key = PublicKeyLoader::load($publicKeyPem);
        if (!$key instanceof RsaPublicKey) {
            throw new \InvalidArgumentException('RSA-OAEP requires an RSA public key');
        }

        $configured = $key
            ->withHash('sha256')
            ->withMGFHash('sha256')
            ->withPadding(RSA::ENCRYPTION_OAEP)
            ->withLabel($label ?? '');

        try {
            return $configured->encrypt($plaintext);
        } catch (\Throwable $e) {
            throw new PublisherException('RSA-OAEP encryption failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Decrypt — used only by tests and consumers that hold the issuer's private key.
     */
    public static function decrypt(string $ciphertext, string $privateKeyPem, ?string $label = null): string
    {
        $key = PublicKeyLoader::load($privateKeyPem);
        // Allow either a private key directly or PrivateKey/PublicKey loader.
        if (!$key instanceof \phpseclib3\Crypt\RSA\PrivateKey) {
            throw new \InvalidArgumentException('RSA-OAEP decrypt requires an RSA private key');
        }

        $configured = $key
            ->withHash('sha256')
            ->withMGFHash('sha256')
            ->withPadding(RSA::ENCRYPTION_OAEP)
            ->withLabel($label ?? '');

        try {
            return $configured->decrypt($ciphertext);
        } catch (\Throwable $e) {
            throw new PublisherException('RSA-OAEP decryption failed: ' . $e->getMessage(), 0, $e);
        }
    }
}
