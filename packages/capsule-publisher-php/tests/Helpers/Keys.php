<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Tests\Helpers;

/**
 * Shared key generation helpers — keep tests independent of pinned PEM
 * fixtures while still using openssl-generated keys end to end.
 */
final class Keys
{
    /**
     * @return array{privatePem:string, publicPem:string}
     */
    public static function generateEcdsaP256(): array
    {
        $kp = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($kp === false) {
            throw new \RuntimeException('Failed to generate ECDSA P-256 keypair');
        }
        openssl_pkey_export($kp, $privatePem);
        $publicPem = openssl_pkey_get_details($kp)['key'];
        return ['privatePem' => $privatePem, 'publicPem' => $publicPem];
    }

    /**
     * @return array{privatePem:string, publicPem:string}
     */
    public static function generateEcdhP256(): array
    {
        // Same key shape as ECDSA on P-256 — different SDK usage downstream.
        return self::generateEcdsaP256();
    }

    /**
     * @return array{privatePem:string, publicPem:string}
     */
    public static function generateRsa(int $bits = 2048): array
    {
        $kp = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits]);
        if ($kp === false) {
            throw new \RuntimeException('Failed to generate RSA keypair');
        }
        openssl_pkey_export($kp, $privatePem);
        $publicPem = openssl_pkey_get_details($kp)['key'];
        return ['privatePem' => $privatePem, 'publicPem' => $publicPem];
    }
}
