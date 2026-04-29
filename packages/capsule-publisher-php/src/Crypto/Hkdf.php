<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Crypto;

/**
 * HKDF-SHA256 (RFC 5869) — uses PHP's built-in hash_hkdf().
 *
 * Note on argument order: hash_hkdf signature is (algo, ikm, length, info, salt) —
 * deliberately wrap it so callers see (ikm, salt, info, length) like WebCrypto / RFC 5869.
 */
final class Hkdf
{
    public static function sha256(string $ikm, string $salt, string $info, int $length): string
    {
        if ($length < 1) {
            throw new \InvalidArgumentException('HKDF length must be >= 1');
        }
        // hash_hkdf with SHA-256 enforces length <= 255 * 32 internally.
        return hash_hkdf('sha256', $ikm, $length, $info, $salt);
    }
}
