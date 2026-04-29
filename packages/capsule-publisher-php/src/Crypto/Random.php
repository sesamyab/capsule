<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Crypto;

final class Random
{
    public const GCM_IV_SIZE = 12;
    public const GCM_TAG_LENGTH = 16;
    public const AES_KEY_SIZE = 32;

    public static function bytes(int $length): string
    {
        if ($length < 1) {
            throw new \InvalidArgumentException('length must be >= 1');
        }
        return random_bytes($length);
    }

    public static function aesKey(): string
    {
        return self::bytes(self::AES_KEY_SIZE);
    }

    public static function iv(): string
    {
        return self::bytes(self::GCM_IV_SIZE);
    }

    public static function renderId(): string
    {
        return Encoding::toBase64Url(self::bytes(16));
    }

    public static function jti(): string
    {
        return Encoding::toHex(self::bytes(16));
    }
}
