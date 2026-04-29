<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Crypto;

final class Encoding
{
    public static function toBase64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function fromBase64Url(string $b64url): string
    {
        $b64 = strtr($b64url, '-_', '+/');
        $pad = strlen($b64) % 4;
        if ($pad !== 0) {
            $b64 .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($b64, true);
        if ($decoded === false) {
            throw new \InvalidArgumentException('Invalid base64url input');
        }
        return $decoded;
    }

    public static function toHex(string $bytes): string
    {
        return bin2hex($bytes);
    }

    public static function fromHex(string $hex): string
    {
        $bytes = @hex2bin($hex);
        if ($bytes === false) {
            throw new \InvalidArgumentException('Invalid hex input');
        }
        return $bytes;
    }
}
