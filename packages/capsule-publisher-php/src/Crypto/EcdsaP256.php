<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Crypto;

use Sesamy\Capsule\Publisher\Exceptions\PublisherException;

/**
 * ECDSA P-256 (ES256) signing.
 *
 * openssl_sign() emits DER-encoded ECDSA signatures. JWT/ES256 requires the
 * fixed 64-byte IEEE P1363 form (r || s, each 32 bytes, big-endian, zero-padded).
 * This class converts between the two so the produced JWT round-trips with
 * any standards-compliant ES256 verifier (including WebCrypto).
 */
final class EcdsaP256
{
    private const COORD_LEN = 32;

    /**
     * Sign $data with $privateKeyPem and return a 64-byte IEEE P1363 signature.
     */
    public static function sign(string $data, string $privateKeyPem): string
    {
        $key = openssl_pkey_get_private($privateKeyPem);
        if ($key === false) {
            throw new \InvalidArgumentException('Invalid ECDSA private key PEM');
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
            throw new \InvalidArgumentException('Key is not EC');
        }
        if (($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            throw new \InvalidArgumentException('ES256 requires P-256 (prime256v1)');
        }

        $derSignature = '';
        if (!openssl_sign($data, $derSignature, $key, OPENSSL_ALGO_SHA256)) {
            throw new PublisherException('openssl_sign failed');
        }
        return self::derToP1363($derSignature);
    }

    /**
     * Convert a DER-encoded ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }`
     * into the 64-byte IEEE P1363 / JOSE form `r || s`.
     */
    public static function derToP1363(string $der): string
    {
        $offset = 0;
        if (self::readByte($der, $offset) !== 0x30) {
            throw new \InvalidArgumentException('DER signature: expected SEQUENCE');
        }
        // length (could be one or more bytes; for ECDSA P-256 it's always single short form)
        self::readLength($der, $offset);

        $r = self::readDerInteger($der, $offset);
        $s = self::readDerInteger($der, $offset);

        return self::leftPad($r, self::COORD_LEN) . self::leftPad($s, self::COORD_LEN);
    }

    /**
     * Convert a 64-byte IEEE P1363 signature back into DER.
     * Provided for tests / verification against fixtures from other languages.
     */
    public static function p1363ToDer(string $sig): string
    {
        if (strlen($sig) !== 2 * self::COORD_LEN) {
            throw new \InvalidArgumentException('P1363 signature must be 64 bytes');
        }
        $r = substr($sig, 0, self::COORD_LEN);
        $s = substr($sig, self::COORD_LEN);

        $rDer = self::encodeDerInteger($r);
        $sDer = self::encodeDerInteger($s);
        $body = $rDer . $sDer;

        return "\x30" . self::encodeLength(strlen($body)) . $body;
    }

    private static function readDerInteger(string $der, int &$offset): string
    {
        if (self::readByte($der, $offset) !== 0x02) {
            throw new \InvalidArgumentException('DER signature: expected INTEGER tag');
        }
        $len = self::readLength($der, $offset);
        $bytes = substr($der, $offset, $len);
        if (strlen($bytes) !== $len) {
            throw new \InvalidArgumentException('DER signature: truncated INTEGER');
        }
        $offset += $len;

        // Strip a single leading 0x00 byte that DER prepends to keep the value positive.
        if (strlen($bytes) > 1 && $bytes[0] === "\x00") {
            $bytes = substr($bytes, 1);
        }
        if (strlen($bytes) > self::COORD_LEN) {
            throw new \InvalidArgumentException('DER INTEGER longer than 32 bytes for P-256');
        }
        return $bytes;
    }

    private static function encodeDerInteger(string $coord): string
    {
        // Strip leading zero bytes...
        $value = ltrim($coord, "\x00");
        if ($value === '') {
            $value = "\x00";
        }
        // ...then prepend a single 0x00 if the high bit would otherwise mark it negative.
        if ((ord($value[0]) & 0x80) !== 0) {
            $value = "\x00" . $value;
        }
        return "\x02" . self::encodeLength(strlen($value)) . $value;
    }

    private static function readByte(string $buf, int &$offset): int
    {
        if ($offset >= strlen($buf)) {
            throw new \InvalidArgumentException('DER signature: unexpected end');
        }
        return ord($buf[$offset++]);
    }

    private static function readLength(string $buf, int &$offset): int
    {
        $first = self::readByte($buf, $offset);
        if (($first & 0x80) === 0) {
            return $first;
        }
        $n = $first & 0x7F;
        if ($n === 0 || $n > 4) {
            throw new \InvalidArgumentException('DER signature: unsupported length form');
        }
        $len = 0;
        for ($i = 0; $i < $n; $i++) {
            $len = ($len << 8) | self::readByte($buf, $offset);
        }
        return $len;
    }

    private static function encodeLength(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $out = '';
        while ($len > 0) {
            $out = chr($len & 0xFF) . $out;
            $len >>= 8;
        }
        return chr(0x80 | strlen($out)) . $out;
    }

    private static function leftPad(string $bytes, int $length): string
    {
        if (strlen($bytes) === $length) {
            return $bytes;
        }
        if (strlen($bytes) > $length) {
            throw new \InvalidArgumentException('value longer than target length');
        }
        return str_repeat("\x00", $length - strlen($bytes)) . $bytes;
    }
}
