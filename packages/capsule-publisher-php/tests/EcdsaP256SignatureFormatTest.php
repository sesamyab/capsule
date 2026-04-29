<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Tests;

use PHPUnit\Framework\TestCase;
use Sesamy\Capsule\Publisher\Crypto\EcdsaP256;

final class EcdsaP256SignatureFormatTest extends TestCase
{
    public function testSignatureRoundTripsThroughOpenSsl(): void
    {
        $kp = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($kp);
        $details = openssl_pkey_get_details($kp);
        $publicPem = $details['key'];
        openssl_pkey_export($kp, $privatePem);

        $message = 'test message';
        $p1363 = EcdsaP256::sign($message, $privatePem);
        self::assertSame(64, strlen($p1363), 'P1363 sig must be exactly 64 bytes');

        // Convert P1363 → DER and verify with stock openssl.
        $der = EcdsaP256::p1363ToDer($p1363);
        $verify = openssl_verify($message, $der, $publicPem, OPENSSL_ALGO_SHA256);
        self::assertSame(1, $verify, 'openssl_verify must accept the DER-converted signature');
    }

    public function testDerToP1363RoundTrip(): void
    {
        // A well-formed DER ECDSA signature with high-bit r and s (forces a 0x00 prefix).
        $r = hex2bin('80112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
        $s = hex2bin('ff112233445566778899aabbccddeeff00112233445566778899aabbccddee01');
        $p1363 = $r . $s;

        $der = EcdsaP256::p1363ToDer($p1363);
        $back = EcdsaP256::derToP1363($der);
        self::assertSame(bin2hex($p1363), bin2hex($back));
    }

    public function testDerWithLeadingZeroIntegersConvertsCorrectly(): void
    {
        // Construct a P1363 with small r (lots of leading zeros) — the DER integer
        // form will be shorter than 32 bytes and must be left-padded back.
        $r = str_repeat("\x00", 30) . "\x12\x34";
        $s = str_repeat("\x00", 31) . "\xab";
        $p1363 = $r . $s;

        $der = EcdsaP256::p1363ToDer($p1363);
        $back = EcdsaP256::derToP1363($der);
        self::assertSame(bin2hex($p1363), bin2hex($back));
    }
}
