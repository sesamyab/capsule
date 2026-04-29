<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Tests;

use PHPUnit\Framework\TestCase;
use Sesamy\Capsule\Publisher\Crypto\Encoding;
use Sesamy\Capsule\Publisher\Jwks\PublisherJwks;

final class PublisherJwksTest extends TestCase
{
    public function testBuildPublisherJwkProducesExpectedShape(): void
    {
        $kp = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($kp);
        $publicPem = openssl_pkey_get_details($kp)['key'];

        $jwk = PublisherJwks::buildPublisherJwk($publicPem, 'k1');
        self::assertSame(['kty', 'crv', 'x', 'y', 'kid', 'use', 'alg'], array_keys($jwk));
        self::assertSame('EC', $jwk['kty']);
        self::assertSame('P-256', $jwk['crv']);
        self::assertSame('k1', $jwk['kid']);
        self::assertSame('sig', $jwk['use']);
        self::assertSame('ES256', $jwk['alg']);
        // x and y must be 32-byte coordinates → 43-char base64url (no padding).
        self::assertSame(43, strlen($jwk['x']));
        self::assertSame(43, strlen($jwk['y']));
        self::assertSame(32, strlen(Encoding::fromBase64Url($jwk['x'])));
        self::assertSame(32, strlen(Encoding::fromBase64Url($jwk['y'])));
    }

    public function testBuildPublisherJwksDocumentRejectsDuplicateKid(): void
    {
        $kp = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $pem = openssl_pkey_get_details($kp)['key'];

        $this->expectException(\RuntimeException::class);
        PublisherJwks::buildPublisherJwksDocument([
            ['publicKeyPem' => $pem, 'kid' => 'k1'],
            ['publicKeyPem' => $pem, 'kid' => 'k1'],
        ]);
    }

    public function testRetiredStatusSurfacesOnJwk(): void
    {
        $kp = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $pem = openssl_pkey_get_details($kp)['key'];

        $jwk = PublisherJwks::buildPublisherJwk($pem, 'old', 'retired');
        self::assertSame('retired', $jwk['status']);
    }
}
