<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Tests;

use PHPUnit\Framework\TestCase;
use Sesamy\Capsule\Publisher\Crypto\EcdsaP256;
use Sesamy\Capsule\Publisher\Crypto\Encoding;
use Sesamy\Capsule\Publisher\Publisher;
use Sesamy\Capsule\Publisher\PublisherConfig;
use Sesamy\Capsule\Publisher\ShareLinkOptions;
use Sesamy\Capsule\Publisher\Tests\Helpers\Keys;

final class ShareLinkTokenTest extends TestCase
{
    public function testTokenSignsAndDecodesWithExpectedClaims(): void
    {
        $signing = Keys::generateEcdsaP256();
        $publisher = new Publisher(new PublisherConfig(
            domain: 'news.example.com',
            signingKeyPem: $signing['privatePem'],
            rotationSecret: base64_encode(random_bytes(32)),
            signingKeyId: 'k1',
        ));

        $jwt = $publisher->createShareLinkToken(new ShareLinkOptions(
            resourceId: 'article-9',
            contentNames: ['bodytext'],
            expiresIn: 3600,
            maxUses: 50,
            data: ['campaign' => 'spring'],
        ));

        [$headerB64, $payloadB64, $sigB64] = explode('.', $jwt);

        $header = json_decode(Encoding::fromBase64Url($headerB64), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('ES256', $header['alg']);
        self::assertSame('JWT', $header['typ']);
        self::assertSame('k1', $header['kid']);

        $payload = json_decode(Encoding::fromBase64Url($payloadB64), true, flags: JSON_THROW_ON_ERROR);
        self::assertSame('dca-share', $payload['type']);
        self::assertSame('news.example.com', $payload['domain']);
        self::assertSame('article-9', $payload['resourceId']);
        self::assertSame(['bodytext'], $payload['contentNames']);
        self::assertSame(50, $payload['maxUses']);
        self::assertSame(['campaign' => 'spring'], $payload['data']);
        self::assertGreaterThan(0, $payload['iat']);
        self::assertSame($payload['iat'] + 3600, $payload['exp']);
        self::assertSame(32, strlen($payload['jti']), 'jti is hex-encoded 16 bytes');

        // Verify the signature with stock openssl after converting P1363→DER.
        $signingInput = $headerB64 . '.' . $payloadB64;
        $der = EcdsaP256::p1363ToDer(Encoding::fromBase64Url($sigB64));
        self::assertSame(1, openssl_verify($signingInput, $der, $signing['publicPem'], OPENSSL_ALGO_SHA256));
    }
}
