<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Tests;

use PHPUnit\Framework\TestCase;
use Sesamy\Capsule\Publisher\ContentItem;
use Sesamy\Capsule\Publisher\Crypto\Aes;
use Sesamy\Capsule\Publisher\Crypto\EcdsaP256;
use Sesamy\Capsule\Publisher\Crypto\Encoding;
use Sesamy\Capsule\Publisher\Dca\Wrap;
use Sesamy\Capsule\Publisher\IssuerConfig;
use Sesamy\Capsule\Publisher\Publisher;
use Sesamy\Capsule\Publisher\PublisherConfig;
use Sesamy\Capsule\Publisher\RenderOptions;
use Sesamy\Capsule\Publisher\Tests\Helpers\Keys;

/**
 * End-to-end PHP render: encrypt content → wrap for issuer → unwrap with the
 * issuer's private key → AES-decrypt the content.
 *
 * If this passes for both ECDH-P256 and RSA-OAEP, the publisher's wire output
 * is internally consistent. The JS-side interop test then covers cross-language
 * compatibility.
 */
final class PublisherRenderTest extends TestCase
{
    public function testEcdhP256RoundTrip(): void
    {
        $signing = Keys::generateEcdsaP256();
        $issuer = Keys::generateEcdhP256();

        $publisher = new Publisher(new PublisherConfig(
            domain: 'news.example.com',
            signingKeyPem: $signing['privatePem'],
            rotationSecret: base64_encode(random_bytes(32)),
            signingKeyId: 'sign-1',
        ));

        $plaintext = '<p>Premium body — ECDH path</p>';
        $result = $publisher->render(new RenderOptions(
            resourceId: 'article-ecdh',
            contentItems: [new ContentItem('bodytext', $plaintext, scope: 'premium')],
            issuers: [new IssuerConfig(
                issuerName: 'sesamy',
                unlockUrl: 'https://api.example.com/unlock',
                publicKeyPem: $issuer['publicPem'],
                keyId: 'iss-1',
                scopes: ['premium'],
            )],
            resourceData: ['title' => 'Hello'],
        ));

        $manifest = $result->manifest;
        self::assertSame('0.10', $manifest['version']);
        self::assertArrayHasKey('bodytext', $manifest['content']);
        self::assertSame('iss-1', $manifest['issuers']['sesamy']['keyId']);

        // Recover contentKey via the issuer's private key, scope-bound AAD = 'premium'.
        $issuerEntry = $manifest['issuers']['sesamy']['keys'][0];
        $contentKey = Wrap::unwrapEcdhP256(
            $issuerEntry['contentKey'],
            $issuer['privatePem'],
            'premium',
        );
        self::assertSame(32, strlen($contentKey));

        // AAD-bound content decryption.
        $contentEntry = $manifest['content']['bodytext'];
        $iv = Encoding::fromBase64Url($contentEntry['iv']);
        $ciphertext = Encoding::fromBase64Url($contentEntry['ciphertext']);
        $decrypted = Aes::gcmDecrypt($ciphertext, $contentKey, $iv, $contentEntry['aad']);
        self::assertSame($plaintext, $decrypted);

        // wrapKeys path also works (scopes mode includes them).
        self::assertCount(2, $issuerEntry['wrapKeys']);
        $wrapKey = Wrap::unwrapEcdhP256(
            $issuerEntry['wrapKeys'][0]['key'],
            $issuer['privatePem'],
            'premium',
        );
        self::assertSame(32, strlen($wrapKey));

        // Verify resourceJWT signature.
        [$h, $p, $s] = explode('.', $manifest['resourceJWT']);
        $der = EcdsaP256::p1363ToDer(Encoding::fromBase64Url($s));
        self::assertSame(1, openssl_verify("$h.$p", $der, $signing['publicPem'], OPENSSL_ALGO_SHA256));
    }

    public function testRsaOaepRoundTrip(): void
    {
        $signing = Keys::generateEcdsaP256();
        $issuer = Keys::generateRsa(2048);

        $publisher = new Publisher(new PublisherConfig(
            domain: 'news.example.com',
            signingKeyPem: $signing['privatePem'],
            rotationSecret: base64_encode(random_bytes(32)),
        ));

        $plaintext = '<p>Premium body — RSA path</p>';
        $result = $publisher->render(new RenderOptions(
            resourceId: 'article-rsa',
            contentItems: [new ContentItem('bodytext', $plaintext, scope: 'premium')],
            issuers: [new IssuerConfig(
                issuerName: 'sesamy',
                unlockUrl: 'https://api.example.com/unlock',
                publicKeyPem: $issuer['publicPem'],
                keyId: 'rsa-1',
                scopes: ['premium'],
            )],
        ));

        $manifest = $result->manifest;
        $issuerEntry = $manifest['issuers']['sesamy']['keys'][0];

        $contentKey = Wrap::unwrapRsaOaep(
            $issuerEntry['contentKey'],
            $issuer['privatePem'],
            'premium',
        );
        $contentEntry = $manifest['content']['bodytext'];
        $decrypted = Aes::gcmDecrypt(
            Encoding::fromBase64Url($contentEntry['ciphertext']),
            $contentKey,
            Encoding::fromBase64Url($contentEntry['iv']),
            $contentEntry['aad'],
        );
        self::assertSame($plaintext, $decrypted);
    }

    public function testNameGranularModeOmitsWrapKeys(): void
    {
        $signing = Keys::generateEcdsaP256();
        $issuer = Keys::generateEcdhP256();

        $publisher = new Publisher(new PublisherConfig(
            domain: 'news.example.com',
            signingKeyPem: $signing['privatePem'],
            rotationSecret: base64_encode(random_bytes(32)),
        ));

        $result = $publisher->render(new RenderOptions(
            resourceId: 'r-1',
            contentItems: [
                new ContentItem('bodytext', 'body', scope: 'premium'),
                new ContentItem('teaser', 'teaser', scope: 'premium'),
            ],
            issuers: [new IssuerConfig(
                issuerName: 'sesamy',
                unlockUrl: 'https://x',
                publicKeyPem: $issuer['publicPem'],
                keyId: 'k1',
                contentNames: ['bodytext'], // name-granular
            )],
        ));

        $entries = $result->manifest['issuers']['sesamy']['keys'];
        self::assertCount(1, $entries, 'only bodytext is wrapped');
        self::assertSame('bodytext', $entries[0]['contentName']);
        self::assertArrayNotHasKey('wrapKeys', $entries[0], 'name-granular mode must not leak scope wrapKeys');
    }

    public function testManifestScriptEscapesClosingTags(): void
    {
        $signing = Keys::generateEcdsaP256();
        $issuer = Keys::generateEcdhP256();
        $publisher = new Publisher(new PublisherConfig(
            domain: 'news.example.com',
            signingKeyPem: $signing['privatePem'],
            rotationSecret: base64_encode(random_bytes(32)),
        ));

        $result = $publisher->render(new RenderOptions(
            resourceId: 'r-1',
            contentItems: [new ContentItem('bodytext', 'a</script>b', scope: 'premium')],
            issuers: [new IssuerConfig(
                issuerName: 'sesamy',
                unlockUrl: 'https://x',
                publicKeyPem: $issuer['publicPem'],
                keyId: 'k1',
                scopes: ['premium'],
            )],
        ));

        // The literal "</" must not appear in the embedded JSON inside the
        // <script> tag (encrypted content can't bleed through, but defence-in-depth).
        self::assertStringContainsString('<script type="application/json" class="dca-manifest">', $result->manifestScript);
        self::assertStringEndsWith('</script>', $result->manifestScript);
        $inner = substr($result->manifestScript, strlen('<script type="application/json" class="dca-manifest">'), -strlen('</script>'));
        self::assertStringNotContainsString('</', $inner);
    }

    public function testVendorIdHelpersBuildHostedSesamyUrls(): void
    {
        $signing = Keys::generateEcdsaP256();
        $config = new PublisherConfig(
            domain: 'news.example.com',
            signingKeyPem: $signing['privatePem'],
            rotationSecret: base64_encode(random_bytes(32)),
            vendorId: 'ehandel',
        );

        self::assertSame('ehandel', $config->vendorId);
        self::assertSame(
            'https://api2.sesamy.com/capsule/vendors/ehandel/unlock',
            $config->sesamyUnlockUrl(),
        );
        self::assertSame(
            'https://api2.sesamy.com/capsule/vendors/ehandel/.well-known/jwks.json',
            $config->sesamyJwksUri(),
        );
    }

    public function testVendorIdOmittedReturnsNullHelpers(): void
    {
        $signing = Keys::generateEcdsaP256();
        $config = new PublisherConfig(
            domain: 'news.example.com',
            signingKeyPem: $signing['privatePem'],
            rotationSecret: base64_encode(random_bytes(32)),
        );

        self::assertNull($config->vendorId);
        self::assertNull($config->sesamyUnlockUrl());
        self::assertNull($config->sesamyJwksUri());
    }

    public function testVendorIdRejectsInvalidShape(): void
    {
        $signing = Keys::generateEcdsaP256();
        $this->expectException(\InvalidArgumentException::class);
        new PublisherConfig(
            domain: 'news.example.com',
            signingKeyPem: $signing['privatePem'],
            rotationSecret: base64_encode(random_bytes(32)),
            vendorId: 'EHandel/../etc',
        );
    }
}
