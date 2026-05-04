<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Sesamy\Capsule\Publisher\Crypto\Aes;
use Sesamy\Capsule\Publisher\Crypto\Encoding;
use Sesamy\Capsule\Publisher\Crypto\Hkdf;
use Sesamy\Capsule\Publisher\Dca\Rotation;
use Sesamy\Capsule\Publisher\Dca\Wrap;
use Sesamy\Capsule\Publisher\Jwks\PublisherJwks;

/**
 * Interop fixtures from the JS publisher.
 *
 * These tests fail loudly if the PHP primitives drift from the JS wire format.
 * Re-emit fixtures with:
 *
 *     node packages/capsule-server/scripts/emit-php-test-vectors.mjs
 */
final class InteropFixturesTest extends TestCase
{
    private const FIXTURE_DIR = __DIR__ . '/fixtures';

    /**
     * @return array<string, array{0: array<string,mixed>}>
     */
    public static function hkdfVectors(): array
    {
        return self::loadList('hkdf.json');
    }

    /**
     * @return array<string, array{0: array<string,mixed>}>
     */
    public static function deriveWrapKeyVectors(): array
    {
        return self::loadList('derive-wrap-key.json');
    }

    #[DataProvider('hkdfVectors')]
    public function testHkdfVector(array $v): void
    {
        $okm = Hkdf::sha256(hex2bin($v['ikmHex']), $v['salt'], $v['info'], (int) $v['length']);
        self::assertSame($v['okmHex'], bin2hex($okm));
    }

    #[DataProvider('deriveWrapKeyVectors')]
    public function testDeriveWrapKeyVector(array $v): void
    {
        $wk = Rotation::deriveWrapKey(hex2bin($v['rotationSecretHex']), $v['scope'], $v['kid']);
        self::assertSame($v['wrapKeyHex'], bin2hex($wk));
    }

    public function testPublisherJwkMatches(): void
    {
        $f = self::loadJson('publisher-jwk.json');
        $jwk = PublisherJwks::buildPublisherJwk($f['inputPublicKeyPem'], $f['inputKid']);
        self::assertSame($f['expectedJwk'], $jwk);
    }

    public function testJsRenderedEcdhManifestUnwrapsInPhp(): void
    {
        $keys = self::loadJson('keys.json');
        $f = self::loadJson('js-rendered-manifest-ecdh.json');

        $entry = $f['manifest']['issuers'][$f['issuerName']]['keys'][0];
        $contentEntry = $f['manifest']['content']['bodytext'];

        $contentKey = Wrap::unwrapEcdhP256(
            $entry['contentKey'],
            $keys['ecdhIssuerPrivateKeyPem'],
            $entry['scope'],
        );
        $plaintext = Aes::gcmDecrypt(
            Encoding::fromBase64Url($contentEntry['ciphertext']),
            $contentKey,
            Encoding::fromBase64Url($contentEntry['iv']),
            $contentEntry['aad'],
        );
        self::assertSame($f['plaintext'], $plaintext);
    }

    public function testJsRenderedRsaManifestUnwrapsInPhp(): void
    {
        $keys = self::loadJson('keys.json');
        $f = self::loadJson('js-rendered-manifest-rsa.json');

        $entry = $f['manifest']['issuers'][$f['issuerName']]['keys'][0];
        $contentEntry = $f['manifest']['content']['bodytext'];

        $contentKey = Wrap::unwrapRsaOaep(
            $entry['contentKey'],
            $keys['rsaIssuerPrivateKeyPem'],
            $entry['scope'],
        );
        $plaintext = Aes::gcmDecrypt(
            Encoding::fromBase64Url($contentEntry['ciphertext']),
            $contentKey,
            Encoding::fromBase64Url($contentEntry['iv']),
            $contentEntry['aad'],
        );
        self::assertSame($f['plaintext'], $plaintext);
    }

    public function testJsRenderedShareTokensVerifyInPhp(): void
    {
        $f = self::loadJson('js-rendered-share-tokens.json');

        $tokenWithNames = $f['tokens']['contentNames'];
        $this->assertShareTokenSignsAndDecodes(
            $tokenWithNames,
            $f['domain'],
            $f['resourceId'],
            $f['signingKid'],
            $f['publisherSigningPublicKeyPem'],
        );
        [, $payload] = self::decodeJwt($tokenWithNames);
        self::assertSame(['bodytext'], $payload['contentNames']);
        self::assertSame(5, $payload['maxUses']);
        self::assertSame(['campaign' => 'spring'], $payload['data']);
        self::assertSame($payload['iat'] + 3600, $payload['exp']);
        self::assertArrayNotHasKey('scopes', $payload);

        $tokenWithScopes = $f['tokens']['scopes'];
        $this->assertShareTokenSignsAndDecodes(
            $tokenWithScopes,
            $f['domain'],
            $f['resourceId'],
            $f['signingKid'],
            $f['publisherSigningPublicKeyPem'],
        );
        [, $scopesPayload] = self::decodeJwt($tokenWithScopes);
        self::assertSame(['premium'], $scopesPayload['scopes']);
        self::assertSame($scopesPayload['iat'] + 7200, $scopesPayload['exp']);
        // JS emitter always carries `contentNames` (empty when scopes are used).
        self::assertSame([], $scopesPayload['contentNames']);
    }

    public function testJsRenderedRichManifestUnwrapsInPhp(): void
    {
        $f = self::loadJson('js-rendered-manifest-rich.json');

        // resourceData passthrough — appears verbatim in the resourceJWT payload.
        $resourcePayload = json_decode(
            Encoding::fromBase64Url(explode('.', $f['manifest']['resourceJWT'])[1]),
            true,
            flags: JSON_THROW_ON_ERROR,
        );
        self::assertSame($f['expectedResourceData'], $resourcePayload['data']);

        // Primary issuer (scope mode): wraps both content items, includes wrapKeys.
        $primary = $f['manifest']['issuers'][$f['primary']['issuerName']];
        self::assertCount(2, $primary['keys'], 'scope mode wraps both content items under one issuer');
        $primaryEntries = array_values(array_filter(
            $primary['keys'],
            static fn (array $e): bool => ($e['contentName'] ?? null) === 'bodytext',
        ));
        self::assertNotEmpty($primaryEntries);
        $primaryEntry = $primaryEntries[0];
        self::assertArrayHasKey('wrapKeys', $primaryEntry, 'scope mode must emit wrapKeys');
        self::assertCount(2, $primaryEntry['wrapKeys'], 'current + next kid');

        $primaryContentKey = Wrap::unwrapEcdhP256(
            $primaryEntry['contentKey'],
            $f['primary']['privateKeyPem'],
            $primaryEntry['scope'],
        );
        $bodyEntry = $f['manifest']['content']['bodytext'];
        $bodyPlaintext = Aes::gcmDecrypt(
            Encoding::fromBase64Url($bodyEntry['ciphertext']),
            $primaryContentKey,
            Encoding::fromBase64Url($bodyEntry['iv']),
            $bodyEntry['aad'],
        );
        self::assertSame($f['plaintext'], $bodyPlaintext);

        // The other primary key wraps the sidebar content — unwrap and decrypt
        // it to confirm both name-bound contentKeys round-trip, not just bodytext.
        $sidebarEntries = array_values(array_filter(
            $primary['keys'],
            static fn (array $e): bool => ($e['contentName'] ?? null) !== 'bodytext',
        ));
        self::assertNotEmpty($sidebarEntries);
        $sidebarPrimaryEntry = $sidebarEntries[0];
        $sidebarName = $sidebarPrimaryEntry['contentName'];
        $sidebarContentKey = Wrap::unwrapEcdhP256(
            $sidebarPrimaryEntry['contentKey'],
            $f['primary']['privateKeyPem'],
            $sidebarPrimaryEntry['scope'],
        );
        $sidebarManifestEntry = $f['manifest']['content'][$sidebarName];
        $sidebarPlaintext = Aes::gcmDecrypt(
            Encoding::fromBase64Url($sidebarManifestEntry['ciphertext']),
            $sidebarContentKey,
            Encoding::fromBase64Url($sidebarManifestEntry['iv']),
            $sidebarManifestEntry['aad'],
        );
        self::assertSame($f['sidebarPlaintext'], $sidebarPlaintext);

        // The wrapKey from the manifest unwraps the wrappedContentKey for the
        // matching kid — exercises the cache-friendly client path.
        $wk = Wrap::unwrapEcdhP256(
            $primaryEntry['wrapKeys'][0]['key'],
            $f['primary']['privateKeyPem'],
            $primaryEntry['scope'],
        );
        $matchKid = $primaryEntry['wrapKeys'][0]['kid'];
        $wrapped = null;
        foreach ($bodyEntry['wrappedContentKey'] as $wc) {
            if ($wc['kid'] === $matchKid) {
                $wrapped = $wc;
                break;
            }
        }
        self::assertNotNull($wrapped, "wrappedContentKey for kid $matchKid");
        $contentKeyFromWrap = Aes::gcmDecrypt(
            Encoding::fromBase64Url($wrapped['ciphertext']),
            $wk,
            Encoding::fromBase64Url($wrapped['iv']),
        );
        self::assertSame(bin2hex($primaryContentKey), bin2hex($contentKeyFromWrap));

        // Secondary issuer (name-granular): only bodytext, no wrapKeys.
        $secondary = $f['manifest']['issuers'][$f['secondary']['issuerName']];
        self::assertCount(1, $secondary['keys'], 'name-granular: only the requested contentName');
        $secEntry = $secondary['keys'][0];
        self::assertSame('bodytext', $secEntry['contentName']);
        self::assertArrayNotHasKey('wrapKeys', $secEntry, 'name-granular must not leak wrapKeys');

        $secondaryContentKey = Wrap::unwrapEcdhP256(
            $secEntry['contentKey'],
            $f['secondary']['privateKeyPem'],
            $secEntry['scope'],
        );
        $secPlaintext = Aes::gcmDecrypt(
            Encoding::fromBase64Url($bodyEntry['ciphertext']),
            $secondaryContentKey,
            Encoding::fromBase64Url($bodyEntry['iv']),
            $bodyEntry['aad'],
        );
        self::assertSame($f['plaintext'], $secPlaintext);
    }

    /**
     * Verify a JS-emitted ES256 share token round-trips through the PHP side:
     * header + claims have the right shape, signature verifies under the
     * publisher's public key.
     */
    private function assertShareTokenSignsAndDecodes(
        string $jwt,
        string $expectedDomain,
        string $expectedResourceId,
        string $expectedKid,
        string $publisherPublicKeyPem,
    ): void {
        [$header, $payload, $headerB64, $payloadB64, $sigB64] = self::decodeJwtFull($jwt);

        self::assertSame('ES256', $header['alg']);
        self::assertSame('JWT', $header['typ']);
        self::assertSame($expectedKid, $header['kid']);

        self::assertSame('dca-share', $payload['type']);
        self::assertSame($expectedDomain, $payload['domain']);
        self::assertSame($expectedResourceId, $payload['resourceId']);
        self::assertGreaterThan(0, $payload['iat']);
        self::assertGreaterThan($payload['iat'], $payload['exp']);
        self::assertArrayHasKey('jti', $payload);

        $der = \Sesamy\Capsule\Publisher\Crypto\EcdsaP256::p1363ToDer(
            \Sesamy\Capsule\Publisher\Crypto\Encoding::fromBase64Url($sigB64),
        );
        self::assertSame(
            1,
            openssl_verify(
                $headerB64 . '.' . $payloadB64,
                $der,
                $publisherPublicKeyPem,
                OPENSSL_ALGO_SHA256,
            ),
            'JS-emitted share token must verify under the publisher public key',
        );
    }

    /**
     * @return array{0: array<string,mixed>, 1: array<string,mixed>}
     */
    private static function decodeJwt(string $jwt): array
    {
        [$header, $payload] = self::decodeJwtFull($jwt);
        return [$header, $payload];
    }

    /**
     * @return array{0: array<string,mixed>, 1: array<string,mixed>, 2: string, 3: string, 4: string}
     */
    private static function decodeJwtFull(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new \RuntimeException('share token is not a 3-part JWT');
        }
        [$headerB64, $payloadB64, $sigB64] = $parts;
        $header = json_decode(
            \Sesamy\Capsule\Publisher\Crypto\Encoding::fromBase64Url($headerB64),
            true,
            flags: JSON_THROW_ON_ERROR,
        );
        $payload = json_decode(
            \Sesamy\Capsule\Publisher\Crypto\Encoding::fromBase64Url($payloadB64),
            true,
            flags: JSON_THROW_ON_ERROR,
        );
        return [$header, $payload, $headerB64, $payloadB64, $sigB64];
    }

    /**
     * @return array<string, array{0: array<string,mixed>}>
     */
    private static function loadList(string $filename): array
    {
        $list = self::loadJson($filename);
        if (!is_array($list)) {
            throw new \RuntimeException("Fixture $filename is not a list");
        }
        $cases = [];
        foreach ($list as $i => $entry) {
            $cases["$filename#$i"] = [$entry];
        }
        return $cases;
    }

    private static function loadJson(string $filename): array
    {
        $path = self::FIXTURE_DIR . '/' . $filename;
        if (!file_exists($path)) {
            self::fail("Fixture $filename missing — run `node packages/capsule-server/scripts/emit-php-test-vectors.mjs`");
        }
        $body = file_get_contents($path);
        if ($body === false) {
            self::fail("Failed to read fixture $filename");
        }
        $decoded = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            self::fail("Fixture $filename did not decode to an array");
        }
        return $decoded;
    }
}
