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
