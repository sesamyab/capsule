<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Sesamy\Capsule\Publisher\Crypto\Hkdf;
use Sesamy\Capsule\Publisher\Dca\Rotation;
use Sesamy\Capsule\Publisher\Dca\Wrap;
use Sesamy\Capsule\Publisher\Jwks\PublisherJwks;

/**
 * Pinned, never-regenerate cross-language interop vectors.
 *
 * Unlike InteropFixturesTest (which loads fixtures regenerated on every
 * `composer test:interop` run), these vectors live in tests/fixtures/static/
 * and are committed once. They catch lockstep refactors of the PHP and JS
 * implementations — if both sides are simultaneously broken in the same
 * direction, the dynamic round-trip would still pass; this test wouldn't.
 *
 * Regenerate intentionally with:
 *
 *     rm packages/capsule-publisher-php/tests/fixtures/static/*.json
 *     pnpm --filter @sesamy/capsule-server build
 *     node packages/capsule-server/scripts/generate-static-fixtures.mjs
 */
final class StaticFixturesTest extends TestCase
{
    private const FIXTURE_DIR = __DIR__ . '/fixtures/static';

    /**
     * @return array<string, array{0: array<string,mixed>}>
     */
    public static function hkdfVectors(): array
    {
        return self::loadList('hkdf-vectors.json');
    }

    /**
     * @return array<string, array{0: array<string,mixed>}>
     */
    public static function deriveWrapKeyVectors(): array
    {
        return self::loadList('derive-wrap-key-vectors.json');
    }

    #[DataProvider('hkdfVectors')]
    public function testStaticHkdfVector(array $v): void
    {
        $okm = Hkdf::sha256(hex2bin($v['ikmHex']), $v['salt'], $v['info'], (int) $v['length']);
        self::assertSame($v['okmHex'], bin2hex($okm));
    }

    #[DataProvider('deriveWrapKeyVectors')]
    public function testStaticDeriveWrapKeyVector(array $v): void
    {
        $wk = Rotation::deriveWrapKey(hex2bin($v['rotationSecretHex']), $v['scope'], $v['kid']);
        self::assertSame($v['wrapKeyHex'], bin2hex($wk));
    }

    public function testStaticPublisherJwk(): void
    {
        $f = self::loadJson('publisher-jwk-vector.json');
        $jwk = PublisherJwks::buildPublisherJwk($f['inputPublicKeyPem'], $f['inputKid']);
        self::assertSame($f['expectedJwk'], $jwk);
    }

    public function testStaticEcdhUnwrap(): void
    {
        $f = self::loadJson('ecdh-unwrap-vector.json');
        $plaintext = Wrap::unwrapEcdhP256(
            $f['wrappedBlob'],
            $f['issuerPrivateKeyPem'],
            $f['aad'],
        );
        self::assertSame($f['expectedPlaintextHex'], bin2hex($plaintext));
    }

    public function testStaticRsaUnwrap(): void
    {
        $f = self::loadJson('rsa-unwrap-vector.json');
        $plaintext = Wrap::unwrapRsaOaep(
            $f['wrappedBlob'],
            $f['issuerPrivateKeyPem'],
            $f['aad'],
        );
        self::assertSame($f['expectedPlaintextHex'], bin2hex($plaintext));
    }

    /**
     * @return array<string, array{0: array<string,mixed>}>
     */
    private static function loadList(string $filename): array
    {
        $list = self::loadJson($filename);
        if (!is_array($list)) {
            throw new \RuntimeException("Static fixture $filename is not a list");
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
            self::fail(
                "Static fixture $filename missing — generate once with " .
                "`node packages/capsule-server/scripts/generate-static-fixtures.mjs`",
            );
        }
        $body = file_get_contents($path);
        if ($body === false) {
            self::fail("Failed to read static fixture $filename");
        }
        $decoded = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            self::fail("Static fixture $filename did not decode to an array");
        }
        return $decoded;
    }
}
