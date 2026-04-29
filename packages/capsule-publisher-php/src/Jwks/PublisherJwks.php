<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Jwks;

use Sesamy\Capsule\Publisher\Crypto\Encoding;
use Sesamy\Capsule\Publisher\Exceptions\PublisherException;

/**
 * Build the JWKS document a publisher serves at /.well-known/dca-publishers.json
 * so JWKS-configured issuers can resolve the publisher's ES256 signing key.
 *
 * Mirrors packages/capsule-server/src/dca-publisher-jwks.ts.
 */
final class PublisherJwks
{
    /**
     * Produce a single JWK for a publisher signing key.
     *
     * @return array<string,mixed>
     */
    public static function buildPublisherJwk(string $publicKeyPem, string $kid, ?string $status = null): array
    {
        if ($publicKeyPem === '') {
            throw new \InvalidArgumentException('publicKeyPem must be non-empty');
        }
        if ($kid === '') {
            throw new \InvalidArgumentException('kid must be non-empty');
        }

        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            throw new \InvalidArgumentException('Failed to import publisher signing public key');
        }
        $details = openssl_pkey_get_details($key);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
            throw new \InvalidArgumentException('Publisher signing key must be EC');
        }
        if (($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            throw new \InvalidArgumentException('Publisher signing key must be on P-256');
        }

        $x = self::normalizeCoordinate($details['ec']['x'] ?? null, 'x');
        $y = self::normalizeCoordinate($details['ec']['y'] ?? null, 'y');

        $jwk = [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => Encoding::toBase64Url($x),
            'y' => Encoding::toBase64Url($y),
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'ES256',
        ];
        if ($status === 'retired') {
            $jwk['status'] = 'retired';
        }
        return $jwk;
    }

    /**
     * Build a JWKS document (RFC 7517) wrapping one or more publisher signing keys.
     *
     * @param list<array{publicKeyPem:string, kid:string, status?:string}> $keys
     * @return array{keys: list<array<string,mixed>>}
     */
    public static function buildPublisherJwksDocument(array $keys): array
    {
        if ($keys === []) {
            throw new \InvalidArgumentException('keys must be a non-empty array');
        }
        $seen = [];
        $built = [];
        foreach ($keys as $entry) {
            $kid = $entry['kid'] ?? null;
            $pem = $entry['publicKeyPem'] ?? null;
            if (!is_string($kid) || !is_string($pem)) {
                throw new \InvalidArgumentException('Each entry needs publicKeyPem + kid strings');
            }
            if (isset($seen[$kid])) {
                throw new PublisherException("buildPublisherJwksDocument: duplicate kid \"$kid\"");
            }
            $seen[$kid] = true;
            $built[] = self::buildPublisherJwk($pem, $kid, $entry['status'] ?? null);
        }
        return ['keys' => $built];
    }

    private static function normalizeCoordinate(mixed $coord, string $name): string
    {
        if (!is_string($coord) || $coord === '') {
            throw new \InvalidArgumentException("EC coordinate '$name' is missing or empty");
        }
        if (strlen($coord) > 32) {
            throw new \InvalidArgumentException("EC coordinate '$name' exceeds 32 bytes for P-256");
        }
        if (strlen($coord) === 32) {
            return $coord;
        }
        return str_repeat("\x00", 32 - strlen($coord)) . $coord;
    }
}
