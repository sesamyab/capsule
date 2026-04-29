<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Jwks;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA\PublicKey as RsaPublicKey;
use Sesamy\Capsule\Publisher\Crypto\Encoding;
use Sesamy\Capsule\Publisher\Dca\Wrap;
use Sesamy\Capsule\Publisher\Exceptions\PublisherException;

/**
 * Fetch + cache + select active issuer encryption keys from a JWKS URL.
 *
 * Mirrors the publisher-side use of packages/capsule-server/src/dca-jwks.ts:
 *
 *   - Cache freshness driven by upstream `Cache-Control: max-age` (1 hour fallback).
 *   - On refresh failure, serve a cached entry within the stale-if-error window
 *     (default 30 days) before giving up.
 *   - Active key selection: kid present, status != "retired",
 *     `use` is "enc" or absent, EC-P256 with x+y or RSA with n+e.
 *
 * Returned keys are converted to PEM so {@see Wrap::wrap} can use them.
 */
final class IssuerJwksResolver
{
    private const FALLBACK_MAX_AGE_SECONDS = 3600;
    private const DEFAULT_STALE_WINDOW_SECONDS = 30 * 24 * 3600;
    private const DEFAULT_FETCH_TIMEOUT_MS = 5000;

    public function __construct(
        private readonly JwksCache $cache = new InMemoryJwksCache(),
        private readonly HttpClient $http = new CurlHttpClient(),
        private readonly int $staleWindowSeconds = self::DEFAULT_STALE_WINDOW_SECONDS,
        private readonly int $fetchTimeoutMs = self::DEFAULT_FETCH_TIMEOUT_MS,
    ) {
    }

    /**
     * Resolve the active issuer keys at $url, returning an array of:
     *   [ ['kid' => string, 'algorithm' => string, 'publicKeyPem' => string], ... ]
     *
     * @return list<array{kid:string, algorithm:string, publicKeyPem:string}>
     */
    public function getActiveIssuerKeys(string $url): array
    {
        $jwks = $this->fetchJwks($url);
        $active = self::selectActiveKeys($jwks);
        if ($active === []) {
            throw new PublisherException("JWKS at $url contains no usable active keys");
        }
        return array_map(self::importJwk(...), $active);
    }

    /**
     * @return array{keys: list<array<string,mixed>>}
     */
    public function fetchJwks(string $url): array
    {
        $now = (int) (microtime(true) * 1000);
        $cached = $this->cache->get($url);
        if ($cached !== null && ($cached['freshUntil'] ?? 0) > $now) {
            return $cached['jwks'];
        }
        return $this->refreshAndCache($url, $cached);
    }

    /**
     * Force a re-fetch even when the cache is fresh; still honors the stale
     * fallback. Useful when an unwrap error suggests the issuer rotated keys.
     */
    public function refreshJwks(string $url): array
    {
        $cached = $this->cache->get($url);
        return $this->refreshAndCache($url, $cached);
    }

    /**
     * @param array{jwks: array{keys: array<int,array<string,mixed>>}, freshUntil: int, staleUntil: int}|null $previouslyCached
     */
    private function refreshAndCache(string $url, ?array $previouslyCached): array
    {
        $now = (int) (microtime(true) * 1000);
        try {
            $fetched = $this->doFetchJwks($url);
            $freshUntil = $now + $fetched['maxAgeSeconds'] * 1000;
            $staleUntil = $freshUntil + $this->staleWindowSeconds * 1000;
            $entry = ['jwks' => $fetched['jwks'], 'freshUntil' => $freshUntil, 'staleUntil' => $staleUntil];
            $this->cache->set($url, $entry);
            return $fetched['jwks'];
        } catch (\Throwable $err) {
            if ($previouslyCached !== null && ($previouslyCached['staleUntil'] ?? 0) > $now) {
                trigger_error(
                    "JWKS fetch failed for $url; serving stale cached copy. Error: " . $err->getMessage(),
                    E_USER_WARNING,
                );
                return $previouslyCached['jwks'];
            }
            throw new PublisherException(
                "JWKS fetch failed for $url and no cached copy is available: " . $err->getMessage(),
                0,
                $err,
            );
        }
    }

    /**
     * @return array{jwks: array{keys: list<array<string,mixed>>}, maxAgeSeconds: int}
     */
    private function doFetchJwks(string $url): array
    {
        $response = $this->http->get($url, ['Accept' => 'application/json'], $this->fetchTimeoutMs);
        if ($response['status'] < 200 || $response['status'] >= 300) {
            throw new PublisherException("JWKS fetch failed for $url: HTTP {$response['status']}");
        }
        $body = json_decode($response['body'], true);
        if (!is_array($body) || !isset($body['keys']) || !is_array($body['keys'])) {
            throw new PublisherException("JWKS fetch failed for $url: response has no \"keys\" array");
        }
        $maxAge = self::parseMaxAge($response['headers']['cache-control'] ?? null) ?? self::FALLBACK_MAX_AGE_SECONDS;
        return ['jwks' => ['keys' => $body['keys']], 'maxAgeSeconds' => $maxAge];
    }

    private static function parseMaxAge(?string $cacheControl): ?int
    {
        if ($cacheControl === null) {
            return null;
        }
        if (!preg_match('/(?:^|[,\s])max-age\s*=\s*(\d+)/i', $cacheControl, $m)) {
            return null;
        }
        $n = (int) $m[1];
        return $n >= 0 ? $n : null;
    }

    /**
     * @param array{keys: array<int, array<string,mixed>>} $jwks
     * @return list<array<string,mixed>>
     */
    public static function selectActiveKeys(array $jwks): array
    {
        $out = [];
        foreach ($jwks['keys'] ?? [] as $k) {
            if (!is_array($k)) {
                continue;
            }
            if (!isset($k['kid']) || !is_string($k['kid']) || $k['kid'] === '') {
                continue;
            }
            if (($k['status'] ?? null) === 'retired') {
                continue;
            }
            if (isset($k['use']) && $k['use'] !== 'enc') {
                continue;
            }
            if (($k['kty'] ?? null) === 'EC') {
                if (($k['crv'] ?? null) !== 'P-256') {
                    continue;
                }
                if (!isset($k['x'], $k['y']) || !is_string($k['x']) || !is_string($k['y'])) {
                    continue;
                }
                $out[] = $k;
                continue;
            }
            if (($k['kty'] ?? null) === 'RSA') {
                if (!isset($k['n'], $k['e']) || !is_string($k['n']) || !is_string($k['e'])) {
                    continue;
                }
                $out[] = $k;
                continue;
            }
        }
        return $out;
    }

    /**
     * @param array<string,mixed> $jwk
     * @return array{kid:string, algorithm:string, publicKeyPem:string}
     */
    private static function importJwk(array $jwk): array
    {
        $kid = (string) $jwk['kid'];
        $kty = $jwk['kty'] ?? null;

        if ($kty === 'EC' && ($jwk['crv'] ?? null) === 'P-256') {
            $x = self::leftPad32(Encoding::fromBase64Url((string) $jwk['x']));
            $y = self::leftPad32(Encoding::fromBase64Url((string) $jwk['y']));
            $raw = "\x04" . $x . $y;
            $pem = self::ecP256RawToPem($raw);
            return ['kid' => $kid, 'algorithm' => Wrap::ALG_ECDH_P256, 'publicKeyPem' => $pem];
        }

        if ($kty === 'RSA') {
            // phpseclib3 accepts JWK natively via PublicKeyLoader.
            $key = PublicKeyLoader::load($jwk);
            if (!$key instanceof RsaPublicKey) {
                throw new PublisherException("JWK with kty=RSA did not load as an RSA public key (kid=$kid)");
            }
            $pem = (string) $key->toString('PKCS8');
            return ['kid' => $kid, 'algorithm' => Wrap::ALG_RSA_OAEP, 'publicKeyPem' => $pem];
        }

        throw new PublisherException("Unsupported JWK kty=" . var_export($kty, true) . " for kid=$kid");
    }

    private static function ecP256RawToPem(string $rawUncompressed): string
    {
        if (strlen($rawUncompressed) !== 65 || $rawUncompressed[0] !== "\x04") {
            throw new \InvalidArgumentException('raw EC point must be 65 bytes starting with 0x04');
        }
        $spkiHeader = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200');
        $der = $spkiHeader . $rawUncompressed;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function leftPad32(string $bytes): string
    {
        if (strlen($bytes) >= 32) {
            return $bytes;
        }
        return str_repeat("\x00", 32 - strlen($bytes)) . $bytes;
    }
}
