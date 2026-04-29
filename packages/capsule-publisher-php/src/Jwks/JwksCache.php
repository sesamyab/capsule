<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Jwks;

/**
 * Pluggable cache backend for resolved JWKS documents.
 *
 * Mirrors `DcaJwksCache` in packages/capsule-server/src/dca-jwks.ts. Backends
 * store the value as a JSON-serialisable array verbatim and return it on get.
 *
 * Default in-process backend: {@see InMemoryJwksCache}. WordPress sites can
 * implement this against transients to share across requests.
 */
interface JwksCache
{
    /**
     * @return array{jwks: array{keys: array<int,array<string,mixed>>}, freshUntil: int, staleUntil: int}|null
     */
    public function get(string $key): ?array;

    /**
     * @param array{jwks: array{keys: array<int,array<string,mixed>>}, freshUntil: int, staleUntil: int} $entry
     */
    public function set(string $key, array $entry): void;

    public function delete(string $key): void;
}
