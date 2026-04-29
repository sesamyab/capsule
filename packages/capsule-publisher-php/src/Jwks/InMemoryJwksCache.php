<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Jwks;

final class InMemoryJwksCache implements JwksCache
{
    /** @var array<string, array{jwks: array{keys: array<int,array<string,mixed>>}, freshUntil: int, staleUntil: int}> */
    private array $store = [];

    public function get(string $key): ?array
    {
        return $this->store[$key] ?? null;
    }

    public function set(string $key, array $entry): void
    {
        $this->store[$key] = $entry;
    }

    public function delete(string $key): void
    {
        unset($this->store[$key]);
    }
}
