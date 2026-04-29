<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Jwks;

/**
 * Minimal HTTP GET interface for JWKS fetches.
 *
 * Kept tiny so consumers (e.g. WordPress plugins using wp_remote_get) can
 * implement it without dragging in PSR-18 / Guzzle. Default implementation:
 * {@see CurlHttpClient}.
 *
 * @return array{status:int, body:string, headers:array<string,string>}
 */
interface HttpClient
{
    /**
     * @param array<string,string> $headers
     * @return array{status:int, body:string, headers:array<string,string>}
     */
    public function get(string $url, array $headers = [], int $timeoutMs = 5000): array;
}
