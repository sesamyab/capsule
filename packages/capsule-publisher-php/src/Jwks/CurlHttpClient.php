<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Jwks;

use Sesamy\Capsule\Publisher\Exceptions\PublisherException;

/**
 * Default HttpClient using ext-curl. Returns response headers as a
 * lowercase-keyed associative array (last value wins on duplicates).
 */
final class CurlHttpClient implements HttpClient
{
    public function get(string $url, array $headers = [], int $timeoutMs = 5000): array
    {
        if (!function_exists('curl_init')) {
            throw new PublisherException('CurlHttpClient requires the curl extension');
        }

        $ch = curl_init($url);
        if ($ch === false) {
            throw new PublisherException("curl_init failed for $url");
        }

        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        $responseHeaders = [];
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_TIMEOUT_MS => $timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => $timeoutMs,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_HEADERFUNCTION => function ($_ch, string $line) use (&$responseHeaders): int {
                $colon = strpos($line, ':');
                if ($colon !== false) {
                    $name = strtolower(trim(substr($line, 0, $colon)));
                    $value = trim(substr($line, $colon + 1));
                    $responseHeaders[$name] = $value;
                }
                return strlen($line);
            },
        ]);

        $body = curl_exec($ch);
        if ($body === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new PublisherException("HTTP GET $url failed: $err");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return [
            'status' => $status,
            'body' => (string) $body,
            'headers' => $responseHeaders,
        ];
    }
}
