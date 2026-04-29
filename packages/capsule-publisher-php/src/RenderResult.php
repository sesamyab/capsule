<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher;

/**
 * Result of one render. The manifest is the canonical wire format; the
 * `manifestScript` is the same JSON wrapped in a `<script>` tag for HTML
 * embedding.
 */
final class RenderResult
{
    /**
     * @param array<string,mixed> $manifest
     */
    public function __construct(
        public readonly array $manifest,
        public readonly string $manifestScript,
    ) {
    }

    public function jsonString(): string
    {
        $json = json_encode($this->manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new \RuntimeException('Failed to JSON-encode manifest: ' . json_last_error_msg());
        }
        return $json;
    }
}
