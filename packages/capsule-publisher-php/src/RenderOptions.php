<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher;

/**
 * Options for one render call. Mirrors `DcaRenderOptions`.
 */
final class RenderOptions
{
    /**
     * @param list<ContentItem>      $contentItems
     * @param list<IssuerConfig>     $issuers
     * @param array<string,mixed>    $resourceData publisher metadata embedded in resourceJWT.data
     */
    public function __construct(
        public readonly string $resourceId,
        public readonly array $contentItems,
        public readonly array $issuers,
        public readonly array $resourceData = [],
    ) {
        if ($contentItems === []) {
            throw new \InvalidArgumentException('At least one ContentItem is required');
        }
        if ($issuers === []) {
            throw new \InvalidArgumentException('At least one IssuerConfig is required');
        }
    }
}
