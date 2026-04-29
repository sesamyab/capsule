<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher;

/**
 * One content item to encrypt.
 *
 * Mirrors `DcaContentItem`. `scope` defaults to `contentName` when null.
 */
final class ContentItem
{
    public function __construct(
        public readonly string $contentName,
        public readonly string $content,
        public readonly ?string $scope = null,
        public readonly string $contentType = 'text/html',
    ) {
        if ($contentName === '') {
            throw new \InvalidArgumentException('contentName must be non-empty');
        }
    }

    public function effectiveScope(): string
    {
        return $this->scope ?? $this->contentName;
    }
}
