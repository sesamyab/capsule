<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher;

/**
 * Options for creating a share link token. Mirrors `DcaShareLinkOptions`.
 *
 * Either `contentNames` or `scopes` (but not both) must be set.
 */
final class ShareLinkOptions
{
    /**
     * @param list<string>|null   $contentNames
     * @param list<string>|null   $scopes
     * @param array<string,mixed>|null $data publisher metadata
     */
    public function __construct(
        public readonly string $resourceId,
        public readonly ?array $contentNames = null,
        public readonly ?array $scopes = null,
        public readonly int $expiresIn = 7 * 24 * 3600,
        public readonly ?int $maxUses = null,
        public readonly ?string $jti = null,
        public readonly ?array $data = null,
    ) {
        if ($resourceId === '') {
            throw new \InvalidArgumentException('resourceId must be a non-empty string');
        }
        if ($expiresIn <= 0) {
            throw new \InvalidArgumentException('expiresIn must be > 0');
        }
        if ($maxUses !== null && $maxUses <= 0) {
            throw new \InvalidArgumentException('maxUses must be > 0');
        }
        $hasNames = $contentNames !== null && $contentNames !== [];
        $hasScopes = $scopes !== null && $scopes !== [];
        if (!$hasNames && !$hasScopes) {
            throw new \InvalidArgumentException('createShareLinkToken requires contentNames or scopes');
        }
        if ($hasNames && $hasScopes) {
            throw new \InvalidArgumentException('createShareLinkToken: contentNames and scopes are mutually exclusive');
        }
    }
}
