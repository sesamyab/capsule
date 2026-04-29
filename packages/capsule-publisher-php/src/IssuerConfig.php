<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher;

use Sesamy\Capsule\Publisher\Dca\Wrap;

/**
 * Per-issuer config for one render. Mirrors `DcaIssuerConfig`.
 *
 * Either `publicKeyPem` or `jwksUri` must be provided. Either `contentNames`
 * or `scopes` must be set; `scopes` takes precedence when both are given.
 */
final class IssuerConfig
{
    /**
     * @param list<string>|null $contentNames
     * @param list<string>|null $scopes
     */
    public function __construct(
        public readonly string $issuerName,
        public readonly string $unlockUrl,
        public readonly ?string $publicKeyPem = null,
        public readonly ?string $jwksUri = null,
        public readonly ?string $algorithm = null,
        public readonly ?string $keyId = null,
        public readonly ?array $contentNames = null,
        public readonly ?array $scopes = null,
    ) {
        $hasPem = $publicKeyPem !== null && $publicKeyPem !== '';
        $hasJwks = $jwksUri !== null && $jwksUri !== '';
        if ($hasPem && $hasJwks) {
            throw new \InvalidArgumentException("Issuer \"$issuerName\": publicKeyPem and jwksUri are mutually exclusive");
        }
        if (!$hasPem && !$hasJwks) {
            throw new \InvalidArgumentException("Issuer \"$issuerName\": must provide publicKeyPem or jwksUri");
        }
        if ($hasPem && ($keyId === null || $keyId === '')) {
            throw new \InvalidArgumentException("Issuer \"$issuerName\": keyId is required when publicKeyPem is used");
        }
        if ($algorithm !== null && $algorithm !== Wrap::ALG_ECDH_P256 && $algorithm !== Wrap::ALG_RSA_OAEP) {
            throw new \InvalidArgumentException("Issuer \"$issuerName\": unknown algorithm \"$algorithm\"");
        }
    }
}
