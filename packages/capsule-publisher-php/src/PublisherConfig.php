<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher;

use Sesamy\Capsule\Publisher\Crypto\Encoding;
use Sesamy\Capsule\Publisher\Jwks\IssuerJwksResolver;

/**
 * Publisher configuration.
 *
 * Mirrors `DcaPublisherConfig` in packages/capsule-server/src/dca-types.ts.
 */
final class PublisherConfig
{
    public readonly string $rotationSecretBytes;

    public function __construct(
        public readonly string $domain,
        public readonly string $signingKeyPem,
        string $rotationSecret,
        public readonly ?string $signingKeyId = null,
        public readonly int $rotationIntervalHours = 1,
        public readonly ?IssuerJwksResolver $issuerJwksResolver = null,
        bool $rotationSecretIsBase64 = true,
        public readonly ?string $vendorId = null,
    ) {
        $this->rotationSecretBytes = $rotationSecretIsBase64
            ? self::decodeBase64Secret($rotationSecret)
            : $rotationSecret;

        if ($vendorId !== null && !preg_match('/^[a-z0-9][a-z0-9-]*$/', $vendorId)) {
            throw new \InvalidArgumentException(
                "PublisherConfig::vendorId must match /^[a-z0-9][a-z0-9-]*$/ — got \"$vendorId\""
            );
        }
    }

    /**
     * Build the unlock URL for the hosted Sesamy issuer for this config's vendor.
     * Returns null when vendorId is not set.
     */
    public function sesamyUnlockUrl(): ?string
    {
        return $this->vendorId !== null
            ? "https://api2.sesamy.com/capsule/vendors/{$this->vendorId}/unlock"
            : null;
    }

    /**
     * Build the issuer JWKS URI for the hosted Sesamy issuer for this config's vendor.
     * Returns null when vendorId is not set.
     */
    public function sesamyJwksUri(): ?string
    {
        return $this->vendorId !== null
            ? "https://api2.sesamy.com/capsule/vendors/{$this->vendorId}/.well-known/jwks.json"
            : null;
    }

    private static function decodeBase64Secret(string $secret): string
    {
        // Accept either base64url or standard base64. Defensive — same as the JS path
        // that allows passing a `string` rotationSecret (decoded with fromBase64).
        $normalised = strtr($secret, '-_', '+/');
        $pad = strlen($normalised) % 4;
        if ($pad !== 0) {
            $normalised .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($normalised, true);
        if ($decoded === false) {
            // Fall back to treating as raw bytes if it doesn't look base64.
            return $secret;
        }
        return $decoded;
    }
}
