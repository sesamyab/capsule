<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher\Dca;

use Sesamy\Capsule\Publisher\Crypto\EcdsaP256;
use Sesamy\Capsule\Publisher\Crypto\Encoding;
use Sesamy\Capsule\Publisher\Exceptions\PublisherException;

/**
 * Compact JWS (JWT) creation with ES256.
 *
 * Mirrors packages/capsule-server/src/dca-jwt.ts. Two signing helpers:
 *   - createJwt(): generic — used for share link tokens.
 *   - createResourceJwt(): wraps DcaResource fields into the standard
 *       JWT claim names (iss/sub/iat/jti).
 */
final class Jwt
{
    /**
     * Encode a JWT header object. The exact JSON shape (and key order)
     * matters because it becomes part of the signing input.
     *
     * Without a kid we emit `{"alg":"ES256","typ":"JWT"}` byte-equal to the
     * JS implementation's DEFAULT_HEADER_B64.
     */
    private static function encodeHeader(?string $kid): string
    {
        if ($kid === null || $kid === '') {
            $headerJson = '{"alg":"ES256","typ":"JWT"}';
        } else {
            $headerJson = '{"alg":"ES256","typ":"JWT","kid":' . self::jsonString($kid) . '}';
        }
        return Encoding::toBase64Url($headerJson);
    }

    /**
     * Sign $payload (any JSON-serialisable structure) as an ES256 JWT.
     */
    public static function createJwt(array|object $payload, string $signingKeyPem, ?string $kid = null): string
    {
        $headerB64 = self::encodeHeader($kid);
        $payloadJson = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($payloadJson === false) {
            throw new PublisherException('Failed to JSON-encode JWT payload: ' . json_last_error_msg());
        }
        $payloadB64 = Encoding::toBase64Url($payloadJson);

        $signingInput = $headerB64 . '.' . $payloadB64;
        $signature = EcdsaP256::sign($signingInput, $signingKeyPem);

        return $signingInput . '.' . Encoding::toBase64Url($signature);
    }

    /**
     * Build the canonical resourceJWT payload from the publisher's resource
     * fields, then sign as ES256.
     *
     * The claim mapping mirrors `createResourceJwt` in dca-jwt.ts:
     *   domain → iss, resourceId → sub, issuedAt → iat (Unix s),
     *   renderId → jti, scopes → scopes, data → data.
     */
    public static function createResourceJwt(
        string $domain,
        string $resourceId,
        \DateTimeImmutable $issuedAt,
        string $renderId,
        array $scopes,
        array $data,
        string $signingKeyPem,
        ?string $kid = null,
    ): string {
        $payload = [
            'iss' => $domain,
            'sub' => $resourceId,
            'iat' => $issuedAt->getTimestamp(),
            'jti' => $renderId,
            'scopes' => $scopes,
            'data' => (object) $data,
        ];
        return self::createJwt($payload, $signingKeyPem, $kid);
    }

    /**
     * Encode a single JSON string value with PHP-default escaping rules,
     * stripping the surrounding wrapper from json_encode().
     */
    private static function jsonString(string $value): string
    {
        $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($encoded === false) {
            throw new PublisherException('Failed to JSON-encode string');
        }
        return $encoded;
    }
}
