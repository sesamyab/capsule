<?php

declare(strict_types=1);

namespace Sesamy\Capsule\Publisher;

use Sesamy\Capsule\Publisher\Crypto\Aes;
use Sesamy\Capsule\Publisher\Crypto\Encoding;
use Sesamy\Capsule\Publisher\Crypto\Random;
use Sesamy\Capsule\Publisher\Dca\Jwt;
use Sesamy\Capsule\Publisher\Dca\Rotation;
use Sesamy\Capsule\Publisher\Dca\Wrap;
use Sesamy\Capsule\Publisher\Exceptions\PublisherException;

/**
 * DCA Publisher — encrypts content items, derives wrapKeys, wraps key
 * material for each issuer, signs the resourceJWT, and emits the manifest.
 *
 * Direct port of packages/capsule-server/src/dca-publisher.ts. The wire
 * format (DCA v0.10) is identical so the JS issuer accepts manifests from
 * this PHP publisher byte-for-byte.
 */
final class Publisher
{
    public function __construct(private readonly PublisherConfig $config)
    {
    }

    /**
     * Encrypt + wrap + sign one render. Returns the manifest plus the
     * `<script type="application/json" class="dca-manifest">` HTML string.
     */
    public function render(RenderOptions $options): RenderResult
    {
        $rotation = Rotation::getCurrentRotationVersions($this->config->rotationIntervalHours);
        $renderId = Random::renderId();

        // Reject duplicate contentName values.
        $seen = [];
        foreach ($options->contentItems as $item) {
            if (isset($seen[$item->contentName])) {
                throw new PublisherException("Duplicate contentName \"{$item->contentName}\" in contentItems");
            }
            $seen[$item->contentName] = true;
        }

        // Resolve scope per contentName (defaults to contentName).
        $resolvedScopes = [];
        foreach ($options->contentItems as $item) {
            $resolvedScopes[$item->contentName] = $item->effectiveScope();
        }

        // Encrypt each content item, wrap its contentKey under each rotation wrapKey.
        $contentKeys = [];
        $content = [];
        foreach ($options->contentItems as $item) {
            $contentName = $item->contentName;
            $scope = $resolvedScopes[$contentName];

            $contentKey = Random::aesKey();
            $iv = Random::iv();

            $aadString = $this->config->domain . '|' . $options->resourceId . '|' . $contentName . '|' . $scope;
            $ciphertext = Aes::gcmEncrypt($item->content, $contentKey, $iv, $aadString);

            $contentKeys[$contentName] = $contentKey;

            // Wrap contentKey under each rotation-version wrapKey.
            $wrappedContentKey = [];
            foreach ([$rotation['current'], $rotation['next']] as $version) {
                $wrapKey = Rotation::deriveWrapKey($this->config->rotationSecretBytes, $scope, $version['kid']);
                $wrapIv = Random::iv();
                $wrappedKey = Aes::gcmEncrypt($contentKey, $wrapKey, $wrapIv);
                $wrappedContentKey[] = [
                    'kid' => $version['kid'],
                    'iv' => Encoding::toBase64Url($wrapIv),
                    'ciphertext' => Encoding::toBase64Url($wrappedKey),
                ];
            }

            $content[$contentName] = [
                'contentType' => $item->contentType,
                'iv' => Encoding::toBase64Url($iv),
                'aad' => $aadString,
                'ciphertext' => Encoding::toBase64Url($ciphertext),
                'wrappedContentKey' => $wrappedContentKey,
            ];
        }

        // For each issuer: wrap contentKey + (optionally) wrapKeys for each issuer key.
        $issuerData = [];
        foreach ($options->issuers as $issuerConfig) {
            if (isset($issuerData[$issuerConfig->issuerName])) {
                throw new PublisherException("Duplicate issuerName \"{$issuerConfig->issuerName}\" in issuers");
            }
            $resolvedKeys = $this->resolveIssuerKeys($issuerConfig);
            [$contentNamesToWrap, $isNameGranular] = $this->resolveContentNamesForIssuer(
                $issuerConfig,
                $options->contentItems,
                $resolvedScopes,
            );

            $issuerKeys = [];
            foreach ($contentNamesToWrap as $contentName) {
                if (!isset($contentKeys[$contentName])) {
                    throw new PublisherException("Content item \"$contentName\" not found for issuer \"{$issuerConfig->issuerName}\"");
                }
                $contentKey = $contentKeys[$contentName];
                $scope = $resolvedScopes[$contentName];
                $wrapAad = $scope;

                foreach ($resolvedKeys as $issuerKey) {
                    $wrappedContentKey = Wrap::wrap(
                        $contentKey,
                        $issuerKey['publicKeyPem'],
                        $issuerKey['algorithm'],
                        $wrapAad,
                    );

                    $entry = [
                        'contentName' => $contentName,
                        'scope' => $scope,
                    ];
                    if ($issuerKey['kid'] !== null && $issuerKey['kid'] !== '') {
                        $entry['kid'] = $issuerKey['kid'];
                    }
                    $entry['contentKey'] = $wrappedContentKey;

                    if (!$isNameGranular) {
                        $wrapKeysOut = [];
                        foreach ([$rotation['current'], $rotation['next']] as $version) {
                            $wrapKey = Rotation::deriveWrapKey(
                                $this->config->rotationSecretBytes,
                                $scope,
                                $version['kid'],
                            );
                            $wrapKeysOut[] = [
                                'kid' => $version['kid'],
                                'key' => Wrap::wrap(
                                    $wrapKey,
                                    $issuerKey['publicKeyPem'],
                                    $issuerKey['algorithm'],
                                    $wrapAad,
                                ),
                            ];
                        }
                        $entry['wrapKeys'] = $wrapKeysOut;
                    }
                    $issuerKeys[] = $entry;
                }
            }

            $issuerEntry = ['unlockUrl' => $issuerConfig->unlockUrl];
            // Echo the issuer's keyId at entry level only when not using a JWKS (mirrors JS).
            if (($issuerConfig->jwksUri === null || $issuerConfig->jwksUri === '')
                && $issuerConfig->keyId !== null && $issuerConfig->keyId !== ''
            ) {
                $issuerEntry['keyId'] = $issuerConfig->keyId;
            }
            $issuerEntry['keys'] = $issuerKeys;

            $issuerData[$issuerConfig->issuerName] = $issuerEntry;
        }

        // Unique scopes in order of first appearance.
        $uniqueScopes = [];
        foreach ($resolvedScopes as $scope) {
            if (!in_array($scope, $uniqueScopes, true)) {
                $uniqueScopes[] = $scope;
            }
        }

        $issuedAt = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $resourceJwt = Jwt::createResourceJwt(
            $this->config->domain,
            $options->resourceId,
            $issuedAt,
            $renderId,
            $uniqueScopes,
            $options->resourceData,
            $this->config->signingKeyPem,
            $this->config->signingKeyId,
        );

        $manifest = [
            'version' => '0.10',
            'resourceJWT' => $resourceJwt,
            'content' => (object) $content,
            'issuers' => (object) $issuerData,
        ];

        // Canonical (non-HTML) JSON for RenderResult::jsonString() — preserves
        // the (object) casts so empty content/issuers maps serialise as {}.
        $manifestJson = json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($manifestJson === false) {
            throw new PublisherException('Failed to JSON-encode manifest: ' . json_last_error_msg());
        }

        // JSON_HEX_TAG hex-escapes every "<" and ">" byte, which makes the
        // payload safe to embed inside a <script> element regardless of case
        // or surrounding context (e.g. </Script>, <!--, <script).
        $manifestScriptJson = json_encode(
            $manifest,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG,
        );
        if ($manifestScriptJson === false) {
            throw new PublisherException('Failed to JSON-encode manifest: ' . json_last_error_msg());
        }
        $manifestScript = '<script type="application/json" class="dca-manifest">' . $manifestScriptJson . '</script>';

        // Drop stdClass wrappers from the returned array shape so callers see a
        // plain associative array. The canonical JSON (with empty maps as {})
        // is preserved in $manifestJson and surfaced via RenderResult::jsonString().
        $manifest['content'] = $content;
        $manifest['issuers'] = $issuerData;

        return new RenderResult($manifest, $manifestScript, $manifestJson);
    }

    /**
     * Create a publisher-signed share link token (ES256 JWT) granting
     * pre-authenticated access to specific content.
     */
    public function createShareLinkToken(ShareLinkOptions $options): string
    {
        $now = time();
        $payload = [
            'type' => 'dca-share',
            'domain' => $this->config->domain,
            'resourceId' => $options->resourceId,
            'contentNames' => $options->contentNames ?? [],
            'iat' => $now,
            'exp' => $now + $options->expiresIn,
        ];
        if ($options->maxUses !== null) {
            $payload['maxUses'] = $options->maxUses;
        }
        $payload['jti'] = $options->jti ?? Random::jti();
        if ($options->data !== null) {
            $payload['data'] = (object) $options->data;
        }
        if ($options->scopes !== null) {
            $payload['scopes'] = $options->scopes;
        }

        return Jwt::createJwt($payload, $this->config->signingKeyPem, $this->config->signingKeyId);
    }

    /**
     * Resolve the issuer's encryption key(s) — either the pinned PEM or the
     * active set from a JWKS URL.
     *
     * @return list<array{kid:?string, algorithm:string, publicKeyPem:string}>
     */
    private function resolveIssuerKeys(IssuerConfig $issuerConfig): array
    {
        if ($issuerConfig->jwksUri !== null && $issuerConfig->jwksUri !== '') {
            if ($this->config->issuerJwksResolver === null) {
                throw new PublisherException(
                    "Issuer \"{$issuerConfig->issuerName}\" uses jwksUri but PublisherConfig has no issuerJwksResolver",
                );
            }
            $resolved = $this->config->issuerJwksResolver->getActiveIssuerKeys($issuerConfig->jwksUri);
            // Normalise shape (kid is non-null for JWKS-resolved keys).
            return array_map(
                static fn (array $k): array => [
                    'kid' => $k['kid'],
                    'algorithm' => $k['algorithm'],
                    'publicKeyPem' => $k['publicKeyPem'],
                ],
                $resolved,
            );
        }

        $pem = (string) $issuerConfig->publicKeyPem;
        $algorithm = $issuerConfig->algorithm ?? Wrap::detectAlgorithm($pem);
        return [[
            'kid' => $issuerConfig->keyId,
            'algorithm' => $algorithm,
            'publicKeyPem' => $pem,
        ]];
    }

    /**
     * Decide which content names to wrap for this issuer + whether we're in
     * name-granular mode (which omits wrapKeys to prevent scope-key leakage).
     *
     * @param list<ContentItem>     $contentItems
     * @param array<string,string>  $resolvedScopes
     * @return array{0: list<string>, 1: bool}
     */
    private function resolveContentNamesForIssuer(
        IssuerConfig $issuerConfig,
        array $contentItems,
        array $resolvedScopes,
    ): array {
        if ($issuerConfig->scopes !== null && $issuerConfig->scopes !== []) {
            $scopeSet = array_flip($issuerConfig->scopes);
            $names = [];
            foreach ($contentItems as $item) {
                if (isset($scopeSet[$resolvedScopes[$item->contentName]])
                    && !in_array($item->contentName, $names, true)
                ) {
                    $names[] = $item->contentName;
                }
            }
            $isNameGranular = false;
        } elseif ($issuerConfig->contentNames !== null && $issuerConfig->contentNames !== []) {
            $names = array_values(array_unique($issuerConfig->contentNames));
            $isNameGranular = true;
        } else {
            throw new PublisherException(
                "Issuer \"{$issuerConfig->issuerName}\" must specify contentNames or scopes",
            );
        }

        if ($names === []) {
            throw new PublisherException(
                "Issuer \"{$issuerConfig->issuerName}\" resolved to zero content items — check that its scopes match at least one content item",
            );
        }
        return [$names, $isNameGranular];
    }
}
