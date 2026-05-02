<?php

declare(strict_types=1);

/**
 * Render two DCA manifests (ECDH + RSA paths) using the PHP publisher with
 * the pinned keys from tests/fixtures/keys.json, and write the results back
 * to tests/fixtures/php-rendered-manifest-{ecdh,rsa}.json.
 *
 * The JS-side interop test (packages/capsule-server/src/__tests__/php-interop.test.ts)
 * loads those manifests and verifies the JS issuer can decrypt them.
 */

require __DIR__ . '/../../../vendor/autoload.php';

use Sesamy\Capsule\Publisher\ContentItem;
use Sesamy\Capsule\Publisher\IssuerConfig;
use Sesamy\Capsule\Publisher\Publisher;
use Sesamy\Capsule\Publisher\PublisherConfig;
use Sesamy\Capsule\Publisher\RenderOptions;
use Sesamy\Capsule\Publisher\ShareLinkOptions;

$fixtureDir = __DIR__ . '/../tests/fixtures';
$keysPath = $fixtureDir . '/keys.json';
if (!file_exists($keysPath)) {
    fwrite(STDERR, "Missing $keysPath — run the JS emitter first\n");
    exit(1);
}
$keys = json_decode((string) file_get_contents($keysPath), true, flags: JSON_THROW_ON_ERROR);

$plaintext = '<p>Premium body — interop fixture (php-rendered)</p>';
$resourceId = 'article-php-interop';

function renderFor(array $keys, string $issuerPubPem, string $issuerKid, string $algorithm, string $resourceId, string $plaintext): array
{
    $publisher = new Publisher(new PublisherConfig(
        domain: $keys['domain'],
        signingKeyPem: $keys['publisherSigningPrivateKeyPem'],
        rotationSecret: $keys['rotationSecretBase64'],
        signingKeyId: $keys['signingKid'],
    ));
    $result = $publisher->render(new RenderOptions(
        resourceId: $resourceId,
        contentItems: [new ContentItem('bodytext', $plaintext, scope: 'premium')],
        issuers: [new IssuerConfig(
            issuerName: 'interop',
            unlockUrl: 'https://issuer.example/unlock',
            publicKeyPem: $issuerPubPem,
            keyId: $issuerKid,
            algorithm: $algorithm,
            scopes: ['premium'],
        )],
        resourceData: ['title' => 'Hello from PHP'],
    ));
    return $result->manifest;
}

$ecdhManifest = renderFor(
    $keys,
    $keys['ecdhIssuerPublicKeyPem'],
    $keys['ecdhIssuerKid'],
    'ECDH-P256',
    $resourceId,
    $plaintext,
);
file_put_contents(
    $fixtureDir . '/php-rendered-manifest-ecdh.json',
    json_encode([
        'resourceId' => $resourceId,
        'plaintext' => $plaintext,
        'issuerName' => 'interop',
        'issuerAlgorithm' => 'ECDH-P256',
        'manifest' => $ecdhManifest,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
);
echo "wrote tests/fixtures/php-rendered-manifest-ecdh.json\n";

$rsaManifest = renderFor(
    $keys,
    $keys['rsaIssuerPublicKeyPem'],
    $keys['rsaIssuerKid'],
    'RSA-OAEP',
    $resourceId,
    $plaintext,
);
file_put_contents(
    $fixtureDir . '/php-rendered-manifest-rsa.json',
    json_encode([
        'resourceId' => $resourceId,
        'plaintext' => $plaintext,
        'issuerName' => 'interop',
        'issuerAlgorithm' => 'RSA-OAEP',
        'manifest' => $rsaManifest,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
);
echo "wrote tests/fixtures/php-rendered-manifest-rsa.json\n";

// ---------------------------------------------------------------------------
// PHP-emitted share-link tokens (contentNames + scopes variants).
// JS verifies them with `verifyShareToken` against the publisher's pinned
// signing key from keys.json.
// ---------------------------------------------------------------------------
$publisher = new Publisher(new PublisherConfig(
    domain: $keys['domain'],
    signingKeyPem: $keys['publisherSigningPrivateKeyPem'],
    rotationSecret: $keys['rotationSecretBase64'],
    signingKeyId: $keys['signingKid'],
));

$shareNames = $publisher->createShareLinkToken(new ShareLinkOptions(
    resourceId: 'php-share-1',
    contentNames: ['bodytext'],
    expiresIn: 3600,
    maxUses: 5,
    data: ['campaign' => 'fall'],
));
$shareScopes = $publisher->createShareLinkToken(new ShareLinkOptions(
    resourceId: 'php-share-1',
    scopes: ['premium'],
    expiresIn: 7200,
));
file_put_contents(
    $fixtureDir . '/php-rendered-share-tokens.json',
    json_encode([
        'domain' => $keys['domain'],
        'resourceId' => 'php-share-1',
        'signingKid' => $keys['signingKid'],
        'tokens' => [
            'contentNames' => $shareNames,
            'scopes' => $shareScopes,
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
);
echo "wrote tests/fixtures/php-rendered-share-tokens.json\n";

// ---------------------------------------------------------------------------
// PHP-rendered "rich" manifest: two issuers (one scope-mode, one
// name-granular), two content items, and rich resourceData. JS verifies the
// resourceData passes through and that both issuers' wrapped material
// unwraps with the matching private key.
// ---------------------------------------------------------------------------
$ecdhB = \openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
\openssl_pkey_export($ecdhB, $ecdhBPriv);
$ecdhBPub = \openssl_pkey_get_details($ecdhB)['key'];
$secondaryKid = 'iss-ecdh-php-2';

$richResult = $publisher->render(new RenderOptions(
    resourceId: 'article-php-rich',
    contentItems: [
        new ContentItem('bodytext', '<p>Premium body — PHP rich</p>', scope: 'premium'),
        new ContentItem('sidebar', '<aside>Side</aside>', scope: 'premium'),
    ],
    issuers: [
        new IssuerConfig(
            issuerName: 'primary',
            unlockUrl: 'https://issuer-a.example/unlock',
            publicKeyPem: $keys['ecdhIssuerPublicKeyPem'],
            keyId: $keys['ecdhIssuerKid'],
            algorithm: 'ECDH-P256',
            scopes: ['premium'],
        ),
        new IssuerConfig(
            issuerName: 'secondary',
            unlockUrl: 'https://issuer-b.example/unlock',
            publicKeyPem: $ecdhBPub,
            keyId: $secondaryKid,
            algorithm: 'ECDH-P256',
            contentNames: ['bodytext'], // name-granular
        ),
    ],
    resourceData: ['title' => 'PHP rich', 'tier' => 'premium', 'listed' => [4, 5, 6]],
));
file_put_contents(
    $fixtureDir . '/php-rendered-manifest-rich.json',
    json_encode([
        'resourceId' => 'article-php-rich',
        'plaintext' => '<p>Premium body — PHP rich</p>',
        'sidebarPlaintext' => '<aside>Side</aside>',
        'primary' => [
            'issuerName' => 'primary',
            'keyId' => $keys['ecdhIssuerKid'],
            'privateKeyPem' => $keys['ecdhIssuerPrivateKeyPem'],
        ],
        'secondary' => [
            'issuerName' => 'secondary',
            'keyId' => $secondaryKid,
            'privateKeyPem' => $ecdhBPriv,
        ],
        'expectedResourceData' => ['title' => 'PHP rich', 'tier' => 'premium', 'listed' => [4, 5, 6]],
        'manifest' => $richResult->manifest,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
);
echo "wrote tests/fixtures/php-rendered-manifest-rich.json\n";
