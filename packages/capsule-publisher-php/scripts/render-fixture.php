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
