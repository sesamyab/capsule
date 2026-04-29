# sesamy/capsule-publisher

PHP port of the Capsule (DCA) CMS publisher. Lets PHP applications — primarily WordPress plugins — encrypt content into the same wire format produced by [`@sesamy/capsule-server`](../capsule-server) so that any DCA-compatible issuer (including the JS issuer in this repo) can unlock it.

Mirrors the `createDcaPublisher` surface from the JS package:

- `Publisher::render()` — encrypts content, derives wrapKeys, wraps key material for issuers (ECDH-P256 + RSA-OAEP), signs the resourceJWT, and emits a DCA v0.10 manifest plus a ready-to-embed `<script>` tag.
- `Publisher::createShareLinkToken()` — publisher-signed ES256 share link JWTs.
- `PublisherJwks::buildPublisherJwksDocument()` — the JWKS document the plugin serves at `.well-known/dca-publishers.json`.
- `IssuerJwksResolver` — fetches + caches issuer encryption keys from a JWKS URL.

## Installation

```bash
composer require sesamy/capsule-publisher
```

Requires PHP 8.1+ with `ext-openssl`, `ext-json`, `ext-hash`. RSA-OAEP-SHA256 wrapping uses [phpseclib3](https://github.com/phpseclib/phpseclib) (PHP's bundled OpenSSL only exposes OAEP-SHA1).

The package is published to Packagist as [`sesamy/capsule-publisher`](https://packagist.org/packages/sesamy/capsule-publisher). Source lives in this monorepo under `packages/capsule-publisher-php/`; a root `composer.json` + `.gitattributes export-ignore` rules ship just the PHP code to Composer consumers (the JS workspace stays out of `vendor/`).

## Quick example

```php
use Sesamy\Capsule\Publisher\{Publisher, PublisherConfig, RenderOptions, ContentItem, IssuerConfig};

$publisher = new Publisher(new PublisherConfig(
    domain: 'www.news-site.com',
    signingKeyPem: getenv('PUBLISHER_ES256_PRIVATE_KEY'),
    rotationSecret: getenv('ROTATION_SECRET'),   // base64
    signingKeyId: '2025-10',
));

$result = $publisher->render(new RenderOptions(
    resourceId: 'article-123',
    contentItems: [
        new ContentItem('bodytext', '<p>Premium body…</p>', scope: 'premium'),
    ],
    issuers: [
        new IssuerConfig(
            issuerName: 'sesamy',
            unlockUrl: 'https://api.sesamy.com/unlock',
            publicKeyPem: getenv('SESAMY_ECDH_PUBLIC_KEY'),
            keyId: '2025-10',
            scopes: ['premium'],
        ),
    ],
    resourceData: ['title' => 'Hello'],
));

echo $result->manifestScript;          // <script type="application/json" class="dca-manifest">…</script>
$json = $result->jsonString();         // canonical manifest JSON
```

## Compatibility tests

This package is locked to DCA manifest version `0.10`. Compatibility with the JS publisher (`@sesamy/capsule-server`) is verified in **both directions** — neither side can drift without a test failing in CI.

### PHP consumes JS ([tests/InteropFixturesTest.php](tests/InteropFixturesTest.php))

The JS package emits canonical fixtures into [tests/fixtures/](tests/fixtures/) which PHPUnit then validates byte-for-byte:

| Fixture                            | What PHP asserts                                                         |
| ---------------------------------- | ------------------------------------------------------------------------ |
| `hkdf.json`                        | `Hkdf::sha256()` output equals JS `hkdf()` for shared inputs             |
| `derive-wrap-key.json`             | `Rotation::deriveWrapKey()` matches JS for `(rotationSecret, scope, kid)`|
| `publisher-jwk.json`               | `PublisherJwks::buildPublisherJwk()` produces the same JWK from same PEM |
| `js-rendered-manifest-ecdh.json`   | PHP unwraps the contentKey (ECDH-P256) and AES-decrypts the body         |
| `js-rendered-manifest-rsa.json`    | PHP unwraps the contentKey (RSA-OAEP-SHA256) and AES-decrypts the body   |

### JS consumes PHP ([packages/capsule-server/src/\_\_tests\_\_/php-interop.test.ts](../capsule-server/src/__tests__/php-interop.test.ts))

PHP renders manifests with the same pinned keys; Vitest then exercises the JS issuer primitives against them:

| Fixture                              | What JS asserts                                                       |
| ------------------------------------ | --------------------------------------------------------------------- |
| `php-rendered-manifest-ecdh.json`    | resourceJWT signature verifies, contentKey unwraps via ECDH, body OK  |
| `php-rendered-manifest-rsa.json`     | resourceJWT signature verifies, contentKey unwraps via RSA, body OK   |
| (same fixture)                       | Scope wrapKey unwraps and itself unwraps the contentKey               |

### CI

[.github/workflows/php-ci.yml](../../.github/workflows/php-ci.yml) runs both sides on every PR:

- **`phpunit`** — matrix over PHP 8.1 / 8.2 / 8.3 / 8.4, runs PHPUnit (consumes the committed JS-emitted fixtures).
- **`interop`** — installs both PHP and Node, regenerates fresh fixtures from scratch, and runs PHPUnit + Vitest end-to-end.

The existing JS [.github/workflows/unit-tests.yml](../../.github/workflows/unit-tests.yml) already covers PHP→JS too, since `pnpm test` picks up `php-interop.test.ts` and the PHP-rendered manifests are committed.

### When you change the wire format

Run the whole loop locally and commit the regenerated fixtures with the change:

```bash
composer test:interop
```

This rebuilds `@sesamy/capsule-server`, regenerates the JS-emitted fixtures, has PHP re-render the matching manifests for the JS suite, and runs both PHPUnit and Vitest. If both go green, the wire format is consistent.

## Development

Run from the repo root (composer.json lives there so the JS workspace and PHP package can stay in lockstep):

```bash
composer install
composer test                  # PHPUnit only (uses committed fixtures)
composer test:interop          # full PHP ↔ JS loop with fresh fixtures
```

## Releasing

Releases are published to Packagist automatically — Packagist watches this repo and treats any tag matching `vX.Y.Z` as a release of `sesamy/capsule-publisher`. The JS packages use Changesets and tag as `@sesamy/capsule-server@x.y.z`, which Packagist ignores entirely, so there's no collision.

To cut a PHP release:

1. Make sure `composer test:interop` is green on `main`.
2. Decide the next version following SemVer (`vMAJOR.MINOR.PATCH`).
3. Tag and push:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
4. Packagist picks up the tag within a minute or two. Verify at <https://packagist.org/packages/sesamy/capsule-publisher>.

Initial Packagist setup (one-time, manual):

1. Sign in to <https://packagist.org> with the Sesamy GitHub account.
2. "Submit Package" → paste the repo URL `https://github.com/sesamyab/capsule`.
3. Enable the GitHub service hook (Packagist's setup page links the right webhook), so future tags sync without a manual "Update" click.
