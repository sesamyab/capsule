#!/usr/bin/env bash
# Refresh interop fixtures and run both test suites end-to-end.
#
# This handles the **regenerated** interop fixtures (hkdf.json,
# js-rendered-manifest-*.json, php-rendered-manifest-*.json, share-token
# fixtures, rich-manifest fixtures). They use fresh keys each run, so they
# only catch *current-run* divergence between PHP and JS.
#
# A second class of fixtures lives in tests/fixtures/static/ and is generated
# **once** by `node packages/capsule-server/scripts/generate-static-fixtures.mjs`.
# These are committed and never regenerated in this script — they are the
# known-answer vectors that catch lockstep refactors of both implementations.
# If you legitimately need to refresh them (wire-format change), delete the
# files manually and re-run the static generator.
#
# Sequence:
#   1. Build the JS publisher (so the emitter can import dist/index.mjs).
#   2. Emit JS-side test vectors + JS-rendered manifests for the PHP suite.
#   3. PHP renders matching manifests for the JS suite to consume.
#   4. Run PHP suite (consumes JS fixtures + static fixtures).
#   5. Run JS suite (consumes PHP fixtures + static fixtures).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PHP_DIR="$REPO_ROOT/packages/capsule-publisher-php"
JS_DIR="$REPO_ROOT/packages/capsule-server"

echo "==> Building @sesamy/capsule-server"
pnpm --filter @sesamy/capsule-server build >/dev/null

echo "==> Emitting JS → PHP test vectors"
node "$JS_DIR/scripts/emit-php-test-vectors.mjs"

echo "==> Rendering PHP → JS interop manifests"
php "$PHP_DIR/scripts/render-fixture.php"

echo "==> Running PHP test suite"
( cd "$REPO_ROOT" && vendor/bin/phpunit -c packages/capsule-publisher-php/phpunit.xml.dist )

echo "==> Running JS test suite"
pnpm --filter @sesamy/capsule-server test
