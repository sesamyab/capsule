#!/usr/bin/env bash
# Refresh interop fixtures and run both test suites end-to-end.
#
# Sequence:
#   1. Build the JS publisher (so the emitter can import dist/index.mjs).
#   2. Emit JS-side test vectors + JS-rendered manifests for the PHP suite.
#   3. PHP renders matching manifests for the JS suite to consume.
#   4. Run PHP suite (consumes JS fixtures).
#   5. Run JS suite (consumes PHP fixtures).
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
