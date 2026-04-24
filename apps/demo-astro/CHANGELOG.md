# @sesamy/demo-astro

## 0.7.1

### Patch Changes

- Updated dependencies [[`cd4da10`](https://github.com/sesamyab/capsule/commit/cd4da10b2108392c6f57238d17bdcd928cc1fac5), [`9337ee8`](https://github.com/sesamyab/capsule/commit/9337ee8d4e1e62ee4f6ee05b47a011c4bdd50c2a)]:
  - @sesamy/capsule-server@0.12.0

## 0.7.0

### Minor Changes

- [#30](https://github.com/sesamyab/capsule/pull/30) [`e5901ea`](https://github.com/sesamyab/capsule/commit/e5901eab0b84b93a01ce4ed69549f189724a569c) Thanks [@markusahlstrand](https://github.com/markusahlstrand)! - Rename DCA protocol terms for clarity and standards alignment; simplify wire format structure (wire format version: `"0.10"`).

  ## What changed

  **Crypto vocabulary — unified on `wrap`/`unwrap`.** Previously "seal" was used inconsistently: for both public-key-to-issuer encryption (HPKE-style) and for symmetric key wrapping. Standardised on WebCrypto's `wrap`/`unwrap` verbs throughout, so one word covers all key-encrypting-another-key operations regardless of algorithm.

  - `seal()` / `unseal()` → `wrap()` / `unwrap()`
  - `sealEcdhP256` / `unsealEcdhP256` → `wrapEcdhP256` / `unwrapEcdhP256`
  - `DcaSealAlgorithm` → `DcaWrapAlgorithm`

  **Time-based naming removed — rotation is a policy, not a protocol primitive.** The key identifier is just a version tag; rotation cadence is the publisher's choice, not baked into the spec.

  - `periodKey` / `periodKeys` → `wrapKey` / `wrapKeys`
  - `periodSecret` → `rotationSecret`
  - `periodDurationHours` → `rotationIntervalHours`
  - `bucket` / `t` → `kid` (JOSE-standard key identifier)
  - `deriveDcaPeriodKey` → `deriveWrapKey`
  - `formatTimeBucket` → `formatTimeKid`
  - `getCurrentTimeBuckets` → `getCurrentRotationVersions`

  **OAuth-aligned access control.** The access-tier concept is OAuth's "scope," nothing new.

  - `keyName` / `keyNames` → `scope` / `scopes`
  - `grantedKeyNames` → `grantedScopes`

  **Manifest structure — one content entry per item.** Previously three top-level maps (`contentSealData`, `sealedContentKeys`, `sealedContent`) had to be cross-referenced by `contentName` to understand a single item. Merged into a single `content` map keyed by `contentName`, with per-item `contentType` / `iv` / `aad` / `ciphertext` / `wrappedContentKey` fields.

  - `DcaData` → `DcaManifest`
  - `<script class="dca-data">` → `<script class="dca-manifest">`
  - `<template class="dca-sealed-content">` → **removed** (ciphertext now lives inline inside `manifest.content[name].ciphertext`)
  - `contentSealData` + `sealedContentKeys` + `sealedContent` → merged into `content`
  - `issuerData` → `issuers`
  - `contentEncryptionKeys` (as a field) → `keys`
  - `DcaRenderResult.html.dcaDataScript` + `.sealedContentTemplate` → single `.manifestScript`

  **Delivery modes renamed.** Describe what the issuer sends, not the mechanism name.

  - `deliveryMode: "contentKey"` → `"direct"`
  - `deliveryMode: "periodKey"` → `"wrapKey"`

  **AEAD field names aligned with WebCrypto.**

  - `nonce` → `iv`

  **Client:**

  - `periodKeyCache` option → `wrapKeyCache`
  - `DcaPeriodKeyCache` type → `DcaWrapKeyCache`
  - Cache key format `dca:pk:{keyName}:{timeBucket}` → `dca:wk:{scope}:{kid}`
  - Default IndexedDB name `dca-period-keys` → `dca-wrap-keys`
  - Default wrapKey caching is on — pass `wrapKeyCache: false` to disable.

  ## Why

  The v2 vocabulary leaked implementation details (time buckets, "sealing") into the protocol surface. v1 names describe what things _are_ (a scope, a wrap key, a manifest) rather than how they happen to be implemented. The structural merge removes a foot-gun where readers had to cross-reference three maps to understand a single content item.

  ## Migration

  This is a breaking wire-format change. Re-render all DCA content with the new `@sesamy/capsule-server` and re-deploy clients with the new `@sesamy/capsule`. Mixed versions will not interoperate.

  The wire format version is set to `"0.10"` since the library is still pre-1.0.

### Patch Changes

- Updated dependencies [[`e5901ea`](https://github.com/sesamyab/capsule/commit/e5901eab0b84b93a01ce4ed69549f189724a569c)]:
  - @sesamy/capsule@0.12.0
  - @sesamy/capsule-server@0.11.0

## 0.6.0

### Minor Changes

- [#28](https://github.com/sesamyab/capsule/pull/28) [`21315f2`](https://github.com/sesamyab/capsule/commit/21315f22c95a3db88ff43a20a502ca8eb3ad74fa) Thanks [@markusahlstrand](https://github.com/markusahlstrand)! - Remove the renderId from keys

### Patch Changes

- Updated dependencies [[`21315f2`](https://github.com/sesamyab/capsule/commit/21315f22c95a3db88ff43a20a502ca8eb3ad74fa)]:
  - @sesamy/capsule@0.11.0
  - @sesamy/capsule-server@0.10.0

## 0.5.0

### Minor Changes

- [#26](https://github.com/sesamyab/capsule/pull/26) [`04e7054`](https://github.com/sesamyab/capsule/commit/04e7054ca1a324e389edd5213db4efa82eb06c23) Thanks [@markusahlstrand](https://github.com/markusahlstrand)! - Update the format for unlocking content

### Patch Changes

- Updated dependencies [[`04e7054`](https://github.com/sesamyab/capsule/commit/04e7054ca1a324e389edd5213db4efa82eb06c23)]:
  - @sesamy/capsule@0.10.0
  - @sesamy/capsule-server@0.9.0

## 0.4.1

### Patch Changes

- Updated dependencies [[`899511b`](https://github.com/sesamyab/capsule/commit/899511bb3c27affca2e3f4fb5d89edccf1525994)]:
  - @sesamy/capsule@0.9.0

## 0.4.0

### Minor Changes

- [#22](https://github.com/sesamyab/capsule/pull/22) [`26d976d`](https://github.com/sesamyab/capsule/commit/26d976d2a602b0f0bf609ca6647e557d6fdf0104) Thanks [@markusahlstrand](https://github.com/markusahlstrand)! - Remove fallback code

### Patch Changes

- Updated dependencies [[`26d976d`](https://github.com/sesamyab/capsule/commit/26d976d2a602b0f0bf609ca6647e557d6fdf0104)]:
  - @sesamy/capsule@0.8.0
  - @sesamy/capsule-server@0.8.0

## 0.3.0

### Minor Changes

- [#20](https://github.com/sesamyab/capsule/pull/20) [`a4c19b0`](https://github.com/sesamyab/capsule/commit/a4c19b03956ecdb87fbd0eb061714fc334c0a59a) Thanks [@markusahlstrand](https://github.com/markusahlstrand)! - Add breaking changes for v0.7

### Patch Changes

- Updated dependencies [[`a4c19b0`](https://github.com/sesamyab/capsule/commit/a4c19b03956ecdb87fbd0eb061714fc334c0a59a)]:
  - @sesamy/capsule@0.7.0
  - @sesamy/capsule-server@0.7.0

## 0.2.1

### Patch Changes

- Updated dependencies [[`a20563f`](https://github.com/sesamyab/capsule/commit/a20563fb103220c7203961e1c0ae39fa3ba5033c)]:
  - @sesamy/capsule@0.6.0

## 0.2.0

### Minor Changes

- [#15](https://github.com/sesamyab/capsule/pull/15) [`bad8a50`](https://github.com/sesamyab/capsule/commit/bad8a500043507bcae13a0bceb6c3c72528fbcdc) Thanks [@markusahlstrand](https://github.com/markusahlstrand)! - Use content names for tiers

- [#16](https://github.com/sesamyab/capsule/pull/16) [`e676237`](https://github.com/sesamyab/capsule/commit/e676237cb17c83938ebd3652f54782fd992902b8) Thanks [@markusahlstrand](https://github.com/markusahlstrand)! - Add v2 version

### Patch Changes

- Updated dependencies [[`bad8a50`](https://github.com/sesamyab/capsule/commit/bad8a500043507bcae13a0bceb6c3c72528fbcdc), [`dcb405c`](https://github.com/sesamyab/capsule/commit/dcb405c42dd5c6543e3a6e11e1dbf0774886b21c), [`e676237`](https://github.com/sesamyab/capsule/commit/e676237cb17c83938ebd3652f54782fd992902b8)]:
  - @sesamy/capsule@0.5.0
  - @sesamy/capsule-server@0.6.0

## 0.1.3

### Patch Changes

- Updated dependencies [[`523fb7e`](https://github.com/sesamyab/capsule/commit/523fb7eb29e4c00be9fe10a331ba7cd9157c3516)]:
  - @sesamy/capsule-server@0.5.0

## 0.1.2

### Patch Changes

- Updated dependencies [[`cfc41ee`](https://github.com/sesamyab/capsule/commit/cfc41ee5ccbc01606b93f82b297a14e131bca4c1)]:
  - @sesamy/capsule@0.4.0
  - @sesamy/capsule-server@0.4.0

## 0.1.1

### Patch Changes

- Updated dependencies [[`a3d1807`](https://github.com/sesamyab/capsule/commit/a3d1807429b8470cabc65f8639ed33d8b87ddaac)]:
  - @sesamy/capsule@0.3.0
  - @sesamy/capsule-server@0.3.0

## 0.1.0

### Minor Changes

- [#2](https://github.com/sesamyab/capsule/pull/2) [`c20fefb`](https://github.com/sesamyab/capsule/commit/c20fefb5623056b8210fc7fdc53ca55253911413) Thanks [@markusahlstrand](https://github.com/markusahlstrand)! - Add a capsule-server

### Patch Changes

- Updated dependencies [[`c20fefb`](https://github.com/sesamyab/capsule/commit/c20fefb5623056b8210fc7fdc53ca55253911413), [`952ff4e`](https://github.com/sesamyab/capsule/commit/952ff4eb49eb3ea5a2ce796ca618919b17125b23)]:
  - @sesamy/capsule@0.2.0
  - @sesamy/capsule-server@0.2.0
