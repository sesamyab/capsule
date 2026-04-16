---
"@sesamy/capsule": minor
"@sesamy/capsule-server": minor
"@sesamy/demo-astro": minor
---

Rename DCA protocol terms for clarity and standards alignment; simplify wire format structure (wire format version: `"0.10"`).

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

The v2 vocabulary leaked implementation details (time buckets, "sealing") into the protocol surface. v1 names describe what things *are* (a scope, a wrap key, a manifest) rather than how they happen to be implemented. The structural merge removes a foot-gun where readers had to cross-reference three maps to understand a single content item.

## Migration

This is a breaking wire-format change. Re-render all DCA content with the new `@sesamy/capsule-server` and re-deploy clients with the new `@sesamy/capsule`. Mixed versions will not interoperate.

The wire format version is set to `"0.10"` since the library is still pre-1.0.
