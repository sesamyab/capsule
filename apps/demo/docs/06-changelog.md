# Changelog

Protocol and library changes by version. Each entry describes what changed,
why, and whether it's backwards compatible.

## v0.10 (Latest)

v0.10 is a pre-release terminology and structure migration. Crypto vocabulary is
aligned with WebCrypto, time-based naming is removed, access control is aligned
with OAuth scopes, and the three top-level key/ciphertext maps are merged into a
single `content` map. The wire format version is `"0.10"`.

### Terminology & Structure Migration

[Breaking]

#### What Changed

The protocol is renamed and restructured end-to-end. The wire format version
is `"0.10"`.

- **Crypto vocabulary** -- aligned with WebCrypto: `seal`/`sealed`/`sealing` -> `wrap`/`wrapped`/`wrapping`, and `nonce` -> `iv` on content items.
- **Time-based naming removed** -- `periodKey` -> `wrapKey`, `periodSecret` -> `rotationSecret`, `bucket`/`t` -> `kid`.
- **OAuth-aligned access control** -- `keyName`/`keyNames` -> `scope`/`scopes`.
- **Manifest rename** -- `DcaData` -> `DcaManifest`, and the embedded `<script class="dca-data">` -> `<script class="dca-manifest">`.
- **Top-level map merge** -- `contentSealData`, `sealedContentKeys`, and `sealedContent` are merged into a single `content` map keyed by `contentName`. The separate `<template class="dca-sealed-content">` is eliminated -- the manifest now carries ciphertext inline.
- **Field renames** -- `issuerData` -> `issuers`, `contentEncryptionKeys` -> `keys`.
- **Delivery modes** -- `deliveryMode: "contentKey"` -> `deliveryMode: "direct"`, and `deliveryMode: "periodKey"` -> `deliveryMode: "wrapKey"`.
- **Version bump** -- `version: "2"` -> `version: "0.10"`.

#### Why

The previous vocabulary mixed metaphors ("seal" vs WebCrypto's `wrapKey`),
encoded a rotation strategy into field names ("period", "bucket"), and used
a project-specific access term ("keyName") instead of the OAuth `scope`
that most consumers already understand. Splitting content across three parallel
top-level maps (seal data, sealed keys, sealed content) also made the manifest
harder to reason about than a single content-keyed map.

#### Current Wire Format

```js
// DcaManifest -- embedded as <script class="dca-manifest"> JSON
{
  "version": "0.10",
  "resourceJWT": "eyJ...",
  "issuers": {
    "sesamy": {
      "unlockUrl": "https://unlock.sesamy.com/v1/unlock",
      "keyId": "sesamy-prod-2026Q2",
      "keys": [
        {
          "contentName": "bodytext",
          "scope": "premium",
          "contentKey": "wrapped...",        // wrapped content key (direct delivery)
          "wrapKeys": [                    // wrapped rotation keys (cacheable)
            { "kid": "260409T11", "key": "wrapped..." },
            { "kid": "260409T12", "key": "wrapped..." }
          ]
        }
      ]
    }
  },
  "content": {
    "bodytext": {
      "contentType": "text/html",
      "iv": "base64url...",                  // AES-GCM IV for the content body
      "aad": "...",                          // AEAD associated data (bound to resource)
      "ciphertext": "base64url...",          // encrypted content body (inline)
      "wrappedContentKey": [               // contentKey wrapped under each wrapKey rotation
        { "kid": "260409T11", "iv": "base64url...", "ciphertext": "base64url..." },
        { "kid": "260409T12", "iv": "base64url...", "ciphertext": "base64url..." }
      ]
    }
  }
}

// resourceJWT payload (decoded)
{
  "iss": "news.example.com",
  "sub": "article-123",
  "iat": 1735689600,
  "jti": "abc123def456",
  "scopes": ["premium"],                   // renamed from keyNames
  "data": { "section": "politics" }
}

// Unlock request
POST /api/unlock
{
  "resourceJWT": "eyJ...",
  "keys": [
    { "contentName": "bodytext", "scope": "premium", "contentKey": "wrapped...", "wrapKeys": [ ... ] }
  ],
  "clientPublicKey": "..."                   // optional
}

// Issuer grant
const result = await issuer.unlock(request, {
  grantedScopes: ["premium"],              // renamed from grantedKeyNames
  deliveryMode: "wrapKey",                 // or "direct" (was "periodKey" / "contentKey")
});
```

#### Migration

| Component | Change |
| --- | --- |
| **Publisher** | Update to `@sesamy/capsule` v0.10 -- `render()` emits the new manifest shape with inline ciphertext |
| **Client** | Update to `@sesamy/capsule-client` v0.10 -- reads `content` and `issuers[name].keys`, uses `iv`/`kid` |
| **Service** | Update to `@sesamy/capsule-server` v0.10 -- `issuer.unlock()` accepts `keys` and `grantedScopes`, emits `direct`/`wrapKey` delivery |
| **Wire format** | `version: "0.10"`. Pre-release -- no backwards compatibility shims for the old `"2"` shape |

## v0.9

v0.9 introduces two changes: entitlement claims in the resourceJWT and a flattened
wire format for content encryption keys.

### Entitlement Claims in resourceJWT

[Backwards compatible]

#### What Changed

The `resourceJWT` payload now includes a `keyNames` claim -- an array
of required entitlement key domains (tiers/roles) declared by the publisher at render time.

#### Why

Previously the issuer had to independently look up which tier a resource required
(e.g. querying a database by `resourceId`). With `keyNames` in
the signed JWT, the issuer has a **trusted source of truth** for what
entitlements are needed -- it can compare directly against the user's subscription
without a separate server-side lookup.

The client can also read `keyNames` before calling unlock to show
the right paywall (e.g. "Subscribe to Premium to read this") without a round-trip.

```js
// resourceJWT payload (decoded)
{
  "iss": "news.example.com",
  "sub": "article-123",
  "iat": 1735689600,
  "jti": "abc123def456",
  "keyNames": ["premium"],           // <- NEW: required entitlements
  "data": { "section": "politics" }
}

// Issuer access decision is now a simple set intersection:
// user entitlements intersect resource keyNames -> grant
const { resource } = await issuer.verify(request);
const userTiers = await getUserSubscriptions(userId);
const grantedKeyNames = resource.keyNames.filter(k => userTiers.includes(k));
```

#### Backwards Compatibility

Fully backwards compatible. The field is populated automatically by the publisher.
Issuers that don't use it can ignore it. The `keyNames` field defaults
to an empty array when parsing older JWTs that lack it.

### Flat contentEncryptionKeys Array

[Breaking]

#### What Changed

The deeply nested `Record<string, DcaContentKeys>` wire format for
content encryption keys is replaced with a flat `DcaContentEncryptionKey[]` array.
This affects three surfaces:

- `issuerData[name].contentKeys` -> `issuerData[name].contentEncryptionKeys` (typed as `DcaSealedContentEncryptionKey[]`)
- `DcaUnlockRequest.contentKeys` -> `DcaUnlockRequest.contentEncryptionKeys` (typed as `DcaSealedContentEncryptionKey[]`)
- `DcaUnlockResponse.keys` -> `DcaUnlockResponse.contentEncryptionKeys` (typed as `DcaContentEncryptionKey[]` -- union of delivery variants)

#### Why

The nested `Record<string, Record<string, string>>` shape had
poor TypeScript ergonomics -- no autocomplete on dynamic keys, hard to type, and
`any`-adjacent in practice. The flat array gives every field a name and
makes the simplest case (single unnamed content item) trivially simple.

```jsonc
// Before (v0.8) -- nested Records
{
  "contentKeys": {
    "bodytext": {
      "contentKey": "base64url...",
      "periodKeys": { "260409T11": "base64url...", "260409T12": "base64url..." }
    }
  }
}

// After (v0.9) -- flat array
{
  "contentEncryptionKeys": [
    {
      "contentName": "bodytext",
      "contentKey": "base64url...",
      "periodKeys": [
        { "bucket": "260409T11", "key": "base64url..." },
        { "bucket": "260409T12", "key": "base64url..." }
      ]
    }
  ]
}

// Simplest case -- single unnamed content item:
{
  "contentEncryptionKeys": [
    { "contentKey": "base64url...", "periodKeys": [{ "bucket": "260409T11", "key": "base64url..." }] }
  ]
}
```

#### New Types

```ts
// Wire format (issuerData + unlock request): both fields required
interface DcaSealedContentEncryptionKey {
  contentName?: string;           // defaults to "default" when omitted
  contentKey: string;             // sealed contentKey (always present)
  periodKeys: DcaPeriodKeyEntry[];  // sealed periodKeys (always present, default 1-hour buckets)
}

// Unlock response: exactly one delivery form per entry
type DcaContentEncryptionKey = DcaContentKeyDelivery | DcaPeriodKeyDelivery;

interface DcaContentKeyDelivery {
  contentName?: string;
  contentKey: string;             // direct key delivery
}

interface DcaPeriodKeyDelivery {
  contentName?: string;
  periodKeys: DcaPeriodKeyEntry[];  // cacheable period key delivery
}

interface DcaPeriodKeyEntry {
  bucket: string;          // e.g. "260409T11"
  key: string;             // base64url-encoded key
}
```

#### Removed Types

- `DcaContentKeys` -- replaced by `DcaSealedContentEncryptionKey`
- `DcaUnlockedKeys` -- folded into `DcaContentEncryptionKey`

#### Migration

| Component | Change |
| --- | --- |
| **Publisher** | Automatic -- `render()` now produces the new format |
| **Client** | Update to `@sesamy/capsule` v0.9 -- reads `contentEncryptionKeys` from both page data and unlock response |
| **Service** | Update to `@sesamy/capsule-server` v0.9 -- `issuer.unlock()` accepts and returns the new format |

## v0.8

v0.8 introduces a security fix for sealed key binding and removes the legacy v1 request format.

### Seal AAD Binding

[Not backwards compatible]

#### What Changed

Sealed key blobs (`contentKeys` and `periodKeys`) are now
cryptographically bound to the access tier via `keyName` as AES-GCM AAD /
RSA-OAEP label.

#### Why

Prevents a **cross-tier key substitution attack** where an attacker
could change `keyName` on a sealed entry to a tier they have access to,
tricking the issuer into unsealing keys for a different tier.

#### How It Works

1. The **publisher** passes `keyName` as AAD when sealing keys
   for issuers. Each entry carries its own `keyName`.
2. The **issuer** reads `keyName` from each entry when unsealing.
3. Mismatched AAD causes decryption to **fail** -- a blob sealed for tier
   "free" cannot be unsealed with AAD "premium".

```js
// Publisher side -- keyName bound as AAD during seal
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", keyName: "premium", content: body, contentType: "text/html" },
  ],
  issuers: [{ issuerName: "sesamy", publicKeyPem, keyId, unlockUrl, keyNames: ["premium"] }],
});
// keyName is automatically included as AES-GCM AAD in the sealed blobs

// Issuer side -- keyName from each entry used as AAD during unseal
const result = await issuer.unlock(request, {
  grantedKeyNames: ["premium"],
  deliveryMode: "contentKey",
});
// If keyName was tampered with, unseal fails
```

### v1 Legacy Removed

[Breaking]

#### What Changed

Removed the v1 request format. The following fields are no longer accepted:

- `resource` (unsigned copy)
- `issuerJWT`
- `sealed`
- `keyId`
- `issuerName`

`DcaData` version is now `"2"` (was `"1"`).

#### Why

v2 is simpler (2 fields instead of 6 + 2 JWTs) and seal AAD provides stronger
cryptographic binding than `issuerJWT` integrity proofs.

#### Removed Types & Functions

- Types: `DcaIssuerJwtPayload`, `DcaIssuerProof`
- Functions: `createIssuerJwt`, `buildIssuerProof`, `verifyIssuerProof`

#### Migration

Use the v2 unlock request format:

```text
// v2 request format (the only format now)
POST /api/unlock
{
  "resourceJWT": "eyJ...",
  "contentKeys": { "bodytext": { "contentKey": "...", "periodKeys": { ... } } },
  "clientPublicKey": "..."   // optional
}
```

## v0.7

v0.7 introduces three changes to the unlock protocol.

### Simplified Unlock Request

[Not backwards compatible]

#### Motivation

The previous unlock request sends six fields and two JWTs. After analysis, five fields
and one entire JWT turn out to be redundant:

- `resource` -- unsigned copy of what's already in `resourceJWT`
- `issuerName` -- the subscription service already knows its own name
- `keyId` -- the service knows its own key; a wrong key fails at AES-GCM unseal anyway
- `issuerJWT` -- contains SHA-256 integrity proofs of the encrypted blobs,
  but AES-GCM is already **authenticated encryption** -- any tampered
  blob fails at unseal time. The proofs are redundant.

The `sealed` field is also renamed to `contentKeys` to better
describe what it contains (encrypted content keys, not a generic "sealed" blob).

#### What Changed

The request is stripped down to the cryptographic essentials:

- `resourceJWT` -- publisher-signed resource metadata (authentication)
- `contentKeys` -- the encrypted content keys (AES-GCM provides integrity)

**Why the issuerJWT is unnecessary:**

1. **Integrity proofs:** SHA-256 hashes of encrypted blobs, to detect tampering.
   But encrypted blobs use **AES-GCM** (authenticated encryption) -- any modification
   causes the unseal to fail with a GCM authentication error. The hashes add nothing.
2. **Metadata:** `issuerName`, `keyId`, and `renderId`.
   The service knows its own name. The `keyId` is redundant (wrong key fails at unseal).
   The `renderId` is in the `resourceJWT`.

Removing the issuerJWT eliminates one JWT signature verification per unlock request
and the SHA-256 proof computation on both publisher and service sides.

```text
// Before -- 6 fields + 2 JWTs
POST /api/unlock
{
  "resource": { "domain": "news.example.com", "resourceId": "...", ... },
  "resourceJWT": "eyJ...",
  "issuerJWT": "eyJ...",
  "sealed": { "bodytext": { "contentKey": "...", "periodKeys": { ... } } },
  "keyId": "issuer-key-1",
  "issuerName": "sesamy",
  "clientPublicKey": "..."   // optional
}

// After -- 1 field + 1 JWT
POST /api/unlock
{
  "resourceJWT": "eyJ...",
  "contentKeys": { "bodytext": { "contentKey": "...", "periodKeys": { ... } } },
  "clientPublicKey": "..."   // optional
}
```

The service auto-detects the format based on whether `resource` is
present in the request:

1. **Verify resourceJWT:** Decode the JWT payload (unverified) to get the
   domain for publisher key selection. Verify the signature with the looked-up key.
   This is standard JWT practice (same as OIDC).
2. **Unseal:** The service unseals the requested content keys using its
   configured private key. AES-GCM authentication ensures any tampered blob is
   rejected -- no proof hashes or keyId checks needed.

#### Backwards Compatibility

| Scenario | Works? | Notes |
| --- | --- | --- |
| Old client -> old service | Yes | No change |
| Old client -> v0.7 service | Yes | Service auto-detects old format, processes normally |
| v0.7 client -> v0.7 service | Yes | Minimal request, full security |
| v0.7 client -> old service | No | Old service requires `issuerJWT`, `resource`, `issuerName`, `sealed` |

**Recommended migration:** Upgrade the service first (accepts both formats),
then switch clients at your own pace.

### Standard JWT Claims in resourceJWT

[Backwards compatible]

#### Motivation

The previous `resourceJWT` uses custom field names (`domain`, `resourceId`, `issuedAt`, `renderId`) instead
of the well-known JWT claim names defined in RFC 7519. Using standard claims
improves interoperability and makes the JWT self-describing.

#### What Changed

The `resourceJWT` payload now uses standard JWT claim names:

| DcaResource field | JWT claim | RFC 7519 name | Notes |
| --- | --- | --- | --- |
| `domain` | `iss` | Issuer | The publisher that signed the JWT |
| `resourceId` | `sub` | Subject | The resource being accessed |
| `issuedAt` (ISO 8601) | `iat` | Issued At | Unix timestamp (seconds) instead of ISO string |
| `renderId` | `jti` | JWT ID | Unique per-render identifier |
| `data` | `data` | (custom) | Publisher-defined metadata, unchanged |

The decoded `resourceJWT` payload now looks like a standard JWT:

```jsonc
// resourceJWT payload (decoded)
{
  "iss": "news.example.com",       // domain
  "sub": "article-123",            // resourceId
  "iat": 1735689600,               // issuedAt (Unix seconds)
  "jti": "abc123def456",           // renderId
  "data": { "section": "politics"} // custom metadata
}
```

The page's `DcaData.resource` still uses the human-readable field names
(`domain`, `resourceId`, etc.) for debugging and display.
The mapping happens automatically when the publisher creates the JWT and when
the service verifies it.

#### Backwards Compatibility

Fully backwards compatible. The service detects the claim format automatically
(checking for `iss` vs `domain`). Both old and new resource
JWTs are accepted. No publisher or client changes are required.

### keyName: Decoupling Content Identity from Key Domain

[Backwards compatible]

#### Motivation

Previously, `contentName` serves three roles simultaneously:

1. **Content identity** -- uniquely identifies a content item within a resource (e.g. "bodytext", "sidebar")
2. **Key derivation salt** -- used as the HKDF salt for periodKey derivation
3. **Access control scope** -- the issuer grants access by contentName

This conflation forces publishers to use artificial names like "TierA" or
"premium" as their contentName, losing the ability to describe *what* the
content actually is. If a page has both a premium body and a premium sidebar, they
need different contentNames but the same access scope -- impossible before this change.

#### What Changed

`keyName` is an optional field on each content item that controls which key
domain that item belongs to. When set, HKDF uses `keyName` instead
of `contentName` as the salt, and the issuer can grant access
by `keyName` instead of listing individual content names.

| Role | Before | After (with keyName) |
| --- | --- | --- |
| Content identity | `contentName` | `contentName` (unchanged) |
| Key derivation salt | `contentName` | `keyName` (falls back to contentName) |
| Access control scope | `grantedContentNames` | `grantedKeyNames` (resolves via entry keyName) |

**Publisher -- before & after:**

```js
// Before: contentName = "TierA" (conflates identity with access scope)
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "TierA", content: body, contentType: "text/html" },
  ],
  issuers: [{
    issuerName: "sesamy",
    publicKeyPem, keyId, unlockUrl,
    contentNames: ["TierA"],
  }],
});

// After: contentName describes WHAT, keyName describes WHO can access
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", keyName: "premium", content: body, contentType: "text/html" },
    { contentName: "sidebar",  keyName: "premium", content: side, contentType: "text/html" },
  ],
  issuers: [{
    issuerName: "sesamy",
    publicKeyPem, keyId, unlockUrl,
    keyNames: ["premium"],           // seals all items with this keyName
  }],
});
```

**Wire format -- keyName on entries:**

Each `contentEncryptionKeys` entry carries its own `keyName`,
making it self-describing. The `keyName` is cryptographically bound
via seal AAD -- tampering causes unseal failure:

```jsonc
// issuerData entry (embedded in page)
{
  "contentEncryptionKeys": [
    { "contentName": "bodytext", "keyName": "premium", "contentKey": "sealed...", "periodKeys": [...] },
    { "contentName": "sidebar",  "keyName": "premium", "contentKey": "sealed...", "periodKeys": [...] }
  ]
}
```

When `keyName` is not explicitly set on a content item, it defaults
to `contentName`, so the simplest case requires no extra configuration.

**Issuer -- grantedKeyNames:**

The issuer's access decision can now use `grantedKeyNames` instead of
(or alongside) `grantedContentNames`:

```js
// Before: grant by content name
const result = await issuer.unlock(request, {
  grantedContentNames: ["bodytext", "sidebar"],
  deliveryMode: "periodKey",
});

// After: grant by key name -- resolves to all matching content items
const result = await issuer.unlock(request, {
  grantedKeyNames: ["premium"],    // grants both "bodytext" and "sidebar"
  deliveryMode: "periodKey",
});
```

**Client -- transparent handling:**

The client handles `keyName` transparently. Period keys are cached
by `keyName` instead of `contentName`, so unlocking any
"premium" article automatically caches the key for all other "premium" articles:

```js
const client = new DcaClient();
const page = client.parsePage();

// keyName is carried on each entry -- no separate mapping needed
const keys = await client.unlock(page, "sesamy");

// Decrypt by contentName -- keyName is resolved from the entries
const body = await client.decrypt(page, "bodytext", keys);
const side = await client.decrypt(page, "sidebar", keys);

// Period key cache is keyed by "premium" (the keyName),
// so navigating to another "premium" article skips the unlock call
```

#### Breaking Change

This is a breaking change -- the seal AAD now includes `keyName`,
so existing encrypted content must be re-rendered. When `keyName` is
omitted on a content item, it defaults to `contentName`.
The `contentKeyMap` field has been removed from the wire format.
The `resourceJWT` is now optional in unlock requests.

### Client Usage

```ts
import { DcaClient } from '@sesamy/capsule-client';

const client = new DcaClient();

const page = client.parsePage();
const response = await client.unlock(page, "sesamy");
const html = await client.decrypt(page, "bodytext", response);
```

### Service-Side Setup

The service accepts unlock requests with `resourceJWT` and `contentKeys`:

```ts
const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
  keyId: "2025-10",
  trustedPublisherKeys: {
    "news.example.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
  },
});

const result = await issuer.unlock(request, {
  grantedContentNames: ["bodytext"],
  deliveryMode: "contentKey",
});
```

### Summary

| Component | Change | Breaking? |
| --- | --- | --- |
| **Publisher** | No change | No |
| **Service** | Accepts resourceJWT + contentKeys | No |
| **Client** | Sends resourceJWT + contentKeys (legacy fields removed) | Yes -- legacy v1 format removed |
| **Wire format** | Only resourceJWT + contentKeys; legacy fields (issuerJWT, keyId, resource, issuerName, sealed) removed | Yes -- new format fails against pre-v0.7 services |

### Security

The simplified format provides **identical security**:

- **Publisher authentication:** The `resourceJWT` is ES256-signed
  by the publisher. The service verifies the signature against the trusted-publisher
  allowlist. Unchanged.
- **Content key integrity:** AES-GCM is authenticated encryption -- modifying
  any encrypted blob causes the unseal to fail with a GCM authentication error. The
  SHA-256 proof hashes in the issuerJWT were a redundant second integrity check.
- **Blob substitution:** Content keys are random per render. Substituting
  encrypted blobs from a different article gives you that article's keys, which cannot
  decrypt this article's content.
- **Domain lookup from JWT:** The service decodes the JWT payload (unverified)
  only for key selection, then fully verifies the signature. Standard JWT practice
  (same as OIDC providers).

### Breaking Changes

The following wire format changes are **not backwards compatible** with
pre-v0.7 services. Upgrade the service first, then switch clients.

| Old field | v0.7 status | Reason |
| --- | --- | --- |
| `resource` | Removed | Decoded from `resourceJWT` (the signed source of truth) |
| `issuerName` | Removed | The service already knows its own name |
| `issuerJWT` | Removed | SHA-256 integrity proofs are redundant -- AES-GCM authenticated encryption catches any tampered blob at unseal time |
| `keyId` | Removed | The service uses its configured key; a wrong key fails at AES-GCM unseal |
| `sealed` | Renamed to `contentKeys` | Describes *what* the data is (encrypted content keys) rather than *what was done to it* |

**v0.7 services accept both formats:** when `resource` is present the
request is treated as the old format (full validation including issuerJWT). When absent, it is
treated as the new format. The deprecated `sealed` field name is also accepted as a
fallback for `contentKeys`.
