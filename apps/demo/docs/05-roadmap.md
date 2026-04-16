# Roadmap

Future protocol and library improvements under consideration.
These are not yet implemented -- feedback is welcome.

## JWE for Issuer-Bound Key Wraps

[Under consideration]

When the publisher wraps keys for an issuer, `wrapEcdhP256()` produces a custom
binary blob stored in `DcaIssuerKey.contentKey` and `DcaWrappedIssuerWrapKey.key`:

    ephemeralPub (65 bytes) ‖ IV (12 bytes) ‖ AES-GCM ciphertext+tag

This is the ECDH-P256 issuer-bound wrap — distinct from `wrappedContentKey`
(the `{ kid, iv, ciphertext }` entries that wrap content keys under symmetric
wrapKeys via AES-GCM). Only the ECDH blob is in scope here.

The custom blob works but is non-standard. Replacing it with **JWE Compact
Serialization** ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516))
would give us:

- A well-known, auditable format instead of a custom byte layout
- Standard algorithm identifiers (`alg: ECDH-ES`, `enc: A256GCM`)
- Built-in algorithm agility through the `alg`/`enc` headers
- Interoperability with any JWE library (jose, node-jose, etc.)

```ts
// Current: DcaIssuerKey.contentKey / DcaWrappedIssuerWrapKey.key
"contentKey": "Base64url(ephemeralPub ‖ IV ‖ AES-GCM(derivedKey, plainKey))"

// Proposed JWE Compact Serialization (same fields)
"contentKey": "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6ey4uLn19..nonce.ciphertext.tag"
//                       header (alg, enc, epk)               .CEK. IV . ciphertext .tag
```

Mapping from the current blob to JWE fields:

| Current blob segment | JWE field |
| --- | --- |
| Ephemeral public key (65 bytes, uncompressed P-256) | `epk` in the JWE protected header (as JWK) |
| 12-byte AES-GCM nonce | JWE Initialization Vector (third segment) |
| AES-GCM ciphertext | JWE Ciphertext (fourth segment) |
| AES-GCM auth tag (last 16 bytes) | JWE Authentication Tag (fifth segment) |
| — (HKDF-derived, not transmitted) | JWE CEK (second segment, empty for ECDH-ES direct agreement) |

The same ECDH-ES + HKDF key derivation is used under the hood; the `epk`
moves into the JWE protected header and the remaining AES-GCM fields become
standard JWE segments.

## Standard JWT Claims for Share Link Tokens

[Under consideration]

Share link tokens currently use custom claim names (`domain`, `resourceId`, `type`) similar to the old resource JWTs.
The same RFC 7519 mapping applied to `resourceJWT` in v0.7 should be applied to share tokens:

| Current claim | Standard claim | Notes |
| --- | --- | --- |
| `domain` | `iss` | Publisher that signed the token |
| `resourceId` | `sub` | Resource being shared |
| `type: "dca-share"` | JWT header `typ: "dca-share+jwt"` | Distinguishes from resource JWTs without a payload claim |

This aligns all publisher-signed JWTs (resource + share) under the same conventions
and allows reusing the same verification code path.

## Structured Error Types

[Under consideration]

Currently, callers distinguish error kinds by parsing `error.message` strings
(e.g. `error.message.includes("not trusted")`). This is fragile --
message text can change between versions.

Instead, the library should expose typed error subclasses with a stable `code` property:

```ts
// Proposed error hierarchy
class DcaError extends Error {
  code: string;
}

class DcaUntrustedPublisherError extends DcaError {
  code = "UNTRUSTED_PUBLISHER";
  domain: string;
}

class DcaKeyMismatchError extends DcaError {
  code = "KEY_MISMATCH";
  expected: string;
  received: string;
}

class DcaUnwrapError extends DcaError {
  code = "UNWRAP_FAILED";
  algorithm: string;
}

// Callers can now match on stable codes
try {
  await issuer.unlock(request, decision);
} catch (err) {
  if (err instanceof DcaUntrustedPublisherError) {
    // handle untrusted publisher
  }
  // or match on err.code === "UNTRUSTED_PUBLISHER"
}
```

## Rename `DcaSealedContentKey.t` Field

[Under consideration]

The `DcaSealedContentKey` type uses a single-character field name `t` for the time bucket identifier:

```jsonc
// Current wire format
"sealedContentKeys": {
  "bodytext": [
    { "t": "2025-06-d", "nonce": "...", "key": "..." },
    { "t": "2025-06-d-12", "nonce": "...", "key": "..." }
  ]
}
```

The abbreviated name saves a few bytes per entry but hurts readability and
discoverability. Two options:

1. **Rename to `timeBucket`** -- explicit and self-documenting.
   Costs ~10 extra bytes per entry (negligible in practice).
2. **Switch to array format** -- use `[timeBucket, nonce, key]` tuples
   instead of objects. Smaller wire size than either naming option and positional semantics
   are unambiguous given the fixed schema.
