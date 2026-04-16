# Roadmap

Future protocol and library improvements under consideration.
These are not yet implemented -- feedback is welcome.

## JWE for Sealed Key Blobs

[Under consideration]

The current seal format is a custom binary blob: ephemeral public key || nonce || ciphertext.
This works but is non-standard. Replacing it with **JWE Compact Serialization** ([RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)) would give us:

- A well-known, auditable format instead of a custom byte layout
- Standard algorithm identifiers (`alg: ECDH-ES`, `enc: A256GCM`)
- Built-in algorithm agility through the `alg`/`enc` headers
- Interoperability with any JWE library (jose, node-jose, etc.)

```ts
// Current custom format
"sealed": "Base64url(ephemeralPub ‖ nonce ‖ AES-GCM(sharedSecret, plainKey))"

// Proposed JWE Compact Serialization
"sealed": "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6ey4uLn19.    .nonce.ciphertext.tag"
//               header          .CEK.  IV  . ciphertext .tag
```

The `epk` (ephemeral public key) moves into the JWE protected header,
and AES-GCM nonce/ciphertext/tag are standard JWE fields. The same ECDH-ES +
HKDF key derivation is used under the hood.

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

class DcaUnsealError extends DcaError {
  code = "UNSEAL_FAILED";
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
