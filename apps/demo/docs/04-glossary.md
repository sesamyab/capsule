# Capsule Cryptography Glossary

Understanding the cryptographic concepts and key hierarchy used in Capsule.

## Contents

- [Key Hierarchy](#key-hierarchy)
- [Encryption Algorithms](#encryption-algorithms)
- [Key Derivation](#key-derivation)
- [Key Wrapping](#key-wrapping)
- [Time Periods & Rotation Versions](#time-periods)
- [DCA (Delegated Content Access)](#dca)
- [JWT Signing & Integrity Proofs](#jwt-integrity)

## Key Hierarchy

### Rotation Secret

The root secret from which all wrap keys are derived. Stored securely on the publisher's server (ideally in a KMS like AWS Secrets Manager, HashiCorp Vault, etc.). Called `rotationSecret` in the codebase.

- Size: 256 bits
- Storage: Server-side only
- Rotation: Rarely (causes key migration)

Never expose the rotation secret to clients or embed it in client code.

### Wrap Key

A time-derived AES-256 key that wraps (encrypts) the content key. Derived from the rotation secret using HKDF with a rotation version label as context. Clients can cache wrap keys to enable offline access and "unlock once, access all" within a time window.

- Algorithm: AES-256
- Purpose: Wrap content keys
- Scope: Per-scope, per-rotation-version
- Client caching: Yes (enables offline access)

In the DCA model, wrap keys are scope-specific by construction -- the scope is used as the HKDF salt, so items in different scopes produce different wrap keys even for the same rotation version. Items sharing a scope share a wrap key.

```
// Wrap key derivation (DCA)
wrapKey = HKDF(
  IKM:  rotationSecret,
  salt: "premium",           // scope
  info: "dca|251023T13",     // "dca|" + kid
  len:  32                   // AES-256
)
```

### Content Key

The key that actually encrypts article content. Each article (or content item) gets its own unique content key, generated randomly at encryption time. In envelope encryption terminology this is the Data Encryption Key (DEK).

- Algorithm: AES-256-GCM
- Purpose: Encrypt content
- Scope: Per-article / per-content-item
- Generation: Random (crypto.getRandomValues)

The content key is wrapped with one or more wrap keys and stored alongside the encrypted content. Clients unwrap the content key using a wrap key they received from the issuer.

```
// Content key usage
contentKey = randomBytes(32)
ciphertext = AES-GCM(contentKey, plaintext, iv, aad)
wrappedKey = AES-GCM(wrapKey, contentKey, wrapIv)
```

### Issuer Key Pair

Each issuer (subscription provider) holds an asymmetric key pair used for **wrapping**. The publisher encrypts content keys and wrap keys with the issuer's public key so only that issuer can unwrap them.

- Algorithm: ECDH P-256 or RSA-OAEP
- Storage: Issuer server
- Purpose: Key wrapping / unwrapping

ECDH P-256 is the preferred algorithm for DCA. Each wrap operation generates a fresh ephemeral key pair, producing a self-contained blob that only the issuer's private key can decrypt.

### Publisher Signing Key

An ECDSA P-256 key pair used by the publisher to sign JWTs (ES256). The publisher signs a `resourceJWT` and per-issuer `issuerJWT`s. Issuers verify these signatures using the publisher's public key (looked up by domain).

- Algorithm: ECDSA P-256 (ES256)
- Storage: Publisher server (private key)
- Purpose: JWT signing & verification

## Encryption Algorithms

### AES-256-GCM

Symmetric authenticated encryption (AEAD). AES-256-GCM is used for both content encryption and key wrapping in Capsule. It provides confidentiality *and* authenticity in a single operation.

- Key size: 256 bits
- IV size: 96 bits (12 bytes)
- Auth tag: 128 bits
- AAD: Optional (used in DCA)

In the DCA model, content encryption includes **Additional Authenticated Data (AAD)** that binds the ciphertext to its context -- preventing content from being relocated to a different page or domain.

### AAD (Additional Authenticated Data)

An AES-GCM feature that authenticates extra context alongside the ciphertext. The AAD is not encrypted, but decryption will fail if the AAD provided at decrypt time doesn't match what was used at encrypt time. Capsule uses AAD in two layers to prevent both content relocation and cross-resource key substitution attacks.

**Content AAD** binds encrypted content to its resource context. If an attacker moves ciphertext to a different page or domain, decryption fails because the AAD no longer matches.

**Wrap AAD** binds wrapped key material (content keys and wrap keys) to the access tier via the `scope`. This prevents an attacker from substituting wrapped keys between tiers -- unwrapping will fail because the `scope` AAD won't match.

- Content AAD: `domain|resourceId|contentName|scope`
- Wrap AAD: `scope`
- Encoding: UTF-8 bytes
- Storage: Content AAD in content[name].aad, Wrap AAD from entry scope

```
// Content AAD — binds ciphertext to its resource context
contentAad = "www.news-site.com|article-123|bodytext|premium"

// Encrypt content with content AAD
ciphertext = AES-GCM(contentKey, plaintext, iv, contentAad)

// Decrypt — must provide the same content AAD
plaintext = AES-GCM-Decrypt(contentKey, ciphertext, iv, contentAad)
// Fails if AAD doesn't match → prevents content relocation

// Wrap AAD — binds wrapped key material to the access tier
wrappedContentKey = wrap(contentKey, issuerPubKey, algorithm, encodeUtf8(scope))
wrappedWrapKey    = wrap(wrapKey, issuerPubKey, algorithm, encodeUtf8(scope))
// Unwrapping fails if scope doesn't match → prevents cross-tier key substitution
```

**Why two layers?** Content AAD protects the ciphertext -- it ensures encrypted content cannot be moved to a different page. Wrap AAD is scope-only (implemented as `encodeUtf8(scope)`) and therefore prevents cross-tier or cross-scope key substitution, but does not by itself provide full cross-resource binding. Full end-to-end binding from key material through to ciphertext requires additional context or mechanisms beyond the scope-only Wrap AAD.

### ECDH P-256 (Elliptic Curve Diffie-Hellman)

Asymmetric key agreement used for **wrapping** key material for issuers. For each wrap operation a fresh ephemeral key pair is generated, and the shared secret is used directly as an AES-256-GCM key.

- Curve: P-256 (secp256r1)
- Shared secret: 32 bytes (x-coordinate)
- Ephemeral: Fresh key per wrap

```
// ECDH P-256 wrapped blob format
| 0-64  | Ephemeral public key (65 bytes, uncompressed) |
| 65-76 | AES-GCM IV (12 bytes)                         |
| 77+   | Ciphertext + 16-byte GCM auth tag             |
```

### RSA-OAEP

Asymmetric encryption using RSA with Optimal Asymmetric Encryption Padding. Used as an alternative wrapping algorithm for DCA issuers.

- Key size: 2048+ bits
- Padding: OAEP
- Hash: SHA-256
- Max payload: ~190 bytes (2048-bit key)

### ECDSA P-256 (ES256)

Elliptic curve digital signature algorithm used for signing DCA JWTs. The publisher signs `resourceJWT` and `issuerJWT` tokens with ES256; issuers verify them before unwrapping keys.

- Curve: P-256
- Hash: SHA-256
- Signature: 64 bytes (IEEE P1363 format, r||s)
- JWT header: `{"alg":"ES256","typ":"JWT"}`

## Key Derivation

### HKDF (HMAC-based Key Derivation Function)

RFC 5869 standard for deriving cryptographic keys from a master secret. Capsule uses HKDF-SHA256 to derive wrap keys from the rotation secret.

- Hash: SHA-256
- Input: Rotation secret + context
- Output: 256-bit keys

```
// DCA wrap key derivation
wrapKey = HKDF-SHA256(
  IKM:  rotationSecret,
  salt: scope,              // e.g., "premium"
  info: "dca|251023T13",    // "dca|" + kid (rotation version)
  len:  32
)
```

In the DCA model, the `salt` is the scope, making wrap keys scope-specific by construction. The `info` parameter encodes the kid (rotation version), ensuring each rotation window gets a unique key.

### Time-Based Key Rotation

Capsule rotates keys automatically using rotation versions. Each rotation version has its own derived key, providing forward secrecy -- old wrap keys can't decrypt future content.

- Hourly rotation versions (YYMMDDTHH format)
- Window: Current + next rotation version always available

```
// kid (rotation version) format
"251023T13"     // Oct 23, 2025 at 13:00 UTC (hourly)
"251023T1430"   // Sub-hour variant (30-min)
```

## Key Wrapping

### Content Key Wrapping

The content key is wrapped (encrypted) with a wrap key using AES-256-GCM. Each article stores multiple wrapped copies of its content key -- one per active rotation version -- so clients can unwrap using whichever wrap key they have cached.

- Algorithm: AES-256-GCM
- IV: Unique 12-byte IV per wrap
- Wrapped copies: 2 (current + next rotation version)

```
// DCA wrappedContentKey structure (per content item)
content: {
  "bodytext": {
    wrappedContentKey: [
      { kid: "251023T13", iv: "...", ciphertext: "..." },
      { kid: "251023T14", iv: "...", ciphertext: "..." }
    ],
    ...
  }
}
```

### Issuer Wrapping

Key material (content keys and wrap keys) is **wrapped** with the issuer's public key. Only the issuer holding the matching private key can unwrap them. Each issuer gets its own wrapped copies, enabling multi-issuer support. Wrapped blobs include AAD binding via the `scope`, which ties the wrapped key material to a specific access tier and prevents cross-tier key substitution.

- ECDH P-256: Ephemeral key per wrap
- RSA-OAEP: Standard ciphertext
- Auto-detection: From PEM key type
- AAD: scope (UTF-8 encoded)

```
// Issuer wrapped structure
issuers: {
  "sesamy": {
    keys: [
      {
        contentName: "bodytext",
        scope: "premium",
        contentKey: "base64url...",   // wrapped with issuer pubkey + scope AAD
        wrapKeys: [
          { kid: "251023T13", key: "base64url..." },
          { kid: "251023T14", key: "base64url..." }
        ]
      }
    ],
    unlockUrl: "https://api.sesamy.com/unlock",
    keyId: "2025-10"
  }
}
```

### Envelope Encryption

The pattern of encrypting data with a content key, then wrapping the content key with a wrap key. This enables "unlock once, access all" -- a single wrap key can unwrap the content key for any article encrypted in that rotation window.

- Content encrypted with random content key (fast, symmetric)
- Content key wrapped with wrap key (enables time-based access)
- Wrap key wrapped with issuer's public key (delegated access)

## Time Periods & Rotation Versions

### Why Rotation Versions?

Rotation versions provide several security benefits:

- **Forward Secrecy:** Old wrap keys can't decrypt new content. If a key is compromised, only that rotation version's content is at risk.
- **Automatic Revocation:** Keys expire naturally. No need to maintain revocation lists.
- **Subscription Enforcement:** Users must have an active subscription to get current wrap keys.

### Rotation Duration Selection

| Rotation | Use Case | Trade-offs |
| --- | --- | --- |
| 30 seconds | Demo/testing | Frequent rotation visible, more server requests |
| 1 hour | News sites (DCA default) | Balance of security and UX |
| 24 hours | Magazines | Daily access pattern, minimal overhead |
| 30 days | Monthly subscriptions | Aligns with billing cycle |

### Clock Drift Handling

To handle clock differences between publisher and client, Capsule always encrypts content keys with both the current *and* next wrap key. This ensures content remains accessible during the transition between rotation versions.

- Publisher wraps content key with current + next wrap keys
- Client tries each wrapped key until one succeeds
- Wrap key cache uses the kid (rotation version) as key

## DCA (Delegated Content Access)

### What is DCA?

DCA is an open standard for encrypted content delivery with multi-issuer support. It separates the roles of **publisher** (encrypts content), **issuer** (manages access), and **client** (decrypts content).

- **Publisher:** Encrypts content at build time, wraps keys for each issuer, signs JWTs
- **Issuer:** Verifies JWTs, checks integrity proofs, makes access decisions, unwraps and returns keys
- **Client:** Parses DCA manifest from the page, calls an issuer's unlock endpoint, decrypts content

### Multiple Content Items

A single page can contain multiple named content items (e.g., `"bodytext"`, `"sidebar"`, `"data"`). Each item gets its own content key, IV, AAD, and wrapped copies. Issuers can grant access to a subset of items per request.

```
// Multiple content items
contentItems: [
  { contentName: "bodytext", content: "<p>Article...</p>" },
  { contentName: "sidebar", content: "<aside>Premium ...</aside>" },
  { contentName: "data",    content: '{"stats": [...]}',
    contentType: "application/json" }
]
```

### Key Delivery Modes

When a client requests access, the issuer can return keys in two modes:

- **contentKey mode:** Returns the raw content key directly. Simplest path -- client decrypts immediately.
- **wrapKey mode:** Returns wrap keys that the client uses to unwrap the content key from `wrappedContentKey`. Enables client-side caching: a cached wrap key can unlock any article in the same scope and rotation window.

### Wire Format (HTML)

The DCA manifest is embedded in the page as standard HTML elements:

```
<!-- DCA manifest (ciphertext lives inline under manifest.content[name]) -->
<script type="application/json" class="dca-manifest">
  {
    "version": "0.10",
    "resourceJWT": "...",
    "content": {
      "bodytext": { "contentType": "text/html", "iv": "...", "aad": "...", "ciphertext": "base64url_ciphertext...", "wrappedContentKey": [...] },
      "sidebar":  { "contentType": "text/html", "iv": "...", "aad": "...", "ciphertext": "base64url_ciphertext...", "wrappedContentKey": [...] }
    },
    "issuers": {...}
  }
</script>

<!-- Placeholders in the rendered DOM where decrypted content gets injected -->
<div data-dca-content-name="bodytext">placeholder</div>
<div data-dca-content-name="sidebar">placeholder</div>
```

## JWT Signing & Integrity Proofs

### resourceJWT

An ES256 JWT signed by the publisher containing resource metadata. Shared across all issuers. The issuer verifies this JWT to confirm the request originates from a trusted publisher.

```
// resourceJWT payload (standard JWT claims)
{
  "iss": "www.news-site.com",        // publisher domain
  "sub": "article-123",              // resource ID
  "iat": 1698062400,                 // render timestamp (Unix seconds)
  "jti": "base64url...",             // render ID (binds wrapped keys)
  "scopes": ["premium"],             // required entitlements
  "data": { "section": "politics" }  // access metadata
}
```

### issuerJWT

A per-issuer ES256 JWT containing SHA-256 integrity proofs of every wrapped blob for that issuer. The issuer verifies these hashes before unwrapping, ensuring the wrapped keys haven't been tampered with in transit.

```
// issuerJWT payload
{
  "jti": "base64url...",               // must match resourceJWT jti
  "issuerName": "sesamy",
  "proof": {
    "premium": {
      "contentKey": "sha256_hash...",  // hash of wrapped blob
      "wrapKeys": {
        "251023T13": "sha256_hash...",
        "251023T14": "sha256_hash..."
      }
    }
  }
}
```

### SHA-256 Integrity Proofs

Each wrapped blob's base64url string is hashed with SHA-256 and included in the issuerJWT. Before unwrapping, the issuer recomputes the hashes and compares them -- any mismatch indicates tampering and the request is rejected.

```
// Proof hash computation
proofHash = base64url(SHA-256(utf8_bytes_of_base64url_string))

// Note: hashes the base64url STRING as UTF-8 bytes,
// not the decoded binary data
```

### renderId (Binding Token)

A random base64url string (16 bytes) generated fresh each render, carried as the `jti` claim in both the `resourceJWT` and `issuerJWT` payloads. The issuer verifies they match -- binding the two JWTs together and preventing replay of mismatched tokens.
