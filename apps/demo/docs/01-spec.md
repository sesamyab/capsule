# Specification

Capsule is an open standard for client-side article encryption using
envelope encryption. It enables secure content delivery without
requiring server-side authentication or permission systems.

## Architecture Overview

Capsule uses the **Delegated Content Access (DCA)** protocol, which separates content encryption (publisher) from access control (issuer). The publisher encrypts content with AES-256-GCM and wraps keys for each issuer using ECDH P-256. Issuers unwrap keys only when access is granted, and the client decrypts content locally in the browser.

### Roles

| Role | Responsibility |
| --- | --- |
| **Publisher** | Encrypts content at render time. Wraps per-content keys for each issuer with ECDH P-256, using `scope` as wrap AAD. Signs a `resourceJWT` (ES256) binding metadata. |
| **Issuer** | Owns an ECDH P-256 key pair. On unlock, reads `scope` from each entry, unwraps keys using `scope` as wrap AAD, and returns them to the client. Optionally verifies `resourceJWT` for publisher trust. |
| **Client** | Parses DCA data from the page, calls the issuer's unlock endpoint, receives keys, and decrypts content locally with AES-256-GCM. |

## Encryption Flow

### Content Encryption

The publisher generates a random **contentKey** (256-bit AES) and optional rotating **wrapKeys** per content item, then encrypts content with AES-256-GCM using a random iv and an AAD string. The contentKey is additionally wrapped with each wrapKey so the issuer can grant either content-level or rotation-version-level access.

```
// Publisher render (server-side)
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", content: "<p>Premium content…</p>" },
  ],
  issuers: [
    {
      issuerName: "sesamy",
      publicKeyPem: ISSUER_ECDH_PUBLIC_KEY_PEM,
      keyId: "issuer-key-1",
      unlockUrl: "https://issuer.example.com/api/unlock",
      contentNames: ["bodytext"],
    },
  ],
});

// result.html.dcaManifestScript → <script class="dca-manifest">…</script>
```

### Key Wrapping (Publisher -> Issuer)

For each issuer, the publisher uses **ECDH P-256** key agreement to derive a shared secret, then wraps the contentKey and wrapKeys with AES-256-GCM. The resulting opaque blobs are stored in `issuers`. Only the matching issuer private key can unwrap them.

```
// Wrapping internals (automatic during render)
// 1. Ephemeral ECDH P-256 key pair generated per wrap operation
// 2. ECDH shared secret derived: ephemeralPrivate × issuerPublic
// 3. HKDF-SHA256(secret, salt="dca-wrap", info="dca-wrap-aes256gcm") → 256-bit wrapping key
// 4. AES-256-GCM wrap each key with a unique 12-byte iv
//    AAD = scope (binds wrapped blob to this access tier)
// 5. Wrapped blob = ephemeralPublicKey(65B) ‖ iv(12B) ‖ ciphertext+tag
```

### Wrap AAD (Additional Authenticated Data)

When wrapping contentKeys and wrapKeys for issuers, the publisher passes the `scope` (access tier) as AAD to the AES-GCM encryption (for ECDH P-256 wrapping) or as the RSA-OAEP label (for RSA-based wrapping). This cryptographically binds each wrapped key blob to its access tier.

On unlock, the issuer reads `scope` from each entry and provides it as AAD when unwrapping. If the `scope` has been tampered with, AES-GCM decryption fails with an authentication error.

**Why this matters:** Wrap AAD prevents *cross-tier key substitution attacks*. Without it, an attacker could change `scope` from "free" to "premium" on a wrapped entry, tricking the issuer into unwrapping keys for a tier they don't have access to. With wrap AAD, the wrapped blobs are bound to the original `scope` and cannot be unwrapped under a different tier.

```
// Wrap AAD binding
// Publisher (during render):
//   wrappedBlob = AES-256-GCM-Encrypt(wrappingKey, contentKey, iv, aad=scope)
//
// Issuer (during unlock):
//   1. Read scope from each keys entry
//   2. contentKey = AES-256-GCM-Decrypt(wrappingKey, wrappedBlob, iv, aad=scope)
//   3. If scope was tampered with → GCM auth tag check fails → reject
```

### Integrity Protection

Integrity of wrapped key blobs is guaranteed by **wrap AAD** rather than a separate `issuerJWT`. The `scope` (from each wrapped-key entry) is used as AAD during AES-GCM wrapping, so any substitution or tampering of wrapped blobs causes a GCM authentication failure at unwrap time. This replaces the older approach of signing per-issuer SHA-256 hash proofs in a separate JWT.

```
// Integrity: wrap AAD binds keys to access tier
//
// Old approach (deprecated): publisher signed an issuerJWT with SHA-256 hashes of wrapped blobs
//   → issuer verified hashes before unwrapping
//
// Current approach: publisher passes scope as AAD during AES-GCM wrapping
//   → issuer provides scope (from each entry) as AAD during unwrapping
//   → GCM authentication tag rejects any blob wrapped for a different tier
//
// Result: each entry is self-describing and tamper-proof, no separate mapping needed
```

### DCA HTML Embedding

The DCA manifest is embedded in a single `<script>` tag. It holds all metadata, the `resourceJWT`, wrapped keys, and the encrypted content ciphertext inline under each `content[name]` entry. The target elements on the page (e.g. `<div data-dca-content-name="bodytext"></div>`) are empty placeholders that the client fills in after decryption.

```html
<!-- DCA manifest: metadata + wrapped keys + ciphertext -->
<script type="application/json" class="dca-manifest">
{
  "version": "0.10",
  "resourceJWT": "eyJ…",
  "content": {
    "bodytext": {
      "contentType": "text/html",
      "iv": "…",
      "aad": "…",
      "ciphertext": "base64url-encrypted-content…",
      "wrappedContentKey": [
        { "kid": "251023T13", "iv": "…", "ciphertext": "…" }
      ]
    }
  },
  "issuers": {
    "sesamy": {
      "unlockUrl": "https://issuer.example.com/api/unlock",
      "keyId": "issuer-key-1",
      "keys": [
        {
          "contentName": "bodytext",
          "scope": "premium",
          "contentKey": "base64url-wrapped-blob",
          "wrapKeys": [
            { "kid": "251023T13", "key": "base64url-wrapped-blob" }
          ]
        }
      ]
    }
  }
}
</script>

<!-- Target placeholder (filled in by the client after decryption) -->
<div data-dca-content-name="bodytext"></div>
```

### Unlock Flow

When the client calls the issuer's unlock endpoint, the issuer performs a multi-step verification before returning keys:

1. Optionally verify `resourceJWT` signature (ES256) using the publisher's public key, looked up by `resource.domain`. The lookup is either a pinned PEM keyed by domain, or — when the issuer is JWKS-configured — a `kid`-indexed lookup against the JWKS at the publisher's `.well-known/dca-publishers.json` (see [Publisher Key Resolution](#publisher-key-resolution-jwks)).
2. Read `scope` from each `keys` entry.
3. Unwrap keys using the issuer's ECDH private key, providing `scope` as AAD (GCM auth tag validates the blob was wrapped for this access tier).
4. Return keys to the client -- either as plaintext (direct) or RSA-OAEP wrapped (client-bound).

```
// Client → Issuer
POST /api/unlock
{
  "resourceJWT": "eyJ…",             // optional — for publisher trust verification
  "keys": [
    {
      "contentName": "bodytext",
      "scope": "premium",             // AAD-bound access tier
      "contentKey": "base64url-wrapped-blob",
      "wrapKeys": [
        { "kid": "251023T13", "key": "base64url-wrapped-blob" }
      ]
    }
  ],
  "clientPublicKey": "base64url-SPKI-RSA-public-key"   // ← enables client-bound mode
}

// Issuer verification:
// 1. Optionally verify resourceJWT → extract domain, resourceId
// 2. Unwrap each key blob with ECDH private key + scope as AAD
//    (mismatched scope → GCM auth failure → reject)
// 3. Return keys

// Issuer → Client (one delivery form per entry)
//   deliveryMode: "direct"  → returns contentKey only
//   deliveryMode: "wrapKey" → returns wrapKeys only (cacheable, 1-hour rotation versions)
{
  "keys": [
    { "contentName": "bodytext", "scope": "premium", "contentKey": "base64url-key-or-wrapped-key" }
  ],
  "transport": "client-bound"    // or "direct" (default)
}
// — or with wrapKey delivery —
{
  "keys": [
    {
      "contentName": "bodytext",
      "scope": "premium",
      "wrapKeys": [
        { "kid": "251023T13", "key": "base64url-key-or-wrapped-key" }
      ]
    }
  ]
}
```

### Transport Modes

DCA deliberately leaves the issuer -> client transport unspecified. Capsule implements two modes:

| Mode | Key Delivery | Security | Best For |
| --- | --- | --- | --- |
| **Direct** | Plaintext base64url keys in HTTPS response | TLS only -- keys visible in server logs, CDN edges, DevTools | Simple deployments, trusted infrastructure |
| **Client-bound** | RSA-OAEP wrapped with client's browser public key | End-to-end -- only the originating browser can unwrap | High-security content, zero-trust environments |

### Client-Bound Transport

Client-bound transport adds an RSA-OAEP encryption layer on the issuer -> client leg. The client generates an RSA key pair once and stores the **non-extractable** private key in IndexedDB. The public key is sent with every unlock request.

#### Key Pair Lifecycle

```
// DcaClient with client-bound transport enabled
const client = new DcaClient({
  clientBound: true,       // Enable RSA key wrapping
  rsaKeySize: 2048,        // RSA modulus length (default: 2048)
  keyDbName: "dca-keys",   // IndexedDB database name
});

// First unlock triggers key pair generation:
// 1. crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, … })
// 2. Private key re-imported as non-extractable (extractable: false)
// 3. Key pair stored in IndexedDB

// Subsequent visits: key pair loaded from IndexedDB automatically
```

#### Wrapping Flow

```
// Client-bound unlock sequence:

// 1. Client includes RSA public key in unlock request
POST /api/unlock {
  …dcaFields,
  "clientPublicKey": "base64url(SPKI-encoded RSA-OAEP public key)"
}

// 2. Issuer unwraps keys normally, then wraps each with client's public key
for each key in unwrappedKeys:
  wrappedKey = RSA-OAEP-Encrypt(clientPublicKey, rawKeyBytes)
  response.keys[contentName][keyType] = base64url(wrappedKey)
response.transport = "client-bound"

// 3. Client receives wrapped keys — opaque ciphertext, useless without private key
// 4. Client unwraps each key with its non-extractable private key
rawKey = RSA-OAEP-Decrypt(privateKey, wrappedKeyBytes)
// → AES-256 key material, ready for content decryption
```

#### Security Properties of Client-Bound Transport

- **End-to-end encryption:** Key material is never in plaintext outside the browser's crypto engine
- **Non-extractable private key:** Even XSS or DevTools cannot read the raw RSA private key bytes
- **Server-side opacity:** The issuer sees only the client's public key -- it cannot observe which keys the client actually uses
- **Replay resistance:** Wrapped keys are bound to one browser's key pair
- **Backward compatible:** If `clientPublicKey` is absent, the issuer falls back to direct transport
- **Device-bound:** Keys cannot be transferred between browsers/devices (by design)

### Client-Side Decryption

After receiving keys (direct or unwrapped), the client decrypts content using AES-256-GCM with the original iv and AAD from `content[name]`:

```
// 1. Parse DCA manifest from the page
const page = client.parsePage();

// 2. Unlock via issuer (sends wrapped keys + optional clientPublicKey)
const response = await client.unlock("sesamy");

// 3. Decrypt content (handles unwrapping if client-bound)
const html = await client.decrypt("sesamy", "bodytext", response);

// 4. Replace placeholder with decrypted content
document.querySelector('[data-dca-content-name="bodytext"]')
  .innerHTML = html;
```

### Handling Decrypted Content in Scripts

Since content is decrypted client-side *after* the initial page load, any scripts that need to process the content (syntax highlighting, analytics, interactive widgets, etc.) must run after decryption completes. There are two approaches:

#### Option A: Listen for the `capsule:unlocked` Event

Capsule dispatches a custom event when content is decrypted and added to the DOM:

```js
document.addEventListener("capsule:unlocked", (event) => {
  const { resourceId, element, keyId } = event.detail;
  
  // element is the DOM container with the decrypted content
  // Run your initialization code here
  highlightCodeBlocks(element);
  initializeWidgets(element);
  
  console.log(`Article "${resourceId}" unlocked with key: ${keyId}`);
});
```

#### Option B: Use a MutationObserver

For more generic DOM change detection, use a `MutationObserver`:

```js
const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node instanceof HTMLElement) {
        // Check if this is unlocked content
        if (node.classList.contains("premium-content")) {
          initializeContent(node);
        }
      }
    }
  }
});

// Observe the container where encrypted sections appear
observer.observe(document.body, { 
  childList: true, 
  subtree: true 
});
```

## Publisher Key Resolution (JWKS)

The issuer needs the publisher's ES256 public key to verify `resourceJWT` (and share link tokens). Two resolution strategies are supported, symmetric to how publishers resolve issuer encryption keys:

| Strategy | When it fits |
| -------- | ------------ |
| `signingKeyPem` (pinned) | Small deployments where you control both sides. Publisher key rotation requires updating every issuer's config. |
| `jwksUri` (discovery) | Multiple issuers trust the same publisher, or rotation automation matters. Issuer fetches the JWKS once, caches it, and force-refreshes on unknown kid. |

### Publisher JWKS Endpoint

Publishers publishing via JWKS serve an [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) document at `.well-known/dca-publishers.json` on their domain. A typical document:

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "use": "sig",
      "alg": "ES256",
      "kid": "sig-2026-04",
      "x": "…",
      "y": "…"
    }
  ]
}
```

When publishing via JWKS, the publisher also sets a `kid` header on every signed JWT so the issuer can pick the right key:

```
{"alg":"ES256","typ":"JWT","kid":"sig-2026-04"}
```

During a rotation, the publisher includes both keys in the JWKS (old + new) and switches signing to the new `kid`. Issuers verify against whichever kid the JWT advertises.

### JWKS Selection Rules

A JWKS entry is considered active for publisher signing when:

- `kid` is present
- `kty` is `EC` with `crv: "P-256"` (ES256)
- `use` is `"sig"` or absent
- `status` is not `"retired"` (non-standard, honored if present)

RSA signing keys are not supported -- DCA signatures are fixed to ES256.

### Force-Refresh on Unknown Kid

When the JWT header carries a `kid` that isn't in the issuer's cached JWKS, the issuer force-refreshes the JWKS once before failing. This handles the common case where a publisher rotated between the last cache fetch and now. If the kid is still missing after refresh, verification fails with a clear error.

### Backwards Compatibility

JWTs without a `kid` header continue to work against `signingKeyPem`-pinned publishers unchanged. JWKS-configured publishers that don't set `signingKeyId` on their publisher instance produce kid-less JWTs too, which fall back to "the only active key in the JWKS" -- handy for single-key setups but ambiguous during rotation overlap. Setting `signingKeyId` is strongly recommended for any JWKS-configured publisher.

## Share Link Tokens

Share links allow pre-authenticated access to premium content without requiring the recipient to have a subscription. This enables social media sharing, email distribution, and promotional campaigns.

### DCA-Compatible Design

The critical design insight: a share link token is **purely an authorization grant**, not a key-delivery mechanism. The publisher's `rotationSecret` never leaves the publisher. Key material flows through the normal DCA wrap/unwrap channel -- the wrapped keys are already embedded in the page's DCA manifest, and the issuer unwraps them as usual.

This is DCA-compatible because the issuer never needs the publisher's `rotationSecret`. The publisher creates a signed JWT that says "this bearer may access these content items for this resource." The issuer validates the token signature (the publisher already has a trusted signing key in the allowlist), uses the token's claims as the access decision, and returns unwrapped keys from the normal DCA manifest.

```
// Share Link Flow (DCA-compatible)
//
// 1. Publisher signs a share token (ES256 JWT) granting access
// 2. User clicks the share link → loads page with normal DCA-wrapped content
// 3. Client includes the share token in the unlock request
// 4. Issuer verifies token (publisher-signed, trusted key) → access decision
// 5. Issuer unwraps keys from normal DCA manifest → returns to client
// 6. Client decrypts content locally
//
// Key insight: rotationSecret never leaves the publisher.
// The token is authorization only — key material uses normal DCA channels.
```

### Token Structure

Share link tokens are ES256 (ECDSA P-256) signed JWTs, using the same publisher signing key that signs `resourceJWT`. The issuer already trusts this key via its `trustedPublisherKeys` allowlist.

```
// DcaShareLinkTokenPayload (ES256 JWT payload)
{
  "type": "dca-share",                // Type discriminator
  "domain": "news.example.com",       // Publisher domain (must match resource)
  "resourceId": "article-123",        // Resource this token grants access to
  "contentNames": ["bodytext"],        // Content items to unlock
  "iat": 1707400800,                  // Issued at (Unix timestamp)
  "exp": 1708005600,                  // Expires at (Unix timestamp)
  "maxUses": 100,                     // Optional: usage limit (advisory)
  "jti": "share-abc123",              // Optional: unique ID (for tracking/revocation)
  "data": { "campaign": "twitter" }   // Optional: publisher-defined metadata
}
```

### Token Generation (Publisher)

The publisher creates share tokens using the same `createDcaPublisher` instance that renders pages:

```js
import { createDcaPublisher } from '@sesamy/capsule-server';

const publisher = createDcaPublisher({
  domain: "news.example.com",
  signingKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY!,
  rotationSecret: process.env.ROTATION_SECRET!,
});

// Generate a share link token
const token = await publisher.createShareLinkToken({
  resourceId: "article-123",
  contentNames: ["bodytext"],
  expiresIn: 7 * 24 * 3600,             // 7 days (default)
  maxUses: 50,                           // Optional
  jti: "share-" + crypto.randomUUID(),   // Optional: for tracking
  data: { sharedBy: "user-42" },         // Optional: metadata
});

// Create shareable URL
const shareUrl = `https://news.example.com/article/123?share=${token}`;
```

### Issuer-Side Validation

The issuer validates the share token using the publisher's signing key (already in `trustedPublisherKeys`). No new secrets or key material are needed:

```js
import { createDcaIssuer } from '@sesamy/capsule-server';

const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
  keyId: "2025-10",
  trustedPublisherKeys: {
    "news.example.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
  },
});

// In unlock endpoint:
export async function POST(request: Request) {
  const body = await request.json();

  if (body.shareToken) {
    // Share link flow: token IS the access decision
    const result = await issuer.unlockWithShareToken(body, {
      deliveryMode: "direct",            // or "wrapKey" for caching
      onShareToken: async (payload, resource) => {
        // Optional: use-count tracking, audit logging
        console.log(`Share token used: ${payload.jti}`);
        // Throw to reject: throw new Error("Usage limit exceeded");
      },
    });
    return Response.json(result);
  }

  // Normal subscription flow...
}
```

The issuer performs these validation steps:

1. Verifies `resourceJWT` and extracts `renderId` (same as normal unlock)
2. Verifies share token signature with the publisher's ES256 key
3. Validates type discriminator (`"dca-share"`)
4. Validates domain binding (token domain must match resource domain)
5. Validates resourceId binding (token must be for this resource)
6. Checks expiry (reject expired tokens)
7. Invokes optional `onShareToken` callback (use-count, audit)
8. Grants access to content names listed in token intersection with available wrapped data
9. Unwraps keys from normal DCA wrapped blobs and returns them

### Unlock Request with Share Token

```
// Client → Issuer
POST /api/unlock
{
  "resourceJWT": "eyJ…",
  "keys": [
    { "contentName": "bodytext", "contentKey": "…", "wrapKeys": [{ "kid": "…", "key": "…" }] }
  ],
  "shareToken": "eyJ…",                  // ← Share link token
  "clientPublicKey": "base64url-SPKI…"   // Optional: client-bound transport
}

// Issuer → Client (same response format as normal unlock)
{
  "keys": [
    { "contentName": "bodytext", "contentKey": "base64url-key-or-wrapped-key" }
  ],
  "transport": "client-bound"
}
```

### Client-Side Share Link Handling

```js
import { DcaClient } from '@sesamy/capsule';

const client = new DcaClient();
const page = client.parsePage();

// Check for share token in URL
const shareToken = DcaClient.getShareTokenFromUrl(); // reads ?share= param

if (shareToken) {
  // Unlock with share token (auto-includes token in unlock request)
  const keys = await client.unlockWithShareToken(page, "sesamy", shareToken);
  const html = await client.decrypt(page, "bodytext", keys);
  document.querySelector('[data-dca-content-name="bodytext"]')!.innerHTML = html;

  // Clean up URL (cosmetic)
  const url = new URL(window.location.href);
  url.searchParams.delete("share");
  history.replaceState({}, "", url);
}
```

### Use-Count Tracking

The `maxUses` field is advisory -- enforcement is the issuer's responsibility. Use the `onShareToken` callback to implement tracking:

```js
// Example: Redis-based use-count tracking
const result = await issuer.unlockWithShareToken(body, {
  onShareToken: async (payload) => {
    if (!payload.jti) return; // No tracking without token ID

    const key = `share-uses:${payload.jti}`;
    const count = await redis.incr(key);

    // Set TTL on first use
    if (count === 1) {
      await redis.expire(key, payload.exp - Math.floor(Date.now() / 1000));
    }

    if (payload.maxUses && count > payload.maxUses) {
      throw new Error("Share link usage limit exceeded");
    }
  },
});
```

### Standalone Token Verification

The issuer can verify a share token without performing a full unlock, useful for pre-flight checks:

```
const payload = await issuer.verifyShareToken(shareToken, "news.example.com");
// payload: { type, domain, resourceId, contentNames, iat, exp, jti?, maxUses?, data? }
```

### Security Considerations for Share Links

- Tokens are ES256-signed using the publisher's existing signing key
- Issuer validates signature via the trusted-publisher allowlist (no new secrets)
- `rotationSecret` never leaves the publisher -- DCA boundary intact
- Expiration limits exposure window
- Usage limits via `maxUses` + `onShareToken` callback
- Resource and domain binding prevent token reuse across content
- Content-name scoping limits what each token can unlock
- Full audit trail via `jti`, `data`, and callback
- Key material uses the same DCA wrap/unwrap channel (no new attack surface)
- Tokens are bearer credentials -- anyone with the URL has access
- Publisher signing key must be protected (same requirement as normal DCA)

## Security Considerations

### Rotation Secret Protection

The rotation secret is the root of all security. If compromised, attackers can derive all future wrapKeys. Only the publisher should hold the rotation secret.

| Component | Public/Secret | Storage |
| --- | --- | --- |
| Rotation Secret | SECRET | KMS only (Publisher server) |
| WrapKey Derivation Algorithm | Public | Open source code |
| WrapKeys | SECRET | Derived on-demand, cached briefly |
| Content Keys | SECRET | Wrapped (never in plaintext) |
| User Private Keys | SECRET | Browser IndexedDB (non-extractable) |

### Access Revocation

With rotating wrapKeys, access is automatically revoked within the rotation interval (default: 1 hour):

- User's browser caches unwrapped content key until the rotation version expires
- When subscription cancelled, issuer refuses new unlock requests
- Cached content key expires -- user can no longer decrypt new content
- No content re-encryption needed

### Publisher Compromise Scenarios

**If the publisher is compromised, attacker gets:**

- Plaintext content (publisher already has this)
- Rotation secret and derived wrapKeys
- Cannot unwrap keys without issuer private key
- Cannot decrypt for other users (no user private keys)

### Issuer Compromise Scenarios

**If the issuer is compromised, attacker gets:**

- ECDH private key -- can unwrap content keys and wrapKeys
- Can decrypt content if they also have the encrypted content
- Cannot access content without the encrypted HTML (publisher-side)
- Cannot forge publisher JWTs (no ES256 signing key)

**Mitigation:** Use separate infrastructure, rotate issuer key pairs, audit logs

### Private Key Protection

Private keys must be stored with `extractable: false` in the Web Crypto API. This prevents JavaScript from accessing the raw key material.

### Key Storage

The rotation secret and signing keys should be stored in a secure key management system (KMS) in production. Never hardcode secrets in source code.

### Transport Security

The key exchange endpoint must use HTTPS. While the wrapped content key is encrypted, HTTPS prevents MITM attacks on the public key exchange.

### IV Uniqueness

Each encrypted article must use a unique initialization vector (IV). Never reuse IVs with the same content key, as this breaks AES-GCM security.

## Security Properties

### What Capsule Provides

- **Confidentiality:** Content encrypted at rest and in transit
- **Integrity:** AES-GCM authentication detects tampering
- **Forward Secrecy:** Rotation versions limit exposure window
- **Secure Key Transport:** ECDH P-256 wrapping + optional RSA-OAEP client-bound wrapping
- **Content Key Binding:** Two layers of AAD prevent substitution -- content AAD (`domain|resourceId|contentName|scope`) binds ciphertext to resource context, wrap AAD (`scope`) binds wrapped key material to the access tier
- **Cross-Tier Protection:** Wrap AAD prevents key substitution between access tiers -- wrapped blobs cannot be unwrapped under a different tier's context
- **Offline Access:** Cached keys work without network
- **No Server-Side User Tracking:** Keys are bearer tokens

### What Capsule Does NOT Provide

- **DRM:** Determined users can extract decrypted content
- **Copy Protection:** Once decrypted, content can be copied
- **Watermarking:** No user-specific content marking

Capsule is designed for honest users who want convenient access, not for preventing determined adversaries from extracting content.

## Implementation Checklist

- AES-256-GCM for content encryption
- ECDH P-256 for key wrapping (with scope as wrap AAD)
- ES256 (ECDSA P-256) for JWT signing
- Unique 96-bit IV per encrypted content
- 128-bit authentication tag (GCM)
- Private keys stored with extractable: false
- HTTPS for key exchange endpoint
- Proper error handling and validation
