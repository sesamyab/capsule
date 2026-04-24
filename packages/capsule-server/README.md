# @sesamy/capsule-server

Server-side **DCA (Delegated Content Access)** library — encrypt content for publishers and handle unlock requests for issuers.

For the full architecture walkthrough, see the [server docs](https://capsule.sesamy.dev/docs/server).

## Installation

```bash
npm install @sesamy/capsule-server
# or
pnpm add @sesamy/capsule-server
```

## Quick Start

### Publisher (CMS side)

```typescript
import { createDcaPublisher } from "@sesamy/capsule-server";

const publisher = createDcaPublisher({
  domain: "www.news-site.com",
  signingKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY!,
  rotationSecret: process.env.ROTATION_SECRET!,
});

const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", content: "<p>Premium article body...</p>" },
  ],
  issuers: [
    {
      issuerName: "sesamy",
      publicKeyPem: process.env.SESAMY_ECDH_PUBLIC_KEY!,
      keyId: "2025-10",
      unlockUrl: "https://api.sesamy.com/unlock",
      contentNames: ["bodytext"],
    },
  ],
});

// Embed in HTML — the manifest is self-contained, ciphertext lives inside it.
const html = `
  <head>${result.html.manifestScript}</head>
  <article data-dca-content-name="bodytext"></article>
`;
```

### Issuer (unlock side)

```typescript
import { createDcaIssuer } from "@sesamy/capsule-server";

const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
  keyId: "2025-10",
  trustedPublisherKeys: {
    "www.news-site.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
  },
});

app.post("/api/unlock", async (req, res) => {
  // Your access check here — then hand the decision to issuer.unlock().
  const result = await issuer.unlock(req.body, {
    grantedContentNames: ["bodytext"],
    deliveryMode: "direct", // or "wrapKey" for client-side caching
  });
  res.json(result);
});
```

## Publisher API

### `createDcaPublisher(config)`

| Param | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `domain` | `string` | yes | Publisher domain (e.g. `"www.news-site.com"`) |
| `signingKeyPem` | `string` | yes | ES256 (ECDSA P-256) private key PEM |
| `rotationSecret` | `string \| Uint8Array` | yes | Base64-encoded 256-bit secret for wrapKey derivation |
| `signingKeyId` | `string` | no | Identifier for the signing key. When set, emitted as the JWT header `kid`. Required for JWKS-based issuer verification — must match a `kid` in the publisher's JWKS. |
| `rotationIntervalHours` | `number` | no | WrapKey rotation granularity in hours (default: `1`) |
| `jwksCache` | `DcaJwksCache` | no | Pluggable cache for issuer JWKS documents (default: in-memory) |
| `jwksStaleWindowSeconds` | `number` | no | Stale-if-error window for JWKS (default: 30 days) |

Returns `{ render, createShareLinkToken }`.

### `publisher.render(options)`

```typescript
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", content: "<p>Premium content</p>" },
    { contentName: "sidebar", scope: "bodytext", content: "<aside>...</aside>" },
  ],
  issuers: [
    {
      issuerName: "sesamy",
      publicKeyPem: issuerPublicKey,
      keyId: "2025-10",
      unlockUrl: "https://api.sesamy.com/unlock",
      contentNames: ["bodytext", "sidebar"],
    },
  ],
  resourceData: { title: "My Article", tier: "premium" },
});
```

**Content items:**

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `contentName` | `string` | yes | Item identifier (e.g. `"bodytext"`) |
| `content` | `string` | yes | Plaintext to encrypt |
| `scope` | `string` | no | Access scope. Defaults to `contentName`. Items sharing a scope share a wrapKey (enables role-based caching). |
| `contentType` | `string` | no | MIME type (default: `"text/html"`) |

**Issuer config** (exactly one of `publicKeyPem` / `jwksUri` is required):

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `issuerName` | `string` | yes | Issuer identifier |
| `publicKeyPem` | `string` | conditional | ECDH P-256 or RSA-OAEP public key PEM. Mutually exclusive with `jwksUri`. |
| `jwksUri` | `string` | conditional | JWKS URL (see [Issuer Key Resolution](#issuer-key-resolution-jwks)). Mutually exclusive with `publicKeyPem`. |
| `keyId` | `string` | conditional | Required with `publicKeyPem`; ignored with `jwksUri` (each JWKS key carries its own `kid`). |
| `unlockUrl` | `string` | yes | Issuer's unlock endpoint URL |
| `contentNames` | `string[]` | conditional | Content items to wrap for this issuer |
| `scopes` | `string[]` | conditional | Or: scopes to wrap (takes precedence over `contentNames`) |
| `algorithm` | `"ECDH-P256" \| "RSA-OAEP"` | no | Auto-detected from PEM if omitted |

**Result:**

| Field | Type | Description |
| ----- | ---- | ----------- |
| `manifest` | `DcaManifest` | Self-contained manifest (metadata + ciphertext + wrapped keys) |
| `html.manifestScript` | `string` | `<script type="application/json" class="dca-manifest">...</script>` |
| `json` | `DcaJsonApiResponse` | Same as `manifest` — for JSON API responses |

### `publisher.createShareLinkToken(options)`

```typescript
const token = await publisher.createShareLinkToken({
  resourceId: "article-123",
  contentNames: ["bodytext"],
  expiresIn: 604800,   // 7 days (default)
  maxUses: 10,
});
```

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `resourceId` | `string` | yes | Resource this token grants access to |
| `contentNames` | `string[]` | conditional | Content items to grant |
| `scopes` | `string[]` | conditional | Or: scopes to grant (mutually exclusive with `contentNames`) |
| `expiresIn` | `number` | no | Token lifetime in seconds (default: 7 days) |
| `maxUses` | `number` | no | Advisory — enforced by issuer callback |
| `jti` | `string` | no | Unique token ID (auto-generated if omitted) |
| `data` | `Record<string, unknown>` | no | Publisher-defined metadata |

## Issuer API

### `createDcaIssuer(config)`

| Param | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `issuerName` | `string` | yes | Issuer identifier |
| `privateKeyPem` | `string` | yes | ECDH P-256 or RSA-OAEP private key PEM |
| `keyId` | `string` | yes | Issuer's own key ID — matches a `kid` on manifest `keys[]` entries |
| `trustedPublisherKeys` | `Record<string, string \| DcaTrustedPublisher>` | yes | Publisher domain → signing key PEM, JWKS URL, or extended config |
| `jwksCache` | `DcaJwksCache` | no | Pluggable cache for publisher JWKS documents (default: in-memory) |
| `jwksStaleWindowSeconds` | `number` | no | Stale-if-error window (default: 30 days) |
| `jwksFetchTimeoutMs` | `number` | no | HTTP timeout for JWKS fetches (default: 5000 ms) |

**Trusted-publisher config** — exactly one of `signingKeyPem` or `jwksUri` per entry. A bare string is shorthand for `{ signingKeyPem: "..." }`:

```typescript
trustedPublisherKeys: {
  // Simplest: pinned PEM, out-of-band distribution.
  "blog.example.com": process.env.BLOG_ES256_PUB!,

  // JWKS-backed: picks up publisher rotation automatically (see "Publisher Key Resolution" below).
  "news.example.com": {
    jwksUri: "https://news.example.com/.well-known/dca-publishers.json",
    allowedResourceIds: [/^premium-/],
  },

  // Extended form with a pinned PEM + resource constraints.
  "other.example.com": {
    signingKeyPem: process.env.OTHER_ES256_PUB!,
    allowedResourceIds: ["article-1"],
  },
}
```

### `issuer.unlock(request, accessDecision)`

```typescript
const result = await issuer.unlock(req.body, {
  grantedContentNames: ["bodytext"], // or: grantedScopes: ["premium"]
  deliveryMode: "direct",             // or "wrapKey"
});
```

**Delivery modes:**

- `"direct"` — return the content key directly (one-time, no caching).
- `"wrapKey"` — return wrapKeys (cacheable; client unwraps content keys locally from the manifest).

### `issuer.unlockWithShareToken(request, options?)`

Processes unlock requests carrying a `shareToken`. Verifies both the resource JWT and the share token signature against the publisher's trusted signing key.

```typescript
const result = await issuer.unlockWithShareToken(req.body, {
  deliveryMode: "direct",
  onShareToken: async (payload, resource) => {
    await incrementShareUseCount(payload.jti);
    // Throw to reject (e.g., rate limit exceeded).
  },
});
```

### `issuer.verify(request)`

Verifies request JWTs without unwrapping. Useful for pre-flight checks.

### `issuer.verifyShareToken(token, domain)`

Verifies a share token standalone.

## Issuer Key Resolution (JWKS)

Publishers can reference issuer public keys either directly (`publicKeyPem`) or via a JWKS URL (`jwksUri`). JWKS is recommended when the issuer rotates encryption keys — it makes rotation a no-op for publishers.

### How It Works

1. Issuer publishes a JWKS at a stable URL (e.g. `https://sesamy.com/.well-known/dca-issuers.json`) per [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).
2. Publisher fetches once, caches in-memory honoring `Cache-Control: max-age` (fallback 1h).
3. At render time, the publisher wraps content for **every** currently-active key in the JWKS. Each manifest `keys[]` entry is tagged with its `kid`.
4. The issuer selects the entry matching its configured `keyId` at unlock time.

During rotation overlap, the publisher produces 2 wrapped entries per content item — one per active issuer kid. Either issuer key can unwrap.

### Key Selection

A JWKS entry is considered active when:

- `kid` is present
- `kty` is `EC` with `crv: "P-256"`, or `kty` is `RSA`
- `use` is `"enc"` or absent
- `status` is not `"retired"` (non-standard, honored if present)

### Usage

```typescript
const publisher = createDcaPublisher({
  domain: "news.example.com",
  signingKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY!,
  rotationSecret: process.env.ROTATION_SECRET!,
});

await publisher.render({
  resourceId: "article-123",
  contentItems: [{ contentName: "bodytext", content: "..." }],
  issuers: [
    {
      issuerName: "sesamy",
      jwksUri: "https://sesamy.com/.well-known/dca-issuers.json",
      unlockUrl: "https://api.sesamy.com/unlock",
      contentNames: ["bodytext"],
    },
  ],
});
```

### Caching and Stale-if-Error

Freshness is driven by the JWKS response's `Cache-Control: max-age` (1h fallback). When the upstream refresh fails, the publisher serves the stale cached copy for up to **30 days past freshness** by default. Availability beats freshness — a blip in the JWKS host shouldn't break rendering. After the stale window, render throws with the URL in the error message.

The default cache is an in-memory Map scoped to the module. For multi-process deployments, supply a persistent backend:

```typescript
import type { DcaJwksCache, DcaJwksCacheEntry } from "@sesamy/capsule-server";

const kvCache: DcaJwksCache = {
  async get(url) {
    const raw = await env.JWKS_KV.get(url);
    return raw ? (JSON.parse(raw) as DcaJwksCacheEntry) : undefined;
  },
  async set(url, entry) {
    await env.JWKS_KV.put(url, JSON.stringify(entry), {
      expiration: Math.floor(entry.staleUntil / 1000),
    });
  },
};

const publisher = createDcaPublisher({
  domain: "news.example.com",
  signingKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY!,
  rotationSecret: process.env.ROTATION_SECRET!,
  jwksCache: kvCache,
  jwksStaleWindowSeconds: 30 * 24 * 3600, // default
});
```

### Force-Refresh

If the issuer returns "unknown kid" on unlock, the JWKS cache is stale. Force-refresh bypasses freshness while still honoring stale-fallback on error:

```typescript
import { refreshJwks } from "@sesamy/capsule-server";

await refreshJwks("https://sesamy.com/.well-known/dca-issuers.json", {
  cache: kvCache,
});
```

## Publisher Key Resolution (JWKS)

Symmetrically to issuer encryption keys, publishers may publish their ES256 **signing** keys at `.well-known/dca-publishers.json` so JWKS-configured issuers can resolve them dynamically. This makes publisher key rotation transparent — no redeploy per issuer.

### Publisher side

Set `signingKeyId` on `createDcaPublisher` so every signed JWT carries a `kid` in its header. Serve the corresponding JWKS document from your own route:

```typescript
import {
  createDcaPublisher,
  buildPublisherJwksDocument,
} from "@sesamy/capsule-server";

const publisher = createDcaPublisher({
  domain: "news.example.com",
  signingKeyPem: process.env.PUBLISHER_SIGNING_KEY!,
  signingKeyId: process.env.PUBLISHER_SIGNING_KEY_ID!, // e.g. "sig-2026-04"
  rotationSecret: process.env.PERIOD_SECRET!,
});

// Serve at https://news.example.com/.well-known/dca-publishers.json
const jwks = await buildPublisherJwksDocument([
  {
    publicKeyPem: process.env.PUBLISHER_PUBLIC_KEY!,
    kid: process.env.PUBLISHER_SIGNING_KEY_ID!,
  },
]);
app.get("/.well-known/dca-publishers.json", (_req, res) => {
  res.set("Cache-Control", "public, max-age=3600").json(jwks);
});
```

During rotation, include both keys in the JWKS and switch `signingKeyId` to the new one. Issuers pick up the new key on their next refresh (or immediately via force-refresh on unknown-kid).

### Issuer side

Replace the pinned PEM with `jwksUri`:

```typescript
const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_PRIVATE_KEY!,
  keyId: process.env.ISSUER_KEY_ID!,
  trustedPublisherKeys: {
    "news.example.com": {
      jwksUri: "https://news.example.com/.well-known/dca-publishers.json",
    },
  },
});
```

The issuer selects a key from the JWKS by the `kid` on the JWT header. When the kid isn't in the current (cached) JWKS, the cache is force-refreshed once before failing — the usual case is a publisher rotation between cache fetches.

### JWKS selection rules

A JWKS entry is considered active when:

- `kid` is present
- `kty` is `EC` with `crv: "P-256"` (ES256)
- `use` is `"sig"` or absent
- `status` is not `"retired"` (non-standard, honored if present)

RSA signing keys are not supported — DCA JWTs are fixed to ES256.

### Recommended vs required

JWKS is **recommended, not required**. Pinned `signingKeyPem` is fine for small deployments where you control both sides and publisher rotation is rare. Switch to JWKS when multiple issuers trust the same publisher, or when rotation automation matters more than the one-time setup cost.

## Key Generation

```typescript
import {
  generateEcdsaP256KeyPair,
  generateEcdhP256KeyPair,
  exportP256KeyPairPem,
  generateAesKeyBytes,
  toBase64,
} from "@sesamy/capsule-server";

// Publisher signing key (ES256)
const signing = await generateEcdsaP256KeyPair();
const signingPem = await exportP256KeyPairPem(signing.privateKey, signing.publicKey);
// → signingPem.privateKeyPem (keep private) / publicKeyPem (share with issuers)

// Issuer wrapping key (ECDH P-256)
const wrapping = await generateEcdhP256KeyPair();
const wrappingPem = await exportP256KeyPairPem(wrapping.privateKey, wrapping.publicKey);
// → wrappingPem.publicKeyPem (share with publishers — or publish via JWKS)

// Rotation secret (publisher-only, never shared)
const rotationSecret = toBase64(generateAesKeyBytes());
```

## Low-Level Exports

- **Encryption:** `encryptContent`, `decryptContent`, `wrapContentKey`, `unwrapContentKey`, `generateContentKey`, `generateIv`
- **JWT:** `createJwt`, `verifyJwt`, `decodeJwtPayload`, `decodeJwtHeader`, `createResourceJwt`, `resourceJwtPayloadToResource`, `computeProofHash`
- **Wrap (ECDH / RSA-OAEP):** `wrap`, `unwrap`, `wrapEcdhP256`, `unwrapEcdhP256`, `wrapRsaOaep`, `unwrapRsaOaep`, `importIssuerPublicKey`, `importIssuerPrivateKey`
- **JWKS:** `fetchJwks`, `refreshJwks`, `getActiveIssuerKeys`, `selectActiveKeys`, `selectActivePublisherKeys`, `resolvePublisherKey`, `clearJwksCache`
- **Publisher JWKS:** `buildPublisherJwk`, `buildPublisherJwksDocument`
- **Rotation:** `formatTimeKid`, `getCurrentRotationVersions`, `deriveWrapKey`, `generateRenderId`
- **Crypto primitives:** `sha256`, `hkdf`, ECDH/ECDSA/RSA key utilities, `toBase64Url`, `fromBase64Url`, `toBase64`, `fromBase64`

See [src/index.ts](src/index.ts) for the full list.
