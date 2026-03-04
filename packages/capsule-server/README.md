# @sesamy/capsule-server

Server-side **DCA (Delegated Content Access)** library — encrypt content for publishers and handle unlock requests for issuers.

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
  periodSecret: process.env.PERIOD_SECRET!,
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

// Embed in HTML
const html = `
  ${result.html.dcaDataScript}
  <article data-dca-content-name="bodytext">
    ${result.html.sealedContentTemplate}
  </article>
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

app.post("/api/unlock", async (req) => {
  const result = await issuer.unlock(req.body, async (verified) => {
    // Check if user has access — return granted content names
    return {
      granted: true,
      grantedContentNames: ["bodytext"],
      deliveryMode: "periodKey",
    };
  });
  return result;
});
```

## Publisher API

### `createDcaPublisher(config)`

Creates a publisher instance for encrypting content.

| Param | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `domain` | `string` | yes | Publisher domain (e.g. `"www.news-site.com"`) |
| `signingKeyPem` | `string` | yes | ES256 (ECDSA P-256) private key in PEM format |
| `periodSecret` | `string \| Uint8Array` | yes | Base64-encoded 256-bit secret for period key derivation |
| `periodDurationHours` | `number` | no | Time bucket granularity in hours (default: `1`) |

Returns an object with `render()` and `createShareLinkToken()` methods.

### `publisher.render(options)`

Encrypts content items and produces DCA output.

```typescript
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", content: "<p>Premium content</p>" },
    { contentName: "sidebar", keyName: "bodytext", content: "<aside>...</aside>" },
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
| `content` | `string` | yes | Plaintext content to encrypt |
| `keyName` | `string` | no | Key domain for period key derivation. Defaults to `contentName`. Items sharing a `keyName` share the same period key. |
| `contentType` | `string` | no | MIME type (default: `"text/html"`) |

**Issuer config:**

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `issuerName` | `string` | yes | Issuer identifier |
| `publicKeyPem` | `string` | yes | Issuer's ECDH P-256 or RSA-OAEP public key PEM |
| `keyId` | `string` | yes | Identifies matching issuer private key |
| `unlockUrl` | `string` | yes | Issuer's unlock endpoint URL |
| `contentNames` | `string[]` | conditional | Content items to seal for this issuer (by `contentName`) |
| `keyNames` | `string[]` | conditional | Key domains to seal for (takes precedence over `contentNames`) |
| `algorithm` | `string` | no | `"ECDH-P256"` or `"RSA-OAEP"` (auto-detected from key) |

**Result:**

| Field | Type | Description |
| ----- | ---- | ----------- |
| `dcaData` | `DcaData` | Complete DCA data object |
| `sealedContent` | `Record<string, string>` | `contentName` → base64url ciphertext |
| `html.dcaDataScript` | `string` | `<script>` tag for HTML embedding |
| `html.sealedContentTemplate` | `string` | `<template>` tag for HTML embedding |
| `json` | `DcaJsonApiResponse` | Combined data + sealed content for JSON APIs |

### `publisher.createShareLinkToken(options)`

Creates an ES256 JWT for share links.

```typescript
const token = await publisher.createShareLinkToken({
  resourceId: "article-123",
  contentNames: ["bodytext"],
  expiresIn: 604800, // 7 days (default)
  maxUses: 10,
});
```

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `resourceId` | `string` | yes | Resource this token grants access to |
| `contentNames` | `string[]` | conditional | Content items to grant access to |
| `keyNames` | `string[]` | conditional | Key domains to grant (alternative to `contentNames`) |
| `expiresIn` | `number` | no | Token lifetime in seconds (default: 7 days) |
| `maxUses` | `number` | no | Advisory max uses (enforced by issuer) |
| `data` | `Record<string, unknown>` | no | Custom metadata |

## Issuer API

### `createDcaIssuer(config)`

Creates an issuer instance for handling unlock requests.

| Param | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `issuerName` | `string` | yes | Issuer identifier |
| `privateKeyPem` | `string` | yes | ECDH P-256 or RSA-OAEP private key PEM |
| `keyId` | `string` | yes | Key ID matching publisher config |
| `trustedPublisherKeys` | `Record<string, string \| DcaTrustedPublisher>` | yes | Domain → signing key PEM (or extended config) |

**Extended trusted publisher config:**

```typescript
trustedPublisherKeys: {
  "www.news-site.com": {
    signingKeyPem: publicKeyPem,
    allowedResourceIds: ["article-*", /^premium-/],
  },
}
```

### `issuer.unlock(request, accessDecision)`

Verifies the request and returns unsealed keys.

```typescript
const result = await issuer.unlock(req.body, async (verified) => {
  // verified.resource contains domain, resourceId, data, etc.
  const hasAccess = await checkUserAccess(verified.resource.resourceId);
  return {
    granted: hasAccess,
    grantedContentNames: ["bodytext"],
    deliveryMode: "periodKey", // or "contentKey"
  };
});
```

**Delivery modes:**
- `"contentKey"` — returns one-time content keys (tied to this render)
- `"periodKey"` — returns period keys (cacheable, client can derive content keys locally)

### `issuer.unlockWithShareToken(request, options?)`

Handles unlock requests containing a share token. Verifies both the request JWTs and the share token.

```typescript
const result = await issuer.unlockWithShareToken(req.body, {
  deliveryMode: "contentKey",
  onShareToken: async (payload, resource) => {
    await incrementShareUseCount(payload.jti);
  },
});
```

### `issuer.verify(request)`

Verifies request JWTs without unsealing. Useful for pre-flight checks.

### `issuer.verifyShareToken(token, domain)`

Verifies a share token independently.

## Key Generation

Generate keys with the included script:

```bash
npx generate-keys
```

Or create keys programmatically:

```typescript
import {
  generateEcdsaP256KeyPair,
  generateEcdhP256KeyPair,
  exportP256KeyPairPem,
  generateAesKeyBytes,
  toBase64,
} from "@sesamy/capsule-server";

// Publisher signing key (ES256 / ECDSA P-256)
const signingKey = await generateEcdsaP256KeyPair();
const signingPem = await exportP256KeyPairPem(signingKey);

// Issuer sealing key (ECDH P-256)
const sealingKey = await generateEcdhP256KeyPair();
const sealingPem = await exportP256KeyPairPem(sealingKey);

// Period secret
const periodSecret = toBase64(await generateAesKeyBytes());
```

## Low-Level Exports

The package also exports lower-level primitives for advanced usage:

- **Encryption**: `encryptContent`, `decryptContent`, `generateContentKey`, `generateIv`
- **JWT**: `createJwt`, `verifyJwt`, `decodeJwtPayload`, `createResourceJwt`, `createIssuerJwt`
- **Seal**: `sealEcdhP256`, `unsealEcdhP256`, `sealRsaOaep`, `unsealRsaOaep`, `seal`, `unseal`
- **Time buckets**: `formatTimeBucket`, `getCurrentTimeBuckets`, `deriveDcaPeriodKey`
- **Crypto**: `sha256`, `hkdf`, `toBase64Url`, `fromBase64Url`, ECDH/ECDSA/RSA utilities

See [src/index.ts](src/index.ts) for the full list of exports.
