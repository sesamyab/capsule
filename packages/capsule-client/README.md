# @sesamy/capsule

Browser-side **DCA (Delegated Content Access)** client — parse encrypted pages, call issuer unlock endpoints, and decrypt content.

## Installation

```bash
npm install @sesamy/capsule
# or
pnpm add @sesamy/capsule
```

## Quick Start

The simplest integration — auto-detects the issuer and share token, then decrypts and renders:

```typescript
import { DcaClient, hasDcaContent } from "@sesamy/capsule";

if (hasDcaContent()) {
  const client = new DcaClient();
  const content = await client.processPage();
  client.renderToPage(content);
}
```

### Step-by-Step

For more control, use the individual methods:

```typescript
import { DcaClient } from "@sesamy/capsule";

const client = new DcaClient();

// Parse DCA data from the current page
const page = client.parsePage();

// Unlock via an issuer
const keys = await client.unlock(page, "sesamy");

// Decrypt a specific content item
const html = await client.decrypt(page, "bodytext", keys);

// Inject into the DOM
document.querySelector('[data-dca-content-name="bodytext"]')!.innerHTML = html;
```

### Decrypt All Content

```typescript
const page = client.parsePage();
const keys = await client.unlock(page, "sesamy");
const decrypted = await client.decryptAll(page, keys);

for (const [contentName, html] of Object.entries(decrypted)) {
  document.querySelector(`[data-dca-content-name="${contentName}"]`)!.innerHTML = html;
}
```

### Share Links

```typescript
import { parseShareToken } from "@sesamy/capsule";

// Standalone function — reads ?share= from current URL
const shareToken = parseShareToken();

// Or via the static method
const shareToken = DcaClient.getShareTokenFromUrl();

if (shareToken) {
  const keys = await client.unlockWithShareToken(page, "sesamy", shareToken);
  const html = await client.decrypt(page, "bodytext", keys);
}
```

### JSON API (non-DOM)

```typescript
const res = await fetch("/api/article/123");
const json = await res.json();

const page = client.parseJsonResponse(json);
const keys = await client.unlock(page, "sesamy");
const content = await client.decrypt(page, "bodytext", keys);
```

## API Reference

### `new DcaClient(options?)`

| Option | Type | Default | Description |
| ------ | ---- | ------- | ----------- |
| `fetch` | `typeof fetch` | `globalThis.fetch` | Custom fetch function (e.g. for adding auth headers) |
| `unlockFn` | `(url, body) => Promise<DcaUnlockResponse>` | — | Custom unlock function (replaces fetch-based unlock) |
| `periodKeyCache` | `DcaPeriodKeyCache` | — | Key-value cache for period key reuse across pages |
| `clientBound` | `boolean` | `false` | Enable client-bound transport (RSA-OAEP key wrapping) |
| `rsaKeySize` | `2048 \| 4096` | `2048` | RSA key size for client-bound transport |
| `keyDbName` | `string` | `"dca-keys"` | IndexedDB database name for key pair storage |

### `client.parsePage(root?)`

Parses DCA data from the DOM. Looks for `<script class="dca-data">` and `<template class="dca-sealed-content">` elements.

```typescript
const page = client.parsePage(); // defaults to document
const page = client.parsePage(someElement); // scoped parse
```

Returns a `DcaParsedPage` used by other methods.

### `client.parseJsonResponse(json)`

Parses a JSON API response into a `DcaParsedPage`.

```typescript
const page = client.parseJsonResponse(apiResponse);
```

### `client.unlock(page, issuerName, additionalBody?)`

Calls the issuer's unlock endpoint and returns keys.

| Param | Type | Description |
| ----- | ---- | ----------- |
| `page` | `DcaParsedPage` | Parsed page data |
| `issuerName` | `string` | Which issuer to call |
| `additionalBody` | `Record<string, unknown>` | Extra fields in the request body (e.g. auth tokens) |

```typescript
const keys = await client.unlock(page, "sesamy", {
  authorization: "Bearer " + userToken,
});
```

### `client.unlockWithShareToken(page, issuerName, shareToken, additionalBody?)`

Calls the unlock endpoint with a share token attached.

### `client.decrypt(page, contentName, unlockResponse)`

Decrypts a single content item using the keys from `unlock()`.

Handles both delivery modes automatically:
- **contentKey mode** — decrypts directly with AES-256-GCM
- **periodKey mode** — unwraps the content key from `sealedContentKeys` first, then decrypts

Also handles client-bound transport (RSA-OAEP unwrapping) and caches period keys when a `periodKeyCache` is configured.

### `client.decryptAll(page, unlockResponse)`

Decrypts all content items in the unlock response.

```typescript
const all = await client.decryptAll(page, keys);
// { bodytext: "<p>...</p>", sidebar: "<aside>...</aside>" }
```

### `client.processPage(options?)`

Convenience method: parse → unlock → decryptAll in one call. Auto-detects the issuer (first key in `issuerData`) and share token (from `?share=` URL parameter).

```typescript
const content = await client.processPage();

// With explicit options
const content = await client.processPage({
  issuerName: "sesamy",          // override auto-detected issuer
  shareToken: null,              // skip share token detection
  root: someElement,             // scope DOM parsing
  additionalBody: { auth: "…" }, // extra fields for unlock request
});
```

### `client.renderToPage(content, root?)`

Injects decrypted content into the DOM. Finds elements with matching `data-dca-content-name` attributes and sets their `innerHTML`. Returns the set of content names that were rendered.

```typescript
const content = await client.processPage();
const rendered = client.renderToPage(content);
// rendered: Set { "bodytext", "sidebar" }
```

### `DcaClient.hasDcaContent(root?)`

Static method. Returns `true` if the page contains a `<script class="dca-data">` element. Also available as a standalone import:

```typescript
import { hasDcaContent } from "@sesamy/capsule";

if (hasDcaContent()) { /* page has DCA content */ }
```

### `DcaClient.getShareTokenFromUrl(paramName?)`

Static method. Extracts a share token from the current URL query params.

```typescript
const token = DcaClient.getShareTokenFromUrl(); // reads ?share=...
const token = DcaClient.getShareTokenFromUrl("token"); // reads ?token=...
```

Returns `null` in non-browser environments or when the param is absent.

### `client.getPublicKey()`

Returns the client's RSA-OAEP public key as base64url-encoded SPKI. Generates and persists a key pair to IndexedDB on first call. Only needed when `clientBound: true`.

### `client.hasKeyPair()`

Checks if an RSA key pair already exists in IndexedDB.

## Period Key Cache

When the issuer returns period keys (instead of content keys), you can cache them for cross-page key reuse:

```typescript
const cache: DcaPeriodKeyCache = {
  async get(key) { return sessionStorage.getItem(key); },
  async set(key, value) { sessionStorage.setItem(key, value); },
};

const client = new DcaClient({ periodKeyCache: cache });
```

Cache keys use the format `dca:pk:{keyName}:{timeBucket}`.

## Client-Bound Transport

When `clientBound: true`, the client generates an RSA-OAEP key pair stored in IndexedDB (private key is non-extractable). Keys returned by the issuer are wrapped with the client's public key, ensuring they can only be decrypted on the same device.

```typescript
const client = new DcaClient({
  clientBound: true,
  rsaKeySize: 2048,
});
```

## Request Format

The unlock request sends `resourceJWT` and `contentEncryptionKeys`. Each entry carries a `keyName` field that is AAD-bound — the issuer uses it directly for access tier resolution.

## Types

```typescript
import type {
  DcaClientOptions,
  DcaParsedPage,
  DcaPeriodKeyCache,
  DcaData,
  DcaUnlockResponse,
  DcaProcessPageOptions,
} from "@sesamy/capsule";
```
