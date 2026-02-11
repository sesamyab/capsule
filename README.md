# Capsule

An open standard for secure article encryption using envelope encryption (RSA-OAEP + AES-256-GCM) via the Web Crypto API.

## Overview

Capsule provides a complete solution for encrypting and decrypting premium content using envelope encryption:

1. **Server-side**: Encrypts articles using AES-256-GCM with unique Data Encryption Keys (DEKs), then wraps DEKs with the recipient's RSA public key
2. **Client-side**: Decrypts wrapped DEKs using a non-extractable private RSA key stored in IndexedDB, then decrypts the article content

### Two Unlock Flows

Capsule supports two ways to unlock content:

| Flow                  | Use Case                             | User Auth Required |
| --------------------- | ------------------------------------ | ------------------ |
| **Subscription Flow** | Logged-in subscribers unlock content | ✅ Yes             |
| **Share Link Flow**   | Anyone with a link can unlock        | ❌ No              |

## Share Links (Pre-signed Tokens)

Publishers can generate shareable links that unlock content without requiring user authentication. Perfect for:

- 📱 **Social Media** - Share articles on Facebook, Twitter, LinkedIn
- 📧 **Email Campaigns** - Direct article access in newsletters
- 🎁 **Gift Articles** - "Send this article to a friend"
- ⏰ **Promotions** - Time-limited free access

### How Share Links Work

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SHARE LINK FLOW                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. PUBLISHER GENERATES TOKEN                                               │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │  POST /api/share { tier: "premium", expiresIn: "7d" }           │     │
│     │                          ↓                                       │     │
│     │  Token: eyJhbGc... (signed with server secret)                  │     │
│     │  URL: https://example.com/article/xyz?token=eyJhbGc...          │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  2. READER CLICKS LINK (no login required)                                  │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │  Browser loads page with encrypted content                       │     │
│     │  Client generates ephemeral RSA key pair                         │     │
│     │  Client extracts token from URL                                  │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  3. CLIENT REQUESTS UNLOCK                                                  │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │  POST /api/unlock {                                              │     │
│     │    token: "eyJhbGc...",      // Proves access                   │     │
│     │    wrappedDek: "...",        // From encrypted article          │     │
│     │    publicKey: "..."          // Client's ephemeral key          │     │
│     │  }                                                               │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  4. SERVER VALIDATES & UNLOCKS                                              │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │  ✓ Validate token signature                                      │     │
│     │  ✓ Check expiration                                              │     │
│     │  ✓ Log unlock for analytics (article, token, timestamp, IP)     │     │
│     │  → Derive KEK from tier + bucket                                 │     │
│     │  → Unwrap DEK, re-wrap for client's public key                  │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
│  5. CLIENT DECRYPTS                                                         │
│     ┌─────────────────────────────────────────────────────────────────┐     │
│     │  Unwrap DEK with private key → Decrypt content with AES-GCM     │     │
│     │  ✨ Article displayed!                                           │     │
│     └─────────────────────────────────────────────────────────────────┘     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Quick Example

```typescript
// Server: Generate share link
import { createTokenManager } from "@sesamy/capsule-server";

const tokens = createTokenManager({ secret: process.env.TOKEN_SECRET });

const token = tokens.generate({
  tier: "premium",
  expiresIn: "7d",
  maxUses: 1000, // Optional: limit uses
  articleId: "my-article", // Optional: restrict to article
});

const shareUrl = `https://example.com/article/my-article?token=${token}`;
// → Share this URL on social media!
```

```typescript
// Client: Auto-unlock when token in URL
const capsule = new CapsuleClient({
  unlock: async (params) => {
    // Token is automatically included if present in URL
    return fetch("/api/unlock", {
      method: "POST",
      body: JSON.stringify(params),
    }).then((r) => r.json());
  },
});

// Check for token and unlock
const urlParams = new URLSearchParams(window.location.search);
const token = urlParams.get("token");

if (token) {
  await capsule.unlockWithToken(article, token);
}
```

### Analytics & Tracking

Every share link unlock is logged with:

- **Token ID** - Unique identifier for the token
- **Tier** - Which tier was accessed
- **Article ID** - Which article was unlocked
- **Timestamp** - When the unlock occurred
- **IP Address** - Reader's location (for geo analytics)

This gives publishers full visibility: _"Share link X was used 847 times, peaked at 3pm when the Twitter post went viral."_

See detailed documentation:

- [@sesamy/capsule-server](./packages/capsule-server/README.md#share-links--pre-signed-tokens) - Token generation and validation
- [@sesamy/capsule](./packages/capsule-client/README.md#share-link-unlock) - Client-side token handling

## Monorepo Structure

This is a pnpm workspace monorepo containing:

```
capsule/
├── apps/
│   └── demo/              # Next.js demo application
├── packages/
│   ├── capsule-client/    # Browser decryption library
│   └── capsule-server/    # Server-side encryption & token management
├── package.json           # Workspace root
└── pnpm-workspace.yaml
```

### Packages

| Package                  | Description                            | Location                                             |
| ------------------------ | -------------------------------------- | ---------------------------------------------------- |
| `@sesamy/capsule`        | Browser client-side decryption library | [packages/capsule-client](./packages/capsule-client) |
| `@sesamy/capsule-server` | Server encryption, tokens & unlock     | [packages/capsule-server](./packages/capsule-server) |

### Apps

| App            | Description                          | Location                 |
| -------------- | ------------------------------------ | ------------------------ |
| `capsule-demo` | Next.js demo with encrypted articles | [apps/demo](./apps/demo) |

## Development

### Prerequisites

- Node.js 18+
- pnpm 8+

### Setup

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Build specific package
pnpm client build

# Run demo
pnpm demo dev

# Run specific app/package commands
pnpm demo <command>   # Run command in demo app
pnpm client <command> # Run command in client package
```

### Available Scripts

```bash
pnpm dev              # Start demo dev server
pnpm build            # Build all packages
pnpm build:client     # Build capsule-client
pnpm build:demo       # Build demo app
pnpm test             # Run tests in all packages
pnpm lint             # Lint all packages
pnpm clean            # Clean all node_modules and build outputs
```

## Security Model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ENVELOPE ENCRYPTION                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CLIENT (Browser)                    SERVER                             │
│  ┌─────────────────┐                ┌─────────────────────────────────┐ │
│  │ Generate RSA    │                │                                 │ │
│  │ Key Pair        │                │  1. Generate random AES-256 DEK │ │
│  │                 │   Public Key   │  2. Encrypt article with DEK    │ │
│  │ Private Key     │ ────────────►  │  3. Wrap DEK with Public Key    │ │
│  │ (non-extractable│                │  4. Return encrypted payload    │ │
│  │  in IndexedDB)  │                │                                 │ │
│  └─────────────────┘                └─────────────────────────────────┘ │
│           │                                      │                      │
│           │                                      │                      │
│           │         Encrypted Payload            │                      │
│           │  ◄─────────────────────────────────  │                      │
│           │   { encryptedContent, iv,            │                      │
│           │     encryptedDek }                   │                      │
│           │                                      │                      │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ 1. Unwrap DEK   │                                                    │
│  │    with Private │                                                    │
│  │    Key          │                                                    │
│  │ 2. Decrypt      │                                                    │
│  │    content with │                                                    │
│  │    AES key      │                                                    │
│  │ 3. Display      │                                                    │
│  └─────────────────┘                                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Security Constraints

- **Private RSA key never leaves the client** - stored as non-extractable in IndexedDB
- **AES DEK only exists in memory** - during decryption process only
- **Each article has a unique DEK** - compromise of one doesn't affect others
- **Dual key model** - Tier keys (unlock all tier articles) + Article-specific keys (single article)
- **RSA-OAEP (2048-bit, SHA-256)** for key wrapping
- **AES-256-GCM** for content encryption with authentication

## DEK Storage Security Modes

Capsule supports two security modes for storing Data Encryption Keys (DEKs), configurable via the `securityMode` prop on `<EncryptedSection>`:

### Persist Mode (Default)

```tsx
<EncryptedSection securityMode="persist" {...props} />
```

| Aspect           | Description                                                 |
| ---------------- | ----------------------------------------------------------- |
| **Storage**      | Non-extractable `CryptoKey` stored directly in IndexedDB    |
| **Page Refresh** | ✅ No network request needed - instant decryption           |
| **Exfiltration** | ✅ Key material cannot be exported via `exportKey()`        |
| **Local Attack** | ⚠️ Attacker with IndexedDB access can _use_ the key locally |
| **Best For**     | Typical premium content, performance-critical apps          |

**How it works**: The `CryptoKey` object is stored directly in IndexedDB (it's structured-cloneable). On page refresh, the key is loaded and used immediately without any network requests. The key is marked as `extractable: false`, meaning `crypto.subtle.exportKey()` will throw an error - an attacker cannot export the raw key bytes to send to their server.

### Session Mode

```tsx
<EncryptedSection securityMode="session" {...props} />
```

| Aspect           | Description                                      |
| ---------------- | ------------------------------------------------ |
| **Storage**      | DEK kept in memory only (not persisted)          |
| **Page Refresh** | ⚠️ Requires network request to fetch new DEK     |
| **Exfiltration** | ✅ Key vanishes when tab closes                  |
| **Local Attack** | ✅ Key only exists while tab is open             |
| **Best For**     | Highly sensitive content, security-critical apps |

**How it works**: The DEK is only stored in JavaScript memory and expires when the page is closed or refreshed. Each page load requires a new network request to obtain a fresh DEK.

### Security Comparison

```
┌────────────────────┬─────────────────┬─────────────────┐
│ Threat             │ Persist Mode    │ Session Mode    │
├────────────────────┼─────────────────┼─────────────────┤
│ Network sniffing   │ ✅ Protected    │ ✅ Protected    │
│ Server compromise  │ ✅ Protected    │ ✅ Protected    │
│ Key exfiltration   │ ✅ Protected    │ ✅ Protected    │
│ Local key usage    │ ⚠️ Vulnerable  │ ✅ Protected*   │
│ Performance        │ ✅ Fast         │ ⚠️ Network req │
└────────────────────┴─────────────────┴─────────────────┘
* While tab is closed
```

### Important: Client-Side Decryption Limitations

**No browser mechanism can fully protect against a compromised browser.** If an attacker can execute JavaScript in your origin (via XSS, malicious extension, or physical access), they can:

1. Intercept decrypted content after decryption
2. Use stored keys (even non-extractable ones) for local decryption
3. Modify the page to exfiltrate content

**Defense in depth is essential:**

- Content Security Policy (CSP) to prevent script injection
- Subresource Integrity (SRI) for all scripts
- Time-limited DEKs with bucket rotation
- Server-side entitlement checks as the primary gate

## Client Library Usage

### Installation

```bash
npm install @sesamy/capsule
# or
pnpm add @sesamy/capsule
```

### Basic Usage

```typescript
import { CapsuleClient } from "@sesamy/capsule";

const client = new CapsuleClient();

// First time: generate and store keys
const publicKey = await client.generateKeyPair();
// Send publicKey to server for registration

// Later: decrypt an article
const content = await client.decryptArticle(encryptedPayload);
```

### Server-side Encryption (Example)

Server-side implementations can use the Web Crypto API in Node.js or any language with RSA-OAEP and AES-GCM support:

```typescript
// Node.js example (see demo for full implementation)
import { subtle } from "crypto";

// 1. Generate random AES-256 key (DEK)
const dek = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
  "encrypt",
]);

// 2. Encrypt content with DEK
const iv = crypto.getRandomValues(new Uint8Array(12));
const encryptedContent = await subtle.encrypt(
  { name: "AES-GCM", iv },
  dek,
  new TextEncoder().encode(content),
);

// 3. Wrap DEK with recipient's public RSA key
const publicKey = await subtle.importKey(/* ... */);
const wrappedDek = await subtle.wrapKey("raw", dek, publicKey, {
  name: "RSA-OAEP",
});

// 4. Return payload
return {
  encryptedContent: base64(encryptedContent),
  iv: base64(iv),
  encryptedDek: base64(wrappedDek),
};
```

## Demo Features

The demo application showcases:

- **Encrypted articles** with tier-based and article-specific keys
- **Key management UI** - view and remove stored keys
- **Developer console** - inspect encryption operations
- **Interactive unlock** - choose between tier or article-specific keys
- **Syntax-highlighted code blocks** - documentation with examples

## Publishing

To publish the client package to npm:

```bash
cd packages/capsule-client
pnpm build
pnpm publish --access public
```

## License

MIT
