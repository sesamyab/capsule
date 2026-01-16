# Capsule

An open standard for secure article encryption using envelope encryption (RSA-OAEP + AES-256-GCM) via the Web Crypto API.

## Overview

Capsule provides a complete solution for encrypting and decrypting premium content using envelope encryption:

1. **Server-side**: Encrypts articles using AES-256-GCM with unique Data Encryption Keys (DEKs), then wraps DEKs with the recipient's RSA public key
2. **Client-side**: Decrypts wrapped DEKs using a non-extractable private RSA key stored in IndexedDB, then decrypts the article content

## Monorepo Structure

This is a pnpm workspace monorepo containing:

```
capsule/
├── apps/
│   └── demo/              # Next.js demo application
├── packages/
│   └── capsule-client/    # Browser decryption library (publishable npm package)
├── package.json           # Workspace root
└── pnpm-workspace.yaml
```

### Packages

| Package | Description | Location |
|---------|-------------|----------|
| `@sesamy/capsule` | Browser client-side decryption library | [packages/capsule-client](./packages/capsule-client) |

### Apps

| App | Description | Location |
|-----|-------------|----------|
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
- **AES key only exists in memory** - during decryption process only
- **Each article has a unique DEK** - compromise of one doesn't affect others
- **RSA-OAEP** for key wrapping (2048 or 4096-bit)
- **AES-256-GCM** for content encryption with authentication

## Security Constraints

- **Private RSA key never leaves the client** - stored as non-extractable in IndexedDB
- **AES DEK only exists in memory** - during decryption process only
- **Each article has a unique DEK** - compromise of one doesn't affect others
- **Dual key model** - Tier keys (unlock all tier articles) + Article-specific keys (single article)
- **RSA-OAEP (2048-bit, SHA-256)** for key wrapping
- **AES-256-GCM** for content encryption with authentication

## Client Library Usage

### Installation

```bash
npm install @sesamy/capsule
# or
pnpm add @sesamy/capsule
```

### Basic Usage

```typescript
import { CapsuleClient } from '@sesamy/capsule';

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
import { subtle } from 'crypto';

// 1. Generate random AES-256 key (DEK)
const dek = await subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  true,
  ['encrypt']
);

// 2. Encrypt content with DEK
const iv = crypto.getRandomValues(new Uint8Array(12));
const encryptedContent = await subtle.encrypt(
  { name: 'AES-GCM', iv },
  dek,
  new TextEncoder().encode(content)
);

// 3. Wrap DEK with recipient's public RSA key
const publicKey = await subtle.importKey(/* ... */);
const wrappedDek = await subtle.wrapKey('raw', dek, publicKey, {
  name: 'RSA-OAEP'
});

// 4. Return payload
return {
  encryptedContent: base64(encryptedContent),
  iv: base64(iv),
  encryptedDek: base64(wrappedDek)
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
