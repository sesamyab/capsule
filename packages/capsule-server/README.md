# @sesamy/capsule-server

Server-side encryption library for Capsule - provides envelope encryption for content and subscription server utilities.

## Installation

```bash
npm install @sesamy/capsule-server
# or
pnpm add @sesamy/capsule-server
```

## Quick Start (High-Level API)

The simplest way to encrypt content - just provide a master secret and call `encrypt()`:

```typescript
import { CapsuleServer } from '@sesamy/capsule-server';

const capsule = new CapsuleServer({
  masterSecret: process.env.MASTER_SECRET,  // Base64-encoded 256-bit secret
});

// Encrypt with tier-based subscription access
const encrypted = await capsule.encrypt('article-123', premiumContent, {
  tiers: ['premium'],
});

// Result: { articleId, encryptedContent, iv, wrappedKeys: [...] }
```

### Output Formats

```typescript
// JSON (default) - for API responses or manual template insertion
const data = await capsule.encrypt(id, content, { 
  tiers: ['premium'],
  format: 'json' 
});

// HTML - ready to embed in your page
const html = await capsule.encrypt(id, content, {
  tiers: ['premium'],
  format: 'html',
  htmlClass: 'premium-content',
  placeholder: '<p>Subscribe to unlock this content...</p>',
});
// Result: <div class="premium-content" data-capsule='{"articleId":...}' data-capsule-id="article-123">
//           <p>Subscribe to unlock this content...</p>
//         </div>

// Template helper - get all formats at once
const { data, json, attribute, html } = await capsule.encryptForTemplate(id, content, {
  tiers: ['premium'],
});
```

### Encryption Options

```typescript
const encrypted = await capsule.encrypt('article-123', content, {
  // Subscription tiers (auto-generates time-bucket keys)
  tiers: ['premium', 'enterprise'],
  
  // Include article-specific permanent key
  includeArticleKey: true,
  
  // Custom keys (partner access, promotional, etc.)
  additionalKeys: [
    { keyId: 'partner:acme', key: partnerKeyBuffer },
    { keyId: 'promo:2024', key: promoKey, expiresAt: new Date('2024-12-31') },
  ],
  
  // Output format
  format: 'json' | 'html' | 'html-template',
});
```

## With Async Key Provider

For advanced use cases where keys come from an external source:

```typescript
import { createCapsuleWithKeyProvider } from '@sesamy/capsule-server';

const capsule = createCapsuleWithKeyProvider(async (articleId) => {
  // Fetch from CMS, subscription server, database, or cache
  const response = await fetch(`https://keys.example.com/api/keys?article=${articleId}`);
  const { keys } = await response.json();
  
  return keys; // [{ keyId: 'premium:123', key: 'base64...', expiresAt: '...' }]
});

// Keys are fetched automatically when encrypting
const encrypted = await capsule.encrypt('article-123', content);
```

## How It Works

### Envelope Encryption

Capsule uses envelope encryption for efficient multi-recipient encryption:

```
Content → [AES-256-GCM] → Encrypted Content
              ↓
           DEK (unique per article)
              ↓
    ┌─────────┼─────────┐
    ↓         ↓         ↓
 Bucket    Bucket    Static
 Key #1    Key #2    Key
    ↓         ↓         ↓
 Wrapped   Wrapped   Wrapped
 DEK #1    DEK #2    DEK #3
```

- Content is encrypted ONCE with a unique DEK (Data Encryption Key)
- The DEK is wrapped with MULTIPLE key-wrapping keys
- Different users can unlock using different wrapped keys
- No need to re-encrypt content when adding access paths

### Time-Bucket Keys (TOTP)

Subscription tier keys rotate automatically:

- Keys are derived from `masterSecret + tier + bucketId` using HKDF
- Bucket ID changes every `bucketPeriodSeconds` (default: 30s)
- CMS always encrypts with current AND next bucket (handles clock drift)
- When bucket expires, old wrapped keys become invalid (forward secrecy)

## Subscription Server Setup

For the unlock endpoint that users call:

```typescript
import { createSubscriptionServer } from '@sesamy/capsule-server';

const server = createSubscriptionServer(
  process.env.MASTER_SECRET,
  30  // bucket period in seconds
);

// Endpoint for CMS to get bucket keys (if not using TOTP)
app.post('/api/cms/bucket-keys', (req) => {
  // Validate CMS API key here
  const { keyId } = req.body;
  return server.getBucketKeysResponse(keyId);
});

// Endpoint for users to unlock content
app.post('/api/unlock', async (req) => {
  // Validate user subscription here!
  const { keyId, wrappedDek, publicKey } = req.body;
  
  return server.unlockForUser(
    { keyId, wrappedDek },
    publicKey,
    // Optional: lookup for static keys (per-article purchase)
    (keyId) => staticKeyStore.get(keyId)
  );
});
```

## Low-Level API

For more control over the encryption process:

```typescript
import { createTotpEncryptor } from '@sesamy/capsule-server';

const encryptor = createTotpEncryptor(
  process.env.MASTER_SECRET,
  30  // bucket period
);

// Encrypt with specific tier
const encrypted = await encryptor.encryptArticleWithTier(
  'article-123',
  'Premium content here...',
  'premium',
  [
    // Additional keys
    { keyId: 'article:article-123', key: articleKey },
  ]
);
```

### API Mode (No Local Secret)

When CMS shouldn't have the master secret:

```typescript
import { createApiEncryptor } from '@sesamy/capsule-server';

const encryptor = createApiEncryptor(
  'https://subscription.example.com',
  process.env.SUBSCRIPTION_API_KEY
);

const encrypted = await encryptor.encryptArticleWithTier(
  'article-123',
  'Premium content...',
  'premium'
);
```

## Framework Examples

### Next.js

```typescript
// lib/capsule.ts
import { CapsuleServer } from '@sesamy/capsule-server';

export const capsule = new CapsuleServer({
  masterSecret: process.env.MASTER_SECRET!,
});

// app/article/[slug]/page.tsx
export default async function ArticlePage({ params }) {
  const article = await getArticle(params.slug);
  
  const encryptedHtml = await capsule.encrypt(
    article.id,
    article.premiumContent,
    { tiers: ['premium'], format: 'html' }
  );
  
  return (
    <article>
      <h1>{article.title}</h1>
      <div>{article.preview}</div>
      <div dangerouslySetInnerHTML={{ __html: encryptedHtml }} />
    </article>
  );
}
```

### Astro

```astro
---
// src/pages/article/[slug].astro
import { CapsuleServer } from '@sesamy/capsule-server';

const capsule = new CapsuleServer({
  masterSecret: import.meta.env.MASTER_SECRET,
});

const article = await getArticle(Astro.params.slug);
const { attribute } = await capsule.encryptForTemplate(
  article.id,
  article.premiumContent,
  { tiers: ['premium'] }
);
---
<article>
  <h1>{article.title}</h1>
  <div set:html={article.preview} />
  <div 
    data-capsule={attribute}
    data-capsule-id={article.id}
  >
    <p>Subscribe to unlock...</p>
  </div>
</article>
```

### Express

```typescript
import express from 'express';
import { CapsuleServer, createSubscriptionServer } from '@sesamy/capsule-server';

const app = express();
const capsule = new CapsuleServer({ masterSecret: process.env.MASTER_SECRET! });
const server = createSubscriptionServer(process.env.MASTER_SECRET!);

// Encrypt content
app.get('/api/article/:id', async (req, res) => {
  const article = await db.getArticle(req.params.id);
  const encrypted = await capsule.encrypt(article.id, article.content, {
    tiers: ['premium'],
  });
  res.json({ ...article, encrypted });
});

// Unlock endpoint
app.post('/api/unlock', async (req, res) => {
  // Validate user subscription first!
  const { keyId, wrappedDek, publicKey } = req.body;
  const result = await server.unlockForUser({ keyId, wrappedDek }, publicKey);
  res.json(result);
});
```

## Security Notes

- **Master secret**: Store in KMS (AWS Secrets Manager, HashiCorp Vault, etc.)
- **Bucket period**: Determines maximum revocation delay (shorter = faster revocation, more wrapped keys)
- **Per-article keys**: Are static (no automatic revocation) - use for permanent purchases
- **CMS isolation**: Consider API mode if CMS shouldn't have master secret
- **User validation**: Always validate subscription before calling `unlockForUser()`

## API Reference

### CapsuleServer

```typescript
class CapsuleServer {
  constructor(options: CapsuleServerOptions);
  
  // Main encryption method
  encrypt<T extends 'json' | 'html' | 'html-template'>(
    articleId: string,
    content: string,
    options?: EncryptOptions & { format?: T }
  ): Promise<EncryptResult<T>>;
  
  // Helper for template integration
  encryptForTemplate(
    articleId: string,
    content: string,
    options?: EncryptOptions
  ): Promise<{ data, json, attribute, html }>;
}
```

### SubscriptionServer

```typescript
class SubscriptionServer {
  constructor(options: SubscriptionServerOptions);
  
  // For CMS key fetching
  getBucketKeysResponse(keyId: string): BucketKeysResponse;
  
  // For user unlock
  unlockForUser(
    wrappedKey: WrappedKey,
    userPublicKey: string,
    staticKeyLookup?: (keyId: string) => Buffer | null
  ): Promise<UnlockResponse>;
}
```

See [TypeScript definitions](./src/types.ts) for full type documentation.
