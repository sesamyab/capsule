# @sesamy/capsule-server

Server-side encryption library for Capsule - provides envelope encryption for content and subscription server utilities.

## Installation

```bash
npm install @sesamy/capsule-server
# or
pnpm add @sesamy/capsule-server
```

## Quick Start

The CMS server just needs a way to get keys - it doesn't care about tiers or how keys are derived.

```typescript
import {
  createCmsServer,
  createTotpKeyProvider,
  createSubscriptionServer,
} from "@sesamy/capsule-server";

// Create a TOTP key provider (derives keys from master secret)
const totp = createTotpKeyProvider({
  masterSecret: process.env.MASTER_SECRET, // Base64-encoded 256-bit secret
});

// CMS side: encrypt content
const cms = createCmsServer({
  getKeys: (keyIds) => totp.getKeys(keyIds),
});

const encrypted = await cms.encrypt("article-123", premiumContent, {
  keyIds: ["premium", "enterprise"], // Just key IDs - CMS doesn't know what they mean
});

// Subscription side: handle unlock requests
const server = createSubscriptionServer({
  masterSecret: process.env.MASTER_SECRET,
});

// In your unlock endpoint
const result = await server.unlockForUser(wrappedKey, publicKey);
```

## CMS Server

The CMS server encrypts content with envelope encryption. It doesn't know or care about subscription tiers - it just works with key IDs and calls your `getKeys` function to get the actual keys.

### Creating the Server

```typescript
import { createCmsServer } from "@sesamy/capsule-server";

// Option 1: Fetch keys from subscription server
const cms = createCmsServer({
  getKeys: async (keyIds) => {
    const response = await fetch("/api/keys", {
      method: "POST",
      body: JSON.stringify({ keyIds }),
    });
    return response.json();
    // Returns: [{ keyId: 'premium:123', key: 'base64...', expiresAt?: '...' }]
  },
});

// Option 2: Use TOTP key provider (derive keys locally)
const totp = createTotpKeyProvider({ masterSecret: process.env.MASTER_SECRET });
const cms = createCmsServer({
  getKeys: (keyIds) => totp.getKeys(keyIds),
});
```

### Encrypting Content

```typescript
const encrypted = await cms.encrypt("article-123", content, {
  keyIds: ["premium", "enterprise"], // Key IDs to encrypt with
});
```

**Returns (JSON format):**

```json
{
  "articleId": "article-123",
  "encryptedContent": "base64...", // AES-256-GCM encrypted content
  "iv": "base64...", // 12-byte initialization vector
  "wrappedKeys": [
    {
      "keyId": "premium:1737158400",
      "wrappedDek": "base64...", // DEK wrapped with this key
      "expiresAt": "2025-01-18T01:00:00.000Z"
    },
    {
      "keyId": "premium:1737158430",
      "wrappedDek": "base64...",
      "expiresAt": "2025-01-18T01:00:30.000Z"
    }
  ]
}
```

### Output Formats

```typescript
// JSON (default) - for API responses
const data = await cms.encrypt(id, content, { keyIds: ["premium"] });

// HTML - ready to embed in your page
const html = await cms.encrypt(id, content, {
  keyIds: ["premium"],
  format: "html",
  htmlClass: "premium-content",
  placeholder: "<p>Subscribe to unlock...</p>",
});
// Result: <div class="premium-content" data-capsule='{"articleId":...}' data-capsule-id="article-123">
//           <p>Subscribe to unlock...</p>
//         </div>

// Template helper - get all formats at once
const { data, json, attribute, html } = await cms.encryptForTemplate(
  id,
  content,
  {
    keyIds: ["premium"],
  },
);
```

## TOTP Key Provider

For deriving time-bucket keys locally from a shared master secret:

```typescript
import { createTotpKeyProvider } from "@sesamy/capsule-server";

const totp = createTotpKeyProvider({
  masterSecret: process.env.MASTER_SECRET,
  bucketPeriodSeconds: 30, // Optional, default 30
});

// Get keys for given IDs (returns current + next bucket for each)
const keys = await totp.getKeys(["premium", "enterprise"]);
// Returns: [
//   { keyId: 'premium:1737158400', key: Buffer, expiresAt: Date },
//   { keyId: 'premium:1737158430', key: Buffer, expiresAt: Date },
//   { keyId: 'enterprise:1737158400', key: Buffer, expiresAt: Date },
//   { keyId: 'enterprise:1737158430', key: Buffer, expiresAt: Date },
// ]

// For per-article purchase keys (static, no expiration)
const articleKey = await totp.getArticleKey("article-123");
// Returns: { keyId: 'article:article-123', key: Buffer }
```

### Combining with Article Keys

```typescript
const cms = createCmsServer({
  getKeys: async (keyIds) => {
    const keys = await totp.getKeys(
      keyIds.filter((id) => !id.startsWith("article:")),
    );

    // Add article keys if requested
    for (const id of keyIds.filter((id) => id.startsWith("article:"))) {
      const articleId = id.slice(8);
      keys.push(await totp.getArticleKey(articleId));
    }

    return keys;
  },
});

// Now you can mix time-bucket and article keys
await cms.encrypt("article-123", content, {
  keyIds: ["premium", "article:article-123"],
});
```

## Subscription Server

Handles unlock requests from users.

### Creating the Server

```typescript
import { createSubscriptionServer } from "@sesamy/capsule-server";

const server = createSubscriptionServer({
  masterSecret: process.env.MASTER_SECRET,
  bucketPeriodSeconds: 30,
});
```

### Unlock Endpoint

The subscription server supports two unlock modes:

**Tier Key Mode (recommended for subscribers):** Returns the tier's key-wrapping key (KEK) so the client can unwrap any article's DEK locally — one server call for all articles in a tier.

**Per-article DEK Mode:** Unwraps a single article's DEK and re-wraps it for the user. Used for share links or single purchases.

```typescript
app.post("/api/unlock", async (req) => {
  // Validate user subscription here!
  const { keyId, wrappedDek, publicKey, mode } = req.body;

  // Parse keyId (e.g., "premium:123456")
  const colonIndex = keyId.lastIndexOf(":");
  const tier = keyId.substring(0, colonIndex);
  const bucketId = keyId.substring(colonIndex + 1);

  // TIER KEY MODE: Return the KEK ("unlock once, access all")
  if (mode === "tier") {
    const result = await server.getTierKeyForUser(tier, bucketId, publicKey);
    return res.json({ ...result, keyType: "kek" });
  }

  // PER-ARTICLE DEK MODE: Return the unwrapped DEK
  const result = await server.unlockForUser(
    { keyId, wrappedDek },
    publicKey,
    // Optional: lookup for static keys (per-article purchase)
    (keyId) => staticKeyStore.get(keyId),
  );
  return res.json({ ...result, keyType: "dek" });
});
```

### Tier Key Endpoint

`getTierKeyForUser()` enables "unlock once, access all" for tier subscribers:

```typescript
// The client fetches this ONCE per tier per bucket period.
// After receiving the KEK, it can unwrap any article's wrappedDek locally.
const result = await server.getTierKeyForUser(
  "premium",    // tier name
  "123456",     // bucket ID (from the article's keyId)
  userPublicKey // Base64 SPKI
);

// result:
// {
//   encryptedDek: "...",  // Actually the KEK, RSA-OAEP encrypted for the user
//   keyId: "premium:123456",
//   bucketId: "123456",
//   expiresAt: "2026-02-23T12:00:30.000Z"
// }
```

**How the client uses it:**
1. RSA-unwrap the KEK with its private key → AES tier key
2. For each article: AES-GCM unwrap the `wrappedDek` locally → article DEK
3. AES-GCM decrypt article content with the DEK
4. Zero server calls for articles 2, 3, 4, ...

### Response `keyType` Field

The unlock endpoint should include `keyType` in its response so the client knows what it received:

| `keyType` | What `encryptedDek` contains | Client behavior |
|-----------|------------------------------|------------------|
| `"kek"`   | Tier key-wrapping key (AES-256) | Cache tier key, unwrap DEKs locally |
| `"dek"`   | Article's data encryption key | Decrypt content directly |
| _(absent)_ | Article's DEK (backward compat) | Decrypt content directly |

## Share Links & Pre-signed Tokens

Capsule supports pre-signed tokens for sharing content without requiring user authentication. This is perfect for:

- 📱 Sharing articles on social media (Facebook, Twitter, LinkedIn)
- 📧 Email campaigns with direct unlock links
- 🎁 "Gift this article" features
- ⏰ Time-limited promotional access

### How Share Links Work

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SHARE LINK FLOW                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PUBLISHER                         READER                    SERVER         │
│  ─────────                         ──────                    ──────         │
│      │                                │                          │          │
│      │ 1. Generate token              │                          │          │
│      │    (tier, expiry, maxUses)     │                          │          │
│      │─────────────────────────────►  │                          │          │
│      │                                │                          │          │
│      │ 2. Create share URL            │                          │          │
│      │    ?token=eyJhbGc...           │                          │          │
│      │                                │                          │          │
│  ════╪════════════════════════════════╪══════════════════════════╪════════  │
│      │     (Share on social media)    │                          │          │
│  ════╪════════════════════════════════╪══════════════════════════╪════════  │
│                                       │                          │          │
│                     3. Click link ───►│                          │          │
│                                       │                          │          │
│                                       │ 4. Extract token from URL│          │
│                                       │    Generate RSA keypair  │          │
│                                       │                          │          │
│                                       │ 5. POST /api/unlock ────►│          │
│                                       │    { token, wrappedDek,  │          │
│                                       │      publicKey }         │          │
│                                       │                          │          │
│                                       │                 6. Validate token   │
│                                       │                    Check expiry     │
│                                       │                    Log analytics    │
│                                       │                          │          │
│                                       │◄─────────────── 7. Return DEK       │
│                                       │                    (wrapped for     │
│                                       │                     client key)     │
│                                       │                          │          │
│                                       │ 8. Decrypt content       │          │
│                                       │    Display article ✨    │          │
│                                       │                          │          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Creating Tokens

```typescript
import { createTokenManager } from "@sesamy/capsule-server";

const tokens = createTokenManager({
  secret: process.env.TOKEN_SECRET, // Separate from master secret
});

// Generate a share token
const token = tokens.generate({
  tier: "premium", // Required: which tier to grant access to
  expiresIn: "7d", // Required: "1h", "24h", "7d", "30d"
  articleId: "crypto-guide", // Optional: restrict to specific article
  maxUses: 1000, // Optional: limit total uses
  userId: "publisher-123", // Optional: for attribution
  meta: { campaign: "twitter" }, // Optional: custom metadata
});

// Create share URL
const shareUrl = `https://example.com/article/crypto-guide?token=${token}`;
```

### Validating Tokens

```typescript
app.post("/api/unlock", async (req) => {
  const { token, wrappedDek, publicKey, articleId } = req.body;

  // Validate the token
  const validation = tokens.validate(token);
  if (!validation.valid) {
    return res.status(401).json({ error: validation.message });
  }

  // Log for analytics
  console.log("Unlock via share link", {
    tokenId: validation.payload.tid,
    tier: validation.payload.tier,
    articleId,
  });

  // Optional: check usage count from Redis/DB
  // if (validation.payload.maxUses) {
  //   const uses = await redis.incr(`token:${validation.payload.tid}:uses`);
  //   if (uses > validation.payload.maxUses) {
  //     return res.status(403).json({ error: "Token usage limit exceeded" });
  //   }
  // }

  // Unlock using the token
  const result = server.unlockWithToken(
    validation.payload,
    wrappedDek,
    publicKey,
    articleId,
  );

  return res.json({ ...result, tokenId: validation.payload.tid });
});
```

### Token Structure

Tokens are URL-safe, signed payloads:

```typescript
interface UnlockTokenPayload {
  v: 1; // Version
  tid: string; // Unique token ID (for tracking/revocation)
  tier: string; // Tier this grants access to
  articleId?: string; // Specific article (if restricted)
  userId?: string; // Creator attribution
  maxUses?: number; // Usage limit
  iat: number; // Issued at (Unix timestamp)
  exp: number; // Expires at (Unix timestamp)
  meta?: Record<string, any>; // Custom metadata
}
```

### Full Example: Share Link Flow

```typescript
// 1. Publisher generates share link
app.post("/api/share", async (req, res) => {
  const { tier, articleId, expiresIn, maxUses } = req.body;

  const token = tokens.generate({ tier, articleId, expiresIn, maxUses });
  const payload = tokens.peek(token);

  res.json({
    token,
    tokenId: payload.tid,
    shareUrl: `https://example.com/article/${articleId}?token=${token}`,
    expiresAt: new Date(payload.exp * 1000).toISOString(),
  });
});

// 2. Reader clicks link, client unlocks
// (Client extracts token from URL, sends with unlock request)

// 3. Server validates and unlocks
app.post("/api/unlock", async (req, res) => {
  const { token, wrappedDek, publicKey, articleId } = req.body;

  if (token) {
    const validation = tokens.validate(token);
    if (!validation.valid) {
      return res.status(401).json({ error: validation.message });
    }

    // Full audit trail
    await analytics.log("share_link_unlock", {
      tokenId: validation.payload.tid,
      tier: validation.payload.tier,
      articleId,
      ip: req.ip,
    });

    const result = server.unlockWithToken(
      validation.payload,
      wrappedDek,
      publicKey,
    );
    return res.json(result);
  }

  // Regular unlock flow...
});
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
  Key #1    Key #2    Key #3
    ↓         ↓         ↓
 Wrapped   Wrapped   Wrapped
 DEK #1    DEK #2    DEK #3
```

- Content is encrypted ONCE with a unique DEK (Data Encryption Key)
- The DEK is wrapped with MULTIPLE key-wrapping keys
- Different users can unlock using different wrapped keys
- No need to re-encrypt content when adding access paths

### Two Unlock Modes

**Tier Key Mode (recommended for subscribers):**

```
Subscriber opens first premium article:
  Client  → Server: "Give me the premium tier key for bucket 123456"
  Server  → Client: AES tier key, RSA-wrapped for this user (keyType: "kek")
  Client: RSA-unwrap → AES tier key → cache in memory

Subscriber opens second premium article (and third, fourth, ...):
  Client: Use cached tier key → AES-unwrap wrappedDek → decrypt content
  (ZERO server calls)
```

**Per-article DEK Mode (for share links / purchases):**

```
Each article requires a server call:
  Client  → Server: wrappedDek + publicKey
  Server  → Client: RSA-wrapped DEK (keyType: "dek")
  Client: RSA-unwrap → decrypt content
```

### Time-Bucket Keys (TOTP)

When using `TotpKeyProvider`, keys rotate automatically:

- Keys are derived from `masterSecret + keyId + bucketId` using HKDF
- Bucket ID changes every `bucketPeriodSeconds` (default: 30s)
- Provider returns current AND next bucket (handles clock drift)
- When bucket expires, old wrapped keys become invalid (forward secrecy)

## Framework Examples

### Next.js

```typescript
// lib/capsule.ts
import { createCmsServer, createTotpKeyProvider } from "@sesamy/capsule-server";

const totp = createTotpKeyProvider({
  masterSecret: process.env.MASTER_SECRET!,
});

export const cms = createCmsServer({
  getKeys: (keyIds) => totp.getKeys(keyIds),
});

// app/article/[slug]/page.tsx
export default async function ArticlePage({ params }) {
  const article = await getArticle(params.slug);

  const encryptedHtml = await cms.encrypt(article.id, article.premiumContent, {
    keyIds: ["premium"],
    format: "html",
  });

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
import { createCmsServer, createTotpKeyProvider } from '@sesamy/capsule-server';

const totp = createTotpKeyProvider({
  masterSecret: import.meta.env.MASTER_SECRET,
});

const cms = createCmsServer({
  getKeys: (keyIds) => totp.getKeys(keyIds),
});

const article = await getArticle(Astro.params.slug);
const { attribute } = await cms.encryptForTemplate(
  article.id,
  article.premiumContent,
  { keyIds: ['premium'] }
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
import express from "express";
import {
  createCmsServer,
  createTotpKeyProvider,
  createSubscriptionServer,
} from "@sesamy/capsule-server";

const app = express();

const totp = createTotpKeyProvider({
  masterSecret: process.env.MASTER_SECRET!,
});
const cms = createCmsServer({ getKeys: (keyIds) => totp.getKeys(keyIds) });
const server = createSubscriptionServer({
  masterSecret: process.env.MASTER_SECRET!,
});

// Encrypt content
app.get("/api/article/:id", async (req, res) => {
  const article = await db.getArticle(req.params.id);
  const encrypted = await cms.encrypt(article.id, article.content, {
    keyIds: ["premium"],
  });
  res.json({ ...article, encrypted });
});

// Unlock endpoint
app.post("/api/unlock", async (req, res) => {
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
- **Key isolation**: CMS only needs key IDs, not the master secret (if using external key provider)
- **User validation**: Always validate subscription before calling `unlockForUser()`

## API Reference

### CmsServer

```typescript
import { createCmsServer, CmsServer } from '@sesamy/capsule-server';

const cms = createCmsServer(options: CmsServerOptions);

interface CmsServerOptions {
  getKeys: (keyIds: string[]) => Promise<KeyEntry[]>;  // Required
  logger?: (msg: string, level: 'info' | 'warn' | 'error') => void;
}

interface KeyEntry {
  keyId: string;              // Key identifier
  key: Buffer | string;       // 256-bit AES key
  expiresAt?: Date | string;  // Optional expiration
}

// Encrypt content
cms.encrypt(articleId, content, { keyIds, format?, ... }): Promise<EncryptedArticle | string>;

// Get all formats for templates
cms.encryptForTemplate(articleId, content, { keyIds }): Promise<{ data, json, attribute, html }>;
```

### TotpKeyProvider

```typescript
import { createTotpKeyProvider, TotpKeyProvider } from '@sesamy/capsule-server';

const totp = createTotpKeyProvider(options: TotpKeyProviderOptions);

interface TotpKeyProviderOptions {
  masterSecret: Buffer | string;   // Required
  bucketPeriodSeconds?: number;    // Default: 30
}

// Get time-bucket keys (current + next for each keyId)
totp.getKeys(keyIds: string[]): Promise<KeyEntry[]>;

// Get static article key
totp.getArticleKey(articleId: string): Promise<KeyEntry>;
```

### SubscriptionServer

```typescript
import { createSubscriptionServer, SubscriptionServer } from '@sesamy/capsule-server';

const server = createSubscriptionServer(options: SubscriptionServerOptions);

interface SubscriptionServerOptions {
  masterSecret: string | Buffer;   // Required
  bucketPeriodSeconds?: number;    // Default: 30
}

// For CMS key fetching (if not using TOTP locally)
server.getBucketKeysResponse(keyId: string): BucketKeysResponse;

// For user unlock (per-article DEK mode)
server.unlockForUser(
  wrappedKey: { keyId, wrappedDek },
  userPublicKey: string,
  staticKeyLookup?: (keyId: string) => Buffer | null
): Promise<UnlockResponse>;

// For tier key mode ("unlock once, access all")
server.getTierKeyForUser(
  tier: string,        // Tier name (e.g., "premium")
  bucketId: string,    // Bucket ID (from the article's keyId)
  userPublicKey: string // Base64 SPKI
): Promise<UnlockResponse>;

// For token-based unlock (share links)
server.unlockWithToken(
  tokenPayload: UnlockTokenPayload,
  wrappedDekB64: string,
  userPublicKey: string,
  articleId?: string
): UnlockResponse;
```

### TokenManager

```typescript
import { createTokenManager, TokenManager } from '@sesamy/capsule-server';

const tokens = createTokenManager(options: TokenManagerOptions);

interface TokenManagerOptions {
  secret: string | Buffer;  // Required, min 32 bytes recommended
}

// Generate a signed token
tokens.generate(options: GenerateTokenOptions): string;

interface GenerateTokenOptions {
  tier: string;              // Required: tier to grant access to
  expiresIn: string | number; // Required: "1h", "24h", "7d", or seconds
  articleId?: string;         // Optional: restrict to article
  maxUses?: number;           // Optional: usage limit
  userId?: string;            // Optional: creator attribution
  meta?: Record<string, any>; // Optional: custom metadata
}

// Validate a token
tokens.validate(token: string): TokenValidationResult | TokenValidationError;

// Peek at payload without validating (for logging)
tokens.peek(token: string): UnlockTokenPayload | null;
```

See [TypeScript definitions](./src/types.ts) for full type documentation.
