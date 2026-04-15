import { CodeBlock } from "@/components/CodeBlock";
import { PageWithToc } from "@/components/PageWithToc";

export default function ServersPage() {
  return (
    <PageWithToc>
      <main className="content-page">
        <h1>Server Implementations</h1>
        <p>
          Capsule implements <strong>Delegated Content Access (DCA)</strong> — a
          two-role delegation model. The <strong>Publisher</strong> encrypts
          content and wraps keys. The <strong>Issuer</strong> verifies access
          and unwraps keys. The <code>@sesamy/capsule-server</code> package
          provides both roles.
        </p>

        <h2>Quick Start</h2>
        <CodeBlock language="bash">{`npm install @sesamy/capsule-server`}</CodeBlock>

        <h3>Publisher: Encrypting Content</h3>
        <p>
          The publisher encrypts content at render time. No network calls — all
          key derivation is local from a <code>rotationSecret</code>:
        </p>
        <CodeBlock>{`import { createDcaPublisher } from '@sesamy/capsule-server';

const publisher = createDcaPublisher({
  domain: "news.example.com",
  signingKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY!,
  rotationSecret: process.env.ROTATION_SECRET!,
  rotationIntervalHours: 1, // default: 1-hour rotation
});

const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", content: "<p>Premium article body…</p>" },
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
  resourceData: { title: "My Article", author: "Jane Doe" },
});

// result.html.manifestScript → <script> tag to embed in <head>
// result.json                → JSON API variant (for SPAs/mobile)`}</CodeBlock>

        <h3>Issuer: Unlock Endpoint</h3>
        <p>
          The issuer verifies JWTs, checks access, and unwraps keys:
        </p>
        <CodeBlock>{`import { createDcaIssuer } from '@sesamy/capsule-server';

const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
  keyId: "2025-10",
  trustedPublisherKeys: {
    "news.example.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
  },
});

// POST /api/unlock
app.post('/api/unlock', async (req, res) => {
  const result = await issuer.unlock(req.body, {
    grantedContentNames: ["bodytext"], // Your access decision
    deliveryMode: "direct",            // or "wrapKey" for caching
  });
  res.json(result);
});`}</CodeBlock>

        <h2>Architecture Overview</h2>

        <h3>Publisher (CMS/Build Side)</h3>
        <ul>
          <li>✅ Encrypts content with AES-256-GCM + AAD</li>
          <li>✅ Derives wrapKeys locally via HKDF (from <code>rotationSecret</code>)</li>
          <li>✅ Wraps contentKeys and wrapKeys for each issuer (ECDH P-256)</li>
          <li>✅ Signs <code>resourceJWT</code> (ES256)</li>
          <li>✅ Embeds the DCA manifest and wrapped content in HTML</li>
          <li>❌ Never has user keys or subscription data</li>
        </ul>

        <h3>Issuer (Unlock Server)</h3>
        <ul>
          <li>✅ Verifies publisher JWT signatures (trusted-publisher allowlist)</li>
          <li>✅ Verifies integrity proofs for wrapped blobs</li>
          <li>✅ Makes access decisions (subscription check, share token, etc.)</li>
          <li>✅ Unwraps keys with its ECDH private key</li>
          <li>✅ Optionally wraps keys with client&apos;s RSA public key (client-bound transport)</li>
          <li>❌ Never sees article content or the publisher&apos;s <code>rotationSecret</code></li>
        </ul>

        <h3>Flow Diagram</h3>
        <pre className="diagram">{`
┌─────────────────────────┐
│       Publisher          │
│  (Content + Encryption)  │
│                          │
│  rotationSecret (local)  │
│  ES256 signing key       │
└──────────┬───────────────┘
           │
           │ 1. Render: encrypt content, wrap keys,
           │    sign resourceJWT, embed in HTML
           ▼
┌─────────────────────────┐
│     Static HTML / CDN   │
│                          │
│  dca-manifest (JSON)     │
│  wrapped content         │
│  resourceJWT             │
└──────────┬───────────────┘
           │
           │ 2. Browser loads page, finds DCA content
           ▼
┌─────────────────┐     ┌─────────────────────┐
│     Browser     │────►│       Issuer         │
│  (DCA Client)   │     │  (Unlock Server)     │
│                 │◄────│                      │
└─────────────────┘     │  Verifies JWTs       │
  3. Send unlock req    │  Checks access       │
     (wrapped keys,     │  Unwraps with ECDH   │
      JWT, kid)         │  private key         │
                        └──────────────────────┘
  4. Receive unwrapped
     keys, decrypt
     content locally
      `}</pre>

        <h2>Publisher Configuration</h2>

        <h3>Key Setup</h3>
        <p>
          The publisher needs two secrets:
        </p>
        <ol>
          <li>
            <strong>ES256 signing key</strong> (ECDSA P-256): for signing{" "}
            <code>resourceJWT</code> and share link tokens
          </li>
          <li>
            <strong>Rotation secret</strong>: for HKDF-based wrapKey derivation
            (never shared with the issuer)
          </li>
        </ol>

        <CodeBlock>{`import { generateEcdsaP256KeyPair, exportP256KeyPairPem } from '@sesamy/capsule-server';

// Generate an ES256 key pair (do this once, store securely)
const keyPair = await generateEcdsaP256KeyPair();
const pem = await exportP256KeyPairPem(keyPair);
// pem.privateKeyPem → store in KMS / env var
// pem.publicKeyPem  → share with issuers

// Generate a rotation secret (do this once, store securely)
import crypto from 'crypto';
const rotationSecret = crypto.randomBytes(32).toString('base64');`}</CodeBlock>

        <h3>DcaPublisherConfig</h3>
        <CodeBlock>{`interface DcaPublisherConfig {
  domain: string;                    // Publisher domain (e.g., "news.example.com")
  signingKeyPem: string;             // ES256 private key PEM
  rotationSecret: string | Uint8Array; // Rotation secret (base64 or raw bytes)
  rotationIntervalHours?: number;    // WrapKey rotation interval (default: 1 hour)
}`}</CodeBlock>

        <h3>Render Options</h3>
        <CodeBlock>{`interface DcaRenderOptions {
  resourceId: string;          // Unique article/resource identifier
  contentItems: Array<{
    contentName: string;       // e.g., "bodytext", "sidebar"
    scope?: string;            // Access scope (defaults to contentName).
                               // Items sharing a scope share a wrapKey.
    content: string;           // Plaintext content to encrypt
    contentType?: string;      // MIME type (default: "text/html")
  }>;
  issuers: Array<{
    issuerName: string;        // Issuer's canonical name
    publicKeyPem: string;      // Issuer's ECDH P-256 public key PEM
    keyId: string;             // Identifies which issuer private key matches
    unlockUrl: string;         // Issuer's unlock endpoint URL
    contentNames?: string[];   // Which content items this issuer gets keys for
    scopes?: string[];         // Or: which scopes this issuer gets keys for
  }>;
  resourceData?: Record<string, unknown>; // Publisher metadata for access decisions
}`}</CodeBlock>

        <h3>Render Result</h3>
        <p>
          The publisher returns a single HTML string ready to embed, plus a JSON
          variant for headless/SPA use. The manifest is self-contained — per
          v1, ciphertext lives inside the manifest, so there is no separate
          content template:
        </p>
        <CodeBlock>{`const result = await publisher.render({ ... });

// HTML embedding (SSR / static site):
// Embed in <head> (or anywhere in the document):
result.html.manifestScript;
// → <script type="application/json" class="dca-manifest">{...}</script>

// Target elements for decrypted content use data-dca-content-name:
// <div data-dca-content-name="bodytext"></div>

// JSON API (headless CMS / mobile) — this IS the manifest:
result.json;
// → { version: "0.10", resourceJWT, content: { ... }, issuers: { ... } }`}</CodeBlock>

        <h3>Manifest Shape</h3>
        <p>
          For reference, the manifest embedded in the{" "}
          <code>dca-manifest</code> script has this shape:
        </p>
        <CodeBlock language="json">{`{
  "version": "0.10",
  "resourceJWT": "eyJhbGciOi...",
  "content": {
    "bodytext": {
      "contentType": "text/html",
      "iv": "base64url_12_bytes",
      "aad": "...",
      "ciphertext": "base64url_gcm_output",
      "wrappedContentKey": [
        { "kid": "251023T13", "iv": "...", "ciphertext": "..." },
        { "kid": "251023T14", "iv": "...", "ciphertext": "..." }
      ]
    }
  },
  "issuers": {
    "sesamy": {
      "unlockUrl": "https://api.sesamy.com/unlock",
      "keyId": "2025-10",
      "keys": [
        {
          "contentName": "bodytext",
          "scope": "bodytext",
          "contentKey": "base64url_wrapped_for_issuer",
          "wrapKeys": [
            { "kid": "251023T13", "key": "base64url_wrapped_for_issuer" },
            { "kid": "251023T14", "key": "base64url_wrapped_for_issuer" }
          ]
        }
      ]
    }
  }
}`}</CodeBlock>

        <h2>Issuer Configuration</h2>

        <h3>Key Setup</h3>
        <p>
          The issuer needs an ECDH P-256 key pair for unwrapping:
        </p>
        <CodeBlock>{`import { generateEcdhP256KeyPair, exportP256KeyPairPem } from '@sesamy/capsule-server';

// Generate an ECDH P-256 key pair (do this once, store securely)
const keyPair = await generateEcdhP256KeyPair();
const pem = await exportP256KeyPairPem(keyPair);
// pem.privateKeyPem → store in KMS / env var (issuer keeps this)
// pem.publicKeyPem  → share with publishers (they wrap keys with it)`}</CodeBlock>

        <h3>DcaIssuerServerConfig</h3>
        <CodeBlock>{`interface DcaIssuerServerConfig {
  issuerName: string;          // Must match what publishers use
  privateKeyPem: string;       // ECDH P-256 private key PEM
  keyId: string;               // Must match what publishers reference
  trustedPublisherKeys: {
    // Map of publisher domain → ES256 public key PEM (or extended config)
    [domain: string]: string | {
      signingKeyPem: string;
      allowedResourceIds?: (string | RegExp)[];  // Optional constraint
    };
  };
}`}</CodeBlock>

        <h3>Trusted-Publisher Allowlist</h3>
        <p>
          Every publisher domain must be explicitly listed. Requests from
          unlisted domains are rejected. Domains are normalized (lowercase,
          trailing dots stripped):
        </p>
        <CodeBlock>{`const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
  keyId: "2025-10",
  trustedPublisherKeys: {
    // Simple: accept any resourceId from this domain
    "news.example.com": process.env.NEWS_ES256_PUB!,

    // Extended: restrict which resourceIds this domain can claim
    "blog.example.com": {
      signingKeyPem: process.env.BLOG_ES256_PUB!,
      allowedResourceIds: ["article-1", /^premium-/],
    },
  },
});`}</CodeBlock>

        <h2>Unlock Endpoint</h2>

        <h3>Access Decision</h3>
        <p>
          The issuer decides which content items (or scopes) to grant and how
          to deliver keys:
        </p>
        <CodeBlock>{`const result = await issuer.unlock(request, {
  // Which content items to grant access to (by contentName)…
  grantedContentNames: ["bodytext"],
  // …or which scopes to grant (mutually exclusive with grantedContentNames)
  // grantedScopes: ["premium"],

  // Key delivery mode:
  //   "direct"  — return the contentKey directly (most common)
  //   "wrapKey" — return wrapKeys (client caches and unwraps locally)
  deliveryMode: "direct",
});`}</CodeBlock>

        <h3>Full Unlock Handler (Next.js)</h3>
        <CodeBlock>{`import { createDcaIssuer } from '@sesamy/capsule-server';
import type { DcaUnlockRequest } from '@sesamy/capsule-server';

const issuer = createDcaIssuer({ /* config */ });

export async function POST(request: Request) {
  const body = await request.json() as DcaUnlockRequest;

  // Share link token flow
  if (body.shareToken) {
    const result = await issuer.unlockWithShareToken(body, {
      deliveryMode: "direct",
      onShareToken: async (payload) => {
        console.log(\`Share: \${payload.resourceId}, jti=\${payload.jti}\`);
        // Throw to reject: throw new Error("Usage limit exceeded");
      },
    });
    return Response.json(result);
  }

  // Normal subscription flow: check user access
  const user = await getUserFromSession(request);
  if (!user?.hasActiveSubscription) {
    return Response.json({ error: "No active subscription" }, { status: 403 });
  }

  const result = await issuer.unlock(body, {
    grantedContentNames: ["bodytext"],
    deliveryMode: "direct",
  });

  return Response.json(result);
}`}</CodeBlock>

        <h3>Pre-Flight Verification</h3>
        <p>
          Verify request JWTs without unwrapping, useful for access checks
          before committing:
        </p>
        <CodeBlock>{`const verified = await issuer.verify(request);
// verified.resource  — the verified DcaResource (publisher domain, resourceId, etc.)
// verified.domain    — normalised publisher domain`}</CodeBlock>

        <h2>WrapKeys and Rotation</h2>
        <p>
          The publisher derives <strong>wrapKeys</strong> locally using HKDF
          from the <code>rotationSecret</code>. These rotate automatically
          based on <code>rotationIntervalHours</code>, enabling subscription
          revocation without re-encrypting content.
        </p>

        <h3>How It Works</h3>
        <CodeBlock>{`// WrapKey derivation (internal to the publisher):
//   IKM  = rotationSecret
//   salt = scope (items sharing a scope share a wrapKey)
//   info = "dca|" + kid (e.g., "dca|251023T13")
//   len  = 32 bytes (AES-256)
//
// The publisher wraps each contentKey with the current and next wrapKeys
// (for rotation overlap). Both are wrapped with the issuer's ECDH key.
//
// Revocation flow:
//   1. User subscription lapses
//   2. Issuer refuses to unwrap keys for that user
//   3. When the kid rotates, the browser no longer has a valid wrapKey
//   4. Even cached wrapKeys expire — no need to re-encrypt content`}</CodeBlock>

        <h3>Rotation Table</h3>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "1rem",
            marginBottom: "1rem",
          }}
        >
          <thead>
            <tr>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Setting
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                kid Format
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Revocation Window
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                <code>rotationIntervalHours: 1</code> (default)
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                <code>251023T13</code>
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Up to 1 hour
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                <code>rotationIntervalHours: 24</code>
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                <code>251023T00</code>
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Up to 24 hours
              </td>
            </tr>
          </tbody>
        </table>

        <h2>Security Best Practices</h2>
        <ul>
          <li>
            🔒 <strong>Store secrets in KMS</strong> (AWS Secrets Manager,
            Google Secret Manager, HashiCorp Vault)
          </li>
          <li>
            🔒 <strong>Use HTTPS</strong> for all API endpoints
          </li>
          <li>
            🔒 <strong>Rate limit</strong> unlock endpoints
          </li>
          <li>
            🔒 <strong>Log requests with redaction</strong> — never log raw
            keys or credentials; truncate identifiers in audit logs
          </li>
          <li>
            🔒 <strong>Rotate signing keys</strong> periodically — use overlapping
            key IDs so outstanding JWTs remain valid during transition
          </li>
        </ul>

        <h4>Key Management</h4>
        <ul>
          <li>
            <strong>Publisher ES256 key</strong> — store private key in KMS;
            share the public key PEM with each issuer
          </li>
          <li>
            <strong>Issuer ECDH P-256 key</strong> — store private key in KMS;
            share the public key PEM with each publisher
          </li>
          <li>
            <strong>Rotation secret</strong> — publisher-only; never shared
            with the issuer (DCA boundary)
          </li>
          <li>
            <strong>One key pair per role</strong> — do not reuse keys across
            issuers or publishers
          </li>
        </ul>

        <h2>Share Link Tokens</h2>
        <p>
          Share links allow pre-authenticated access to premium content. In the
          DCA model, share tokens are <strong>ES256-signed JWTs</strong> created
          by the publisher — they serve as authorization grants without carrying
          any key material.
        </p>

        <h3>Token Generation (Publisher)</h3>
        <p>
          The publisher creates share tokens using the same signing key that
          signs <code>resourceJWT</code>:
        </p>
        <CodeBlock>{`import { createDcaPublisher } from '@sesamy/capsule-server';

const publisher = createDcaPublisher({
  domain: "news.example.com",
  signingKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY!,
  rotationSecret: process.env.ROTATION_SECRET!,
});

const token = await publisher.createShareLinkToken({
  resourceId: "article-123",
  contentNames: ["bodytext"],       // Which content items to grant access to
  expiresIn: 7 * 24 * 3600,        // 7 days (default)
  maxUses: 50,                      // Optional: advisory usage limit
  jti: "share-" + crypto.randomUUID(), // Optional: for tracking/revocation
  data: { campaign: "twitter" },    // Optional: publisher metadata
});

const shareUrl = \`https://news.example.com/article/123?share=\${token}\`;`}</CodeBlock>

        <h3>Token Validation (Issuer)</h3>
        <p>
          The issuer validates share tokens using the publisher&apos;s ES256
          public key, which is already in the <code>trustedPublisherKeys</code>{" "}
          allowlist:
        </p>
        <CodeBlock>{`import { createDcaIssuer } from '@sesamy/capsule-server';

const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
  keyId: "2025-10",
  trustedPublisherKeys: {
    "news.example.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
  },
});

// In /api/unlock handler:
if (body.shareToken) {
  const result = await issuer.unlockWithShareToken(body, {
    deliveryMode: "direct",
    onShareToken: async (payload) => {
      // Optional: track usage, enforce maxUses, audit
      console.log(\`Share token used: \${payload.jti}\`);
    },
  });
  return Response.json(result);
}

// Standalone verification (for pre-flight checks):
const payload = await issuer.verifyShareToken(token, "news.example.com");`}</CodeBlock>

        <h3>Why No <code>rotationSecret</code> Is Needed</h3>
        <p>
          The share token is purely an authorization grant — it replaces the
          subscription check. The key material already flows through the normal
          DCA channel: the publisher wraps keys with the issuer&apos;s ECDH
          public key at render time, and the issuer unwraps them with its
          private key at unlock time. The <code>rotationSecret</code> never
          leaves the publisher.
        </p>

        <h2>Node.js</h2>
        <p>
          The <code>@sesamy/capsule-server</code> package uses the Web Crypto
          API (available in Node.js 18+) for all cryptographic operations.
        </p>

        <h3>Installation</h3>
        <CodeBlock language="bash">{`npm install @sesamy/capsule-server`}</CodeBlock>

        <h3>Complete Publisher Example</h3>
        <CodeBlock>{`import { createDcaPublisher } from '@sesamy/capsule-server';

const publisher = createDcaPublisher({
  domain: "news.example.com",
  signingKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY!,
  rotationSecret: process.env.ROTATION_SECRET!,
});

// Render encrypted article
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", content: "<p>Premium article body…</p>" },
  ],
  issuers: [
    {
      issuerName: "sesamy",
      publicKeyPem: process.env.SESAMY_ECDH_PUBLIC_KEY!,
      keyId: "2025-10",
      unlockUrl: "/api/unlock",
      contentNames: ["bodytext"],
    },
  ],
});

// Embed in HTML template:
// <head>  \${result.html.manifestScript}  </head>`}</CodeBlock>

        <h3>Complete Issuer Example (Next.js)</h3>
        <CodeBlock>{`// app/api/unlock/route.ts
import { createDcaIssuer } from '@sesamy/capsule-server';
import type { DcaUnlockRequest } from '@sesamy/capsule-server';

const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
  keyId: "2025-10",
  trustedPublisherKeys: {
    "news.example.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
  },
});

export async function POST(request: Request) {
  const body = await request.json() as DcaUnlockRequest;

  // Share link token flow
  if (body.shareToken) {
    return Response.json(
      await issuer.unlockWithShareToken(body, { deliveryMode: "direct" })
    );
  }

  // Normal flow: check subscription, then unlock
  return Response.json(
    await issuer.unlock(body, {
      grantedContentNames: ["bodytext"],
      deliveryMode: "direct",
    })
  );
}`}</CodeBlock>

        <h3>Low-Level Crypto Utilities</h3>
        <p>
          The package also exports low-level primitives for custom
          implementations:
        </p>
        <CodeBlock>{`import {
  // Key generation
  generateEcdsaP256KeyPair,   // ES256 signing key pair
  generateEcdhP256KeyPair,    // ECDH P-256 wrapping key pair
  exportP256KeyPairPem,       // Export key pair as PEM strings
  generateAesKeyBytes,        // Random 32-byte AES key

  // Encryption
  encryptContent,             // AES-256-GCM encrypt with AAD
  decryptContent,             // AES-256-GCM decrypt with AAD
  wrapContentKey,             // AES-GCM key wrapping
  unwrapContentKey,           // AES-GCM key unwrapping

  // JWT
  createJwt,                  // Sign ES256 JWT
  verifyJwt,                  // Verify ES256 JWT
  decodeJwtPayload,           // Decode without verification

  // Wrapping (ECDH P-256 / RSA-OAEP)
  wrap,                       // Wrap key material for an issuer
  unwrap,                     // Unwrap key material
  wrapEcdhP256,               // ECDH P-256 wrap
  unwrapEcdhP256,             // ECDH P-256 unwrap

  // Rotation (kid derivation)
  formatTimeKid,              // Format Date → "251023T13"
  getCurrentRotationVersions, // Get current + next kid
  deriveWrapKey,              // HKDF wrapKey derivation

  // Encoding
  toBase64Url, fromBase64Url, toBase64, fromBase64,
} from '@sesamy/capsule-server';`}</CodeBlock>

        <h2>Other Languages</h2>
        <p>
          The DCA protocol uses standard cryptographic primitives (AES-256-GCM,
          ECDH P-256, ES256, HKDF) available in all major languages. Below are
          low-level reference examples for the raw encryption and key-wrapping
          operations. A full DCA implementation would also need JWT signing,
          ECDH wrapping, and the DCA manifest format — see the{" "}
          <a href="/spec">specification</a> for details.
        </p>

        <h3>PHP</h3>
        <CodeBlock language="php">{`<?php

// Encrypt content
$contentKey = random_bytes(32); // AES-256 key
$iv = random_bytes(12);  // GCM IV

$encrypted = openssl_encrypt(
    $content,
    'aes-256-gcm',
    $contentKey,
    OPENSSL_RAW_DATA,
    $iv,
    $tag
);

$result = [
    'encryptedContent' => base64_encode($encrypted . $tag),
    'iv' => base64_encode($iv),
    'contentId' => 'premium'
];`}</CodeBlock>

        <h3>Key Exchange Endpoint</h3>
        <CodeBlock language="php">{`<?php

// api/unlock.php
header('Content-Type: application/json');

$input = json_decode(file_get_contents('php://input'), true);
$contentId = $input['contentId'];
$publicKey = $input['publicKey'];

// Get content key for contentId
$contentKey = getContentKeyForContentId($contentId);

// Convert SPKI to PEM
$publicKeyPem = convertSpkiToPem($publicKey);

// Wrap content key with RSA-OAEP
$encryptedContentKey = '';
openssl_public_encrypt(
    $contentKey,
    $encryptedContentKey,
    $publicKeyPem,
    OPENSSL_PKCS1_OAEP_PADDING
);

echo json_encode([
    'encryptedContentKey' => base64_encode($encryptedContentKey),
    'contentId' => $contentId
]);

function convertSpkiToPem($base64Spki) {
    $der = base64_decode($base64Spki);
    $pem = "-----BEGIN PUBLIC KEY-----\\n";
    $pem .= chunk_split(base64_encode($der), 64);
    $pem .= "-----END PUBLIC KEY-----";
    return $pem;
}`}</CodeBlock>

        <h2>Python</h2>
        <p>
          Python support using the <code>cryptography</code> library.
        </p>

        <h3>Installation</h3>
        <CodeBlock language="bash">{`pip install cryptography`}</CodeBlock>

        <h3>Basic Usage</h3>
        <CodeBlock language="python">{`from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import base64

# Encrypt content
def encrypt_article(content: str, contentKey: bytes) -> dict:
    iv = os.urandom(12)
    aesgcm = AESGCM(contentKey)
    ciphertext = aesgcm.encrypt(iv, content.encode(), None)

    return {
        'encryptedContent': base64.b64encode(ciphertext).decode(),
        'iv': base64.b64encode(iv).decode(),
        'contentId': 'premium'
    }

# Wrap content key
def wrap_content_key(content_key: bytes, public_key_spki: str) -> str:
    # Load public key from SPKI
    public_key = serialization.load_der_public_key(
        base64.b64decode(public_key_spki)
    )

    # Wrap with RSA-OAEP
    encrypted = public_key.encrypt(
        content_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted).decode()`}</CodeBlock>

        <h2>Coming Soon</h2>
        <ul>
          <li>🔨 Go implementation</li>
          <li>🔨 Ruby implementation</li>
          <li>🔨 Rust implementation</li>
          <li>🔨 .NET implementation</li>
        </ul>

        <p>
          Want to contribute an implementation? Check out the{" "}
          <a href="https://github.com/capsule-standard/capsule">
            GitHub repository
          </a>
          .
        </p>
      </main>
    </PageWithToc>
  );
}
