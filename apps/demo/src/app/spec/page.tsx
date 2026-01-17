import { CodeBlock } from "@/components/CodeBlock";

export default function SpecPage() {
  return (
    <main className="content-page">
      <h1>Specification</h1>
      <p>
        Capsule is an open standard for client-side article encryption using envelope
        encryption. It enables secure content delivery without requiring server-side
        authentication or permission systems.
      </p>

      <h2>Architecture Overview</h2>
      <p>
        Capsule uses <strong>envelope encryption</strong>, combining the efficiency of
        symmetric encryption (AES-256-GCM) with the key management benefits of asymmetric
        encryption (RSA-OAEP).
      </p>

      <h2>Encryption Flow</h2>

      <h3>1. Server-Side Pre-Encryption</h3>
      <p>
        Content is encrypted at build time or when published using a Data Encryption Key
        (DEK) associated with a subscription tier or individual article.
      </p>
      <CodeBlock>{`// Generate or retrieve DEK for subscription tier
const dek = getSubscriptionKey("premium"); // 256-bit AES key

// Generate unique IV for this article
const iv = randomBytes(12); // 96 bits for GCM

// Encrypt content with AES-256-GCM
const cipher = createCipheriv("aes-256-gcm", dek, iv);
const encrypted = Buffer.concat([
  cipher.update(content),
  cipher.final(),
  cipher.getAuthTag() // 128-bit authentication tag
]);

// Result: { encryptedContent, iv, tier }`}</CodeBlock>

      <h3>2. HTML Embedding</h3>
      <p>
        Encrypted content is embedded directly in the server-rendered HTML, enabling
        offline access and browser caching.
      </p>
      <CodeBlock>{`<template
  id="encrypted-article-123"
  data-encrypted-content="base64-encoded-ciphertext"
  data-iv="base64-encoded-iv"
  data-tier="premium"
/>`}</CodeBlock>

      <h3>3. Client Key Generation</h3>
      <p>
        On first visit, the browser generates an RSA-OAEP key pair using the Web Crypto API.
        The private key is stored in IndexedDB with <code>extractable: false</code>, ensuring
        it cannot be exported or accessed outside the crypto engine.
      </p>
      <CodeBlock>{`const keyPair = await crypto.subtle.generateKey(
  {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
    hash: "SHA-256",
  },
  true, // extractable - needed to export public key and re-import private key
  ["wrapKey", "unwrapKey"]
);

// Export and re-import private key as non-extractable
const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
const nonExtractablePrivateKey = await crypto.subtle.importKey(
  'jwk',
  privateKeyJwk,
  { name: 'RSA-OAEP', hash: 'SHA-256' },
  false, // NOT extractable - key material cannot be exported
  ['unwrapKey']
);

// Store in IndexedDB
await indexedDB.put("keypair", {
  publicKey: keyPair.publicKey,   // extractable: true
  privateKey: nonExtractablePrivateKey  // extractable: false
});`}</CodeBlock>

      <h4>Why Different Extractability?</h4>
      <p>
        The public and private keys have different <code>extractable</code> settings for important
        security and functional reasons:
      </p>
      
      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1rem', marginBottom: '1rem' }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Key</th>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Extractable</th>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Reason</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}><strong>Public Key</strong></td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}><code>true</code></td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>
              Must be exported to SPKI format and sent to the server for DEK wrapping.
              Safe to share - can only <em>encrypt</em>, not <em>decrypt</em>.
            </td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}><strong>Private Key</strong></td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}><code>false</code></td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>
              Must stay locked in the browser's crypto engine. Can only be used for unwrapping DEKs,
              never exported. Guarantees true end-to-end encryption.
            </td>
          </tr>
        </tbody>
      </table>

      <p><strong>Security Implication:</strong></p>
      <p>
        Even if an attacker gains access to IndexedDB (through XSS or browser DevTools), they can see
        the <code>CryptoKey</code> object but cannot extract the private key bytes:
      </p>
      <CodeBlock>{`// Attacker can do this:
const keyPair = await indexedDB.get('keypair', 'default');
console.log(keyPair.privateKey);
// Output: CryptoKey {type: "private", extractable: false, ...}

// But this FAILS:
await crypto.subtle.exportKey('jwk', keyPair.privateKey);
// ❌ Error: "key is not extractable"

// The CryptoKey object is just a handle/reference.
// The actual key material lives in the browser's crypto subsystem
// and cannot be accessed as raw bytes.`}</CodeBlock>

      <p>
        This architectural design ensures that:
      </p>
      <ul>
        <li>✅ Server can wrap DEKs using the public key</li>
        <li>✅ Browser can unwrap DEKs using the private key</li>
        <li>❌ Private key cannot be stolen, even by malicious JavaScript</li>
        <li>❌ Private key cannot be accidentally exported by the user</li>
        <li>❌ Server compromise cannot reveal private keys (they're not on the server)</li>
      </ul>

      <h3>4. Key Exchange Protocol</h3>
      <p>
        When unlocking content, the client sends its public key to the server. The server
        wraps the DEK with the client's public key and returns it.
      </p>
      <CodeBlock language="json">{`// Client → Server
POST /api/unlock
{
  "tier": "premium",
  "publicKey": "base64-encoded-spki-public-key"
}

// Server → Client
{
  "encryptedDek": "base64-rsa-oaep-wrapped-dek",
  "tier": "premium"
}`}</CodeBlock>

      <h3>5. Client-Side Decryption</h3>
      <p>
        The client unwraps the DEK using its private key, then decrypts the content using
        AES-GCM. The unwrapped DEK is cached in memory for the session.
      </p>
      <CodeBlock>{`// Unwrap DEK with private key
const dek = await crypto.subtle.unwrapKey(
  "raw",
  encryptedDek,
  keyPair.privateKey,
  { name: "RSA-OAEP" },
  { name: "AES-GCM", length: 256 },
  false, // non-extractable
  ["decrypt"]
);

// Cache DEK for this tier
dekCache.set(tier, dek);

// Decrypt content
const decrypted = await crypto.subtle.decrypt(
  { name: "AES-GCM", iv },
  dek,
  encryptedContent
);`}</CodeBlock>

      <h2>Multiple DEK Models</h2>

      <h3>Time-Bucket Keys (Recommended)</h3>
      <p>
        Instead of static DEKs, use <strong>time-bucket keys</strong> that rotate every 15 minutes.
        This enables automatic access revocation without re-encrypting content.
      </p>
      <CodeBlock>{`// Article has stable DEK, wrapped with rotating time-bucket keys
{
  articleId: "crypto-guide",
  articleDek: "stable-256-bit-key",
  wrappedDeks: {
    "123456": wrapDek(articleDek, bucketKey_123456),  // Current
    "123457": wrapDek(articleDek, bucketKey_123457)   // Next (15 min)
  }
}

// Bucket keys derived from master secret
function deriveBucketKey(tier, bucketId) {
  return hkdf(masterSecret, bucketId, \`capsule-bucket-\${tier}\`, 32);
}

// When user unlocks:
// 1. Server validates subscription
// 2. Unwraps DEK with current bucket key
// 3. Re-wraps with user's RSA public key
// 4. User caches unwrapped DEK until bucket expires

// Access revocation:
// - Cancelled user's cached DEK expires in ≤15 minutes
// - Server refuses new bucket key requests
// - No content re-encryption needed`}</CodeBlock>

      <p><strong>Benefits:</strong></p>
      <ul>
        <li>✅ Automatic access revocation (15-minute window)</li>
        <li>✅ No content re-encryption needed</li>
        <li>✅ Deterministic keys (derived, not stored)</li>
        <li>✅ CMS gets time-limited keys (not master secret)</li>
      </ul>

      <h3>Subscription-Based (Legacy)</h3>
      <p>
        One DEK per subscription tier. All articles in the tier use the same key.
        One key exchange unlocks all content in that tier.
      </p>
      <ul>
        <li>✅ Minimal server requests</li>
        <li>✅ Offline access after first unlock</li>
        <li>✅ Fast subsequent article access</li>
        <li>⚠️ Revoking access requires re-encrypting all articles</li>
      </ul>

      <h3>Per-Article</h3>
      <p>
        Unique DEK for each article. Requires server request per article.
      </p>
      <ul>
        <li>✅ Fine-grained access control</li>
        <li>✅ Easy revocation (just delete the DEK)</li>
        <li>⚠️ More server requests</li>
        <li>⚠️ Less efficient for many articles</li>
      </ul>

      <h3>Hybrid</h3>
      <p>
        Combination of both. Some articles use tier-level DEKs, others use unique DEKs.
      </p>

      <h2>Multi-Server Architecture</h2>

      <h3>CMS Server ↔ Subscription Server</h3>
      <p>
        Modern Capsule deployments use separate CMS and Subscription servers for security:
      </p>

      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1rem', marginBottom: '1rem' }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Server</th>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Responsibilities</th>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Has Access To</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}><strong>CMS</strong></td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>
              Content management, encryption, publishing
            </td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>
              Plaintext content, time-bucket keys (15-min cache)
            </td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}><strong>Subscription</strong></td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>
              Key management, user auth, access control
            </td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>
              Master secret, bucket keys (derived), user subscriptions
            </td>
          </tr>
        </tbody>
      </table>

      <h4>Authentication Options</h4>
      <p>CMS authenticates with Subscription Server using:</p>
      <ul>
        <li><strong>Option 1: API Key</strong> - Simple shared secret</li>
        <li><strong>Option 2: JWT with Ed25519</strong> - Asymmetric signatures (more secure)</li>
      </ul>

      <CodeBlock>{`// CMS requests bucket keys (API Key)
POST /api/cms/bucket-keys
Authorization: Bearer YOUR_API_KEY
{ "tier": "premium" }

// Response:
{
  "current": {
    "bucketId": "123456",
    "key": "base64-encoded-256-bit-key",
    "expiresAt": "2026-01-16T15:00:00Z"
  },
  "next": { ... }
}`}</CodeBlock>

      <h2>Security Considerations</h2>

      <h2>Security Considerations</h2>

      <h3>Master Secret Protection</h3>
      <p>
        The master secret is the root of all security. If compromised, attackers can derive
        all future bucket keys. <strong>Never</strong> give the master secret to the CMS.
      </p>
      
      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1rem', marginBottom: '1rem' }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Component</th>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Public/Secret</th>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Storage</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Master Secret</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>🔒 SECRET</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>KMS only (Subscription Server)</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Bucket Derivation Algorithm</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>✅ Public</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Open source code</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Bucket Keys</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>🔒 SECRET</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Derived on-demand, cached 15 min on CMS</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Article DEKs</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>🔒 SECRET</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Wrapped (never in plaintext)</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>User Private Keys</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>🔒 SECRET</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Browser IndexedDB (non-extractable)</td>
          </tr>
        </tbody>
      </table>

      <h3>Access Revocation</h3>
      <p>
        With time-bucket keys, access is automatically revoked within the bucket duration (15 minutes):
      </p>
      <ul>
        <li>User's browser caches unwrapped DEK until bucket expires</li>
        <li>When subscription cancelled, server refuses new bucket key requests</li>
        <li>Cached DEK expires → user can no longer decrypt new content</li>
        <li>No content re-encryption needed</li>
      </ul>

      <h3>CMS Compromise Scenarios</h3>
      <p><strong>If CMS is compromised, attacker gets:</strong></p>
      <ul>
        <li>❌ Plaintext content (CMS already has this)</li>
        <li>❌ Current bucket keys (valid for ≤15 minutes)</li>
        <li>✅ Cannot derive future bucket keys (no master secret)</li>
        <li>✅ Cannot decrypt for other users (no user private keys)</li>
      </ul>

      <h3>Subscription Server Compromise Scenarios</h3>
      <p><strong>If Subscription Server is compromised, attacker gets:</strong></p>
      <ul>
        <li>❌ Master secret → can derive all bucket keys</li>
        <li>❌ Can unwrap article DEKs</li>
        <li>✅ Cannot read content (CMS has encrypted content only)</li>
      </ul>

      <p><strong>Mitigation:</strong> Use separate infrastructure, different access controls, audit logs</p>

      <h3>Private Key Protection</h3>
      <p>
        Private keys must be stored with <code>extractable: false</code> in the Web Crypto API.
        This prevents JavaScript from accessing the raw key material.
      </p>

      <h3>DEK Storage</h3>
      <p>
        Server-side DEKs should be stored in a secure key management system (KMS) in production.
        Never hardcode DEKs in source code.
      </p>

      <h3>Transport Security</h3>
      <p>
        The key exchange endpoint must use HTTPS. While the wrapped DEK is encrypted, HTTPS
        prevents MITM attacks on the public key exchange.
      </p>

      <h3>IV Uniqueness</h3>
      <p>
        Each encrypted article must use a unique initialization vector (IV). Never reuse IVs
        with the same DEK, as this breaks AES-GCM security.
      </p>

      <h2>Implementation Checklist</h2>
      <ul>
        <li>✅ AES-256-GCM for content encryption</li>
        <li>✅ RSA-OAEP with SHA-256 for key wrapping</li>
        <li>✅ Unique 96-bit IV per encrypted content</li>
        <li>✅ 128-bit authentication tag (GCM)</li>
        <li>✅ Private keys stored with extractable: false</li>
        <li>✅ HTTPS for key exchange endpoint</li>
        <li>✅ Proper error handling and validation</li>
      </ul>
    </main>
  );
}
