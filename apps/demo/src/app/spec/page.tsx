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
  true, // extractable for public key export
  ["wrapKey", "unwrapKey"]
);

// Store in IndexedDB
await indexedDB.put("keypair", keyPair);`}</CodeBlock>

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

      <h3>Subscription-Based (Recommended)</h3>
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

      <h2>Security Considerations</h2>

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
