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
        Content is encrypted at build time or when published. A unique Data Encryption Key
        (DEK) is generated for each article, then wrapped with one or more key-wrapping keys
        to enable different unlock paths.
      </p>
      <CodeBlock>{`// Generate unique DEK for this article
const contentDek = randomBytes(32); // 256-bit AES key

// Generate unique IV for this article
const iv = randomBytes(12); // 96 bits for GCM

// Encrypt content ONCE with AES-256-GCM
const cipher = createCipheriv("aes-256-gcm", contentDek, iv);
const encrypted = Buffer.concat([
  cipher.update(content),
  cipher.final(),
  cipher.getAuthTag() // 128-bit authentication tag
]);

// Wrap the DEK with multiple key-wrapping keys
const wrappedKeys = {
  // Time-bucket keys for subscription access (rotates every 15 min)
  [\`premium:\${currentBucketId}\`]: wrapKey(contentDek, currentBucketKey),
  [\`premium:\${nextBucketId}\`]: wrapKey(contentDek, nextBucketKey),
  
  // Static key for per-article purchase (permanent)
  [\`article:\${articleId}\`]: wrapKey(contentDek, articleSpecificKey),
};

// Result: { encryptedContent, iv, wrappedKeys }`}</CodeBlock>

      <h3>2. HTML Embedding</h3>
      <p>
        Encrypted content is embedded directly in the server-rendered HTML, enabling
        offline access and browser caching. Each article includes the ciphertext and
        wrapped keys for the supported unlock paths.
      </p>
      <CodeBlock>{`<template
  id="encrypted-article-123"
  data-encrypted-content="base64-encoded-ciphertext"
  data-iv="base64-encoded-iv"
  data-wrapped-keys='{
    "premium:123456": "base64-wrapped-dek",
    "premium:123457": "base64-wrapped-dek",
    "article:crypto-guide": "base64-wrapped-dek"
  }'
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
        When unlocking content, the client sends its public key and the key ID it wants to use.
        The server validates access, unwraps the content DEK using the appropriate key-wrapping key,
        then re-wraps it with the client's public key.
      </p>
      <CodeBlock language="json">{`// Client → Server
POST /api/unlock
{
  "keyId": "premium",           // or "article:crypto-guide"
  "publicKey": "base64-encoded-spki-public-key",
  "bucketId": "123456"          // optional, for time-bucket keys
}

// Server validates access, then:
// 1. Gets key-wrapping key for this keyId (derived or looked up)
// 2. Unwraps the content DEK from the article's wrappedKeys
// 3. Re-wraps DEK with client's RSA public key

// Server → Client
{
  "encryptedDek": "base64-rsa-oaep-wrapped-dek",
  "keyId": "premium",
  "bucketId": "123456",
  "expiresAt": "2026-01-17T12:15:00Z"  // when client should re-request
}`}</CodeBlock>

      <h3>5. Client-Side Decryption</h3>
      <p>
        The client unwraps the DEK using its private key, then decrypts the content using
        AES-GCM. The unwrapped DEK is cached in memory until expiration.
      </p>
      <CodeBlock>{`// Unwrap content DEK with private key
const contentDek = await crypto.subtle.unwrapKey(
  "raw",
  encryptedDek,
  keyPair.privateKey,
  { name: "RSA-OAEP" },
  { name: "AES-GCM", length: 256 },
  false, // non-extractable
  ["decrypt"]
);

// Cache DEK for this keyId until expiration
dekCache.set(keyId, { dek: contentDek, expiresAt });

// Decrypt content
const decrypted = await crypto.subtle.decrypt(
  { name: "AES-GCM", iv },
  contentDek,
  encryptedContent
);`}</CodeBlock>

      <h3>6. Handling Decrypted Content in Scripts</h3>
      <p>
        Since content is decrypted client-side <em>after</em> the initial page load, any scripts 
        that need to process the content (syntax highlighting, analytics, interactive widgets, etc.) 
        must run after decryption completes. There are two approaches:
      </p>

      <h4>Option A: Listen for the <code>capsule:unlocked</code> Event</h4>
      <p>
        Capsule dispatches a custom event when content is decrypted and added to the DOM:
      </p>
      <CodeBlock>{`document.addEventListener("capsule:unlocked", (event) => {
  const { articleId, element, keyId } = event.detail;
  
  // element is the DOM container with the decrypted content
  // Run your initialization code here
  highlightCodeBlocks(element);
  initializeWidgets(element);
  
  console.log(\`Article "\${articleId}" unlocked with key: \${keyId}\`);
});`}</CodeBlock>

      <h4>Option B: Use a MutationObserver</h4>
      <p>
        For more generic DOM change detection, use a <code>MutationObserver</code>:
      </p>
      <CodeBlock>{`const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node instanceof HTMLElement) {
        // Check if this is unlocked content
        if (node.classList.contains("premium-content")) {
          initializeContent(node);
        }
      }
    }
  }
});

// Observe the container where encrypted sections appear
observer.observe(document.body, { 
  childList: true, 
  subtree: true 
});`}</CodeBlock>

      <h2>Key Architecture</h2>

      <h3>Two-Layer Encryption</h3>
      <p>
        Each piece of content uses <strong>two-layer envelope encryption</strong>:
      </p>
      <ol>
        <li><strong>Content DEK</strong> - A unique AES-256 key generated for each article at encryption time. 
        This encrypts the actual content (fast, efficient symmetric encryption).</li>
        <li><strong>Key-wrapping keys</strong> - The content DEK is then <em>wrapped</em> (encrypted) with 
        one or more key-wrapping keys. Each wrapped copy allows a different unlock path.</li>
      </ol>

      <CodeBlock>{`// Article encryption at build/publish time
{
  articleId: "crypto-guide",
  
  // Content encrypted ONCE with unique DEK
  encryptedContent: encrypt(content, contentDek),
  iv: "unique-iv-for-this-article",
  
  // DEK wrapped with MULTIPLE keys for different unlock paths
  wrappedKeys: {
    // Tier access: wrapped with time-bucket keys
    "premium:bucket-123456": wrap(contentDek, bucketKey_123456),
    "premium:bucket-123457": wrap(contentDek, bucketKey_123457),
    
    // Article-specific access (permanent)
    "article:crypto-guide": wrap(contentDek, articleSpecificKey),
    
    // Different subscription server
    "partner:acme-corp": wrap(contentDek, partnerKey),
  }
}`}</CodeBlock>

      <h3>Multiple Unlock Paths</h3>
      <p>
        The same content can be unlocked through different key IDs. Each key ID represents 
        a different access path:
      </p>
      
      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1rem', marginBottom: '1rem' }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Key ID Type</th>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Example</th>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '2px solid #333' }}>Use Case</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Subscription tier</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}><code>premium</code></td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>User has premium subscription</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Article ID</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}><code>crypto-guide</code></td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>User purchased this specific article</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Partner/Server</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}><code>partner:acme</code></td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Different subscription provider</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Time bucket</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}><code>premium:123456</code></td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #ddd' }}>Current 15-minute window</td>
          </tr>
        </tbody>
      </table>

      <h3>Example: Article with Multiple Access Paths</h3>
      <p>
        Consider an article that can be unlocked via subscription OR individual purchase, 
        with 2 time buckets (current + next) for the subscription path:
      </p>

      <CodeBlock>{`// 4 wrapped keys for this article:
wrappedKeys: {
  // Subscription tier (with time buckets for revocation)
  "premium:bucket-current": wrap(dek, currentBucketKey),  // Expires in ≤15 min
  "premium:bucket-next": wrap(dek, nextBucketKey),        // Handles clock drift
  
  // Per-article purchase (permanent access)
  "article:crypto-guide": wrap(dek, articleKey),
  
  // Note: Only ONE of these needs to succeed for decryption
}`}</CodeBlock>

      <h3>Time-Bucket Keys</h3>
      <p>
        For subscription-based access, <strong>time-bucket keys</strong> rotate every 15 minutes.
        This enables automatic access revocation without re-encrypting content.
      </p>
      <CodeBlock>{`// Bucket keys derived deterministically from master secret
function deriveBucketKey(tier, bucketId) {
  return hkdf(masterSecret, bucketId, \`capsule-bucket-\${tier}\`, 32);
}

// When user unlocks via subscription:
// 1. Server validates active subscription
// 2. Gets current bucket key (derived from master secret)
// 3. Unwraps content DEK using bucket key
// 4. Re-wraps DEK with user's RSA public key
// 5. User caches unwrapped DEK until bucket expires

// Access revocation (subscription cancelled):
// - User's cached DEK expires in ≤15 minutes
// - Server refuses new unlock requests
// - No content re-encryption needed`}</CodeBlock>

      <p><strong>Benefits of time buckets:</strong></p>
      <ul>
        <li>✅ Automatic access revocation (15-minute window)</li>
        <li>✅ No content re-encryption needed when subscriptions change</li>
        <li>✅ Deterministic keys (derived, not stored)</li>
        <li>✅ CMS gets time-limited keys (not master secret)</li>
      </ul>

      <h3>Static Keys (Per-Article Purchases)</h3>
      <p>
        For permanent access (e.g., article purchases), static keys don't rotate:
      </p>
      <ul>
        <li>✅ Permanent access once unlocked</li>
        <li>✅ No ongoing server requests needed</li>
        <li>⚠️ Revocation requires re-encrypting the content</li>
      </ul>

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

      <h2>Flow Summary</h2>
      <p>
        A simplified view of the complete encryption and decryption flow:
      </p>
      <CodeBlock>{`// 1. CMS encrypts article
DEK = generateRandomKey(256)
ciphertext = AES-GCM-Encrypt(DEK, articleContent)
for each tier in [premium, basic]:
  for each bucket in [current, next]:
    KEK = HKDF(masterSecret, tier + ":" + bucket)
    wrappedDek = AES-GCM-Wrap(KEK, DEK)

// 2. Client requests tier access
POST /api/unlock { keyId: "premium:57906340", publicKey }

// 3. Server wraps KEK with client's public key
KEK = HKDF(masterSecret, "premium:57906340")
encryptedKEK = RSA-OAEP-Encrypt(clientPublicKey, KEK)

// 4. Client unwraps KEK and caches it
KEK = RSA-OAEP-Decrypt(privateKey, encryptedKEK)
IndexedDB.store("tier:premium:57906340", KEK)

// 5. Client decrypts content (no network needed!)
DEK = AES-GCM-Unwrap(KEK, article.wrappedKeys["premium:57906340"])
plaintext = AES-GCM-Decrypt(DEK, article.ciphertext, article.iv)

// 6. Subsequent articles use cached KEK - "unlock once, access all"`}</CodeBlock>

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

      <h2>Security Properties</h2>
      
      <h3>What Capsule Provides</h3>
      <ul>
        <li>✅ <strong>Confidentiality:</strong> Content encrypted at rest and in transit</li>
        <li>✅ <strong>Integrity:</strong> AES-GCM authentication detects tampering</li>
        <li>✅ <strong>Forward Secrecy:</strong> Time buckets limit exposure window</li>
        <li>✅ <strong>Secure Key Transport:</strong> RSA-OAEP for key exchange</li>
        <li>✅ <strong>Offline Access:</strong> Cached keys work without network</li>
        <li>✅ <strong>No Server-Side User Tracking:</strong> Keys are bearer tokens</li>
      </ul>

      <h3>What Capsule Does NOT Provide</h3>
      <ul>
        <li>❌ <strong>DRM:</strong> Determined users can extract decrypted content</li>
        <li>❌ <strong>Copy Protection:</strong> Once decrypted, content can be copied</li>
        <li>❌ <strong>Watermarking:</strong> No user-specific content marking</li>
      </ul>
      <p>
        Capsule is designed for honest users who want convenient access, not for 
        preventing determined adversaries from extracting content.
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
