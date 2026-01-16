import { CodeBlock } from "@/components/CodeBlock";

export default function ClientPage() {
  return (
    <main className="content-page">
      <h1>Client Integration</h1>
      <p>
        The Capsule client is a lightweight browser library that handles key management
        and content decryption using the Web Crypto API.
      </p>

      <h2>Installation</h2>
      <CodeBlock language="bash">{`npm install capsule-client`}</CodeBlock>

      <h2>Basic Usage</h2>
      <CodeBlock>{`import { CapsuleClient } from 'capsule-client';

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
import { CapsuleClient } from 'capsule-client';

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
        For subscription-based models, cache unwrapped DEKs to avoid repeated server requests:
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

      <h2>Browser Compatibility</h2>
      <p>Capsule requires the Web Crypto API, which is available in:</p>
      <ul>
        <li>✅ Chrome 37+</li>
        <li>✅ Firefox 34+</li>
        <li>✅ Safari 11+</li>
        <li>✅ Edge 79+</li>
      </ul>
      <p>
        Note: Web Crypto API is only available in secure contexts (HTTPS or localhost).
      </p>
    </main>
  );
}
