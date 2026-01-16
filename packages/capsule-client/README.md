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
import { CapsuleClient } from 'capsule-client';

// Default client (single key)
const client = new CapsuleClient();

// Multi-key scenario (e.g., tier-based or article-specific keys)
const premiumClient = new CapsuleClient({ keyId: 'premium-tier' });
const articleClient = new CapsuleClient({ keyId: 'article-123' });
```

### Generate and Store Keys (First Time Setup)

```typescript
// Generate a new RSA key pair and store in IndexedDB
const publicKeyB64 = await client.generateKeyPair();

// Send publicKeyB64 to your server for registration
await fetch('/api/register-key', {
    method: 'POST',
    body: JSON.stringify({ publicKey: publicKeyB64 }),
    headers: { 'Content-Type': 'application/json' }
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
const response = await fetch('/api/article/123');
const encryptedPayload = await response.json();

// Decrypt using the stored private key
const articleContent = await client.decryptArticle(encryptedPayload);

// Display the decrypted content
document.getElementById('article').textContent = articleContent;
```

### Full Example

```typescript
import { CapsuleClient } from 'capsule-client';

const client = new CapsuleClient();

async function setupEncryption() {
    // Check if we already have keys
    const hasKeys = await client.hasKeyPair();
    
    if (!hasKeys) {
        // Generate new key pair
        const publicKey = await client.generateKeyPair();
        
        // Register public key with server
        await fetch('/api/user/public-key', {
            method: 'POST',
            body: JSON.stringify({ publicKey }),
            headers: { 'Content-Type': 'application/json' }
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
        document.getElementById('article-content').innerHTML = content;
    } catch (error) {
        console.error('Failed to decrypt article:', error);
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
    iv: string;               // Base64
    encryptedDek: string;     // Base64
}
```

## Security Notes

1. **Private key never leaves the browser** - Stored as non-extractable in IndexedDB
2. **AES key only in memory** - DEK is decrypted only for immediate use
3. **Web Crypto API** - Uses hardware-accelerated native cryptography
4. **RSA-OAEP with SHA-256** - Secure key wrapping compatible with server libraries

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
