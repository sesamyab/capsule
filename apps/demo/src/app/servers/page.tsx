import { CodeBlock } from "@/components/CodeBlock";

export default function ServersPage() {
  return (
    <main className="content-page">
      <h1>Server Implementations</h1>
      <p>
        Capsule uses a two-server architecture: a <strong>CMS Server</strong> that encrypts
        content and a <strong>Subscription Server</strong> that manages keys and user access.
        This separation ensures strong security while keeping the CMS simple.
      </p>

      <h2>Architecture Overview</h2>
      
      <h3>CMS Server (Content Management)</h3>
      <ul>
        <li>✅ Has plaintext article content</li>
        <li>✅ Gets time-bucket keys (via TOTP, API, or OAuth2)</li>
        <li>✅ Encrypts articles with AES-256-GCM</li>
        <li>✅ Embeds encrypted content in static HTML</li>
        <li>❌ Never has user keys or subscription data</li>
      </ul>

      <h3>Subscription Server (Key Management)</h3>
      <ul>
        <li>✅ Controls bucket key generation and rotation</li>
        <li>✅ Validates user subscriptions</li>
        <li>✅ Unwraps DEKs and wraps with user RSA keys</li>
        <li>❌ Never sees article content</li>
      </ul>

      <h3>Flow Diagram</h3>
      <pre className="diagram">{`
┌─────────────────────────┐
│  Subscription Server    │
│  (User Auth + Keys)     │
└───────────┬─────────────┘
      ▲     │
      │     │ 4. User requests unlock
      │     │    (sends public key)
      │     │
      │     │ 5. Returns DEK wrapped
      │     │    with user's public key
      │     ▼
┌─────────────────┐     ┌─────────────────┐
│   CMS Server    │     │     Browser     │
│                 │────►│  (Private Key)  │
│                 │     │                 │
└─────────────────┘     └─────────────────┘
  │     ▲                 │
  │     │ 1. Get bucket   │ 2. Request page
  │     │    keys         │
  │     │ (TOTP/API/OAuth)│
  │     │                 │
  └─────┴─────────────────┘
          3. Returns encrypted HTML
             + DEK wrapped with bucket key
      `}</pre>

      <h2>Key Exchange Methods</h2>
      <p>
        The CMS can obtain bucket keys from the Subscription Server using three methods.
        From the <strong>browser&apos;s perspective, all three are identical</strong> - it just
        receives encrypted content and calls the unlock endpoint.
      </p>

      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1rem' }}>
        <thead>
          <tr style={{ borderBottom: '2px solid var(--border-color)' }}>
            <th style={{ textAlign: 'left', padding: '0.5rem' }}>Method</th>
            <th style={{ textAlign: 'left', padding: '0.5rem' }}>How It Works</th>
            <th style={{ textAlign: 'left', padding: '0.5rem' }}>Rotation Control</th>
            <th style={{ textAlign: 'left', padding: '0.5rem' }}>Best For</th>
          </tr>
        </thead>
        <tbody>
          <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
            <td style={{ padding: '0.5rem' }}><strong>TOTP</strong></td>
            <td style={{ padding: '0.5rem' }}>Shared secret, both derive locally</td>
            <td style={{ padding: '0.5rem' }}>Fixed at setup (e.g., 15 min)</td>
            <td style={{ padding: '0.5rem' }}>Offline CMS, no API calls</td>
          </tr>
          <tr style={{ borderBottom: '1px solid var(--border-color)' }}>
            <td style={{ padding: '0.5rem' }}><strong>API Key</strong></td>
            <td style={{ padding: '0.5rem' }}>Bearer token, fetch keys</td>
            <td style={{ padding: '0.5rem' }}>Server controls rotation</td>
            <td style={{ padding: '0.5rem' }}>Simple integration</td>
          </tr>
          <tr>
            <td style={{ padding: '0.5rem' }}><strong>OAuth2</strong></td>
            <td style={{ padding: '0.5rem' }}>Client credentials flow</td>
            <td style={{ padding: '0.5rem' }}>Server controls rotation</td>
            <td style={{ padding: '0.5rem' }}>Enterprise, multi-tenant</td>
          </tr>
        </tbody>
      </table>

      <h3>Method 1: TOTP (RFC 6238)</h3>
      <p>
        Both servers share a secret and derive bucket keys locally using time-based OTP.
        The bucket duration is fixed at setup time - this is part of the TOTP standard.
      </p>
      <CodeBlock>{`// TOTP URI format (like Google Authenticator QR codes)
// otpauth://totp/Capsule:cms@example.com?secret=BASE32SECRET&period=900&algorithm=SHA256

// Standard parameters:
// - secret: Base32-encoded shared secret
// - period: Time step in seconds (default 30, we use 900 = 15 min)
// - algorithm: SHA1, SHA256, or SHA512

const SHARED_SECRET = Buffer.from(process.env.CAPSULE_SHARED_SECRET!, 'base64');
const BUCKET_PERIOD = 900; // 15 minutes (fixed at setup)

function getCurrentBucketId(): string {
  return Math.floor(Date.now() / 1000 / BUCKET_PERIOD).toString();
}

function deriveBucketKey(tier: string): Buffer {
  const bucketId = getCurrentBucketId();
  // Both CMS and Subscription Server derive identical key
  return hkdf(SHARED_SECRET, bucketId, \`capsule-bucket-\${tier}\`, 32);
}

// No API call needed - both servers compute the same key
const bucketKey = deriveBucketKey('premium');`}</CodeBlock>

      <h3>Method 2: API Key (Bearer Token)</h3>
      <p>
        CMS fetches bucket keys from the Subscription Server using a simple API key.
        The server controls rotation - it can return keys with any expiration time.
      </p>
      <CodeBlock>{`// CMS fetches bucket keys
const response = await fetch('https://subscription.example.com/api/bucket-keys', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer cms_live_abc123...',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ tier: 'premium' })
});

const { current, next } = await response.json();
// Server decides rotation period - could be 5 min, 1 hour, etc.
// {
//   current: { bucketId: "abc123", key: "base64...", expiresAt: "2026-01-16T12:30:00Z" },
//   next: { bucketId: "def456", key: "base64...", expiresAt: "2026-01-16T12:45:00Z" }
// }

// Cache until expiry
bucketKeyCache.set(tier, { keys: { current, next }, expiresAt: current.expiresAt });`}</CodeBlock>

      <h3>Method 3: OAuth2 Client Credentials</h3>
      <p>
        Standard OAuth2 flow - more secure for enterprise and multi-tenant deployments.
        CMS authenticates with client ID/secret, receives access token, then fetches keys.
      </p>
      <CodeBlock>{`// 1. Get access token (cached until expiry)
const tokenResponse = await fetch('https://subscription.example.com/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: process.env.CAPSULE_CLIENT_ID!,
    client_secret: process.env.CAPSULE_CLIENT_SECRET!,
    scope: 'bucket-keys:read'
  })
});

const { access_token, expires_in } = await tokenResponse.json();

// 2. Fetch bucket keys with access token
const keysResponse = await fetch('https://subscription.example.com/api/bucket-keys', {
  method: 'POST',
  headers: {
    'Authorization': \`Bearer \${access_token}\`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ tier: 'premium' })
});

const { current, next } = await keysResponse.json();
// Server controls rotation period dynamically`}</CodeBlock>

      <h2>Choosing a Method</h2>
      <ul>
        <li>
          <strong>TOTP:</strong> Best for static site generators, edge deployments, or when
          you want zero API calls. Bucket period is fixed at setup (e.g., 15 min via QR code).
        </li>
        <li>
          <strong>API Key:</strong> Simple to implement. Subscription server controls rotation.
          Good for trusted CMS servers.
        </li>
        <li>
          <strong>OAuth2:</strong> Industry standard. Better audit trails, token revocation,
          and scope management. Best for enterprise deployments.
        </li>
      </ul>

      <h2>Time-Bucket Keys</h2>
      <p>
        Regardless of the method used, Capsule uses <strong>time-bucket keys</strong> that
        rotate periodically. This enables automatic access revocation without re-encrypting
        content.
      </p>

      <h3>How It Works</h3>
      <CodeBlock>{`// CMS encrypts article with current bucket key
const bucketKey = /* from TOTP, API, or OAuth2 */;
const wrappedDek = wrapDek(articleDek, bucketKey);

// User requests unlock from Subscription Server:
// 1. Server checks subscription is active
// 2. Gets/derives the same bucket key
// 3. Unwraps DEK with bucket key
// 4. Re-wraps with user's RSA public key
// 5. Browser unwraps and decrypts content

// If subscription cancelled:
// - Server refuses to unwrap DEK for user
// - Access revoked within one bucket period
// - No need to re-encrypt content`}</CodeBlock>

      <h2>CMS Server Implementation</h2>

      <h3>Unified Bucket Key Client</h3>
      <p>
        A single client that supports all three methods:
      </p>
      <CodeBlock>{`import { createCipheriv, createHmac, randomBytes } from 'crypto';

type KeyMethod = 'totp' | 'api-key' | 'oauth2';

interface BucketKeys {
  current: { bucketId: string; key: Buffer; expiresAt: Date };
  next: { bucketId: string; key: Buffer; expiresAt: Date };
}

class BucketKeyClient {
  private method: KeyMethod;
  private cache = new Map<string, { keys: BucketKeys; expiresAt: number }>();
  
  // TOTP config
  private sharedSecret?: Buffer;
  private bucketPeriod = 900; // 15 min default
  
  // API/OAuth config
  private apiEndpoint?: string;
  private apiKey?: string;
  private clientId?: string;
  private clientSecret?: string;
  private accessToken?: string;
  private tokenExpiresAt?: number;
  
  constructor(config: {
    method: KeyMethod;
    // TOTP
    sharedSecret?: string;
    bucketPeriod?: number;
    // API
    apiEndpoint?: string;
    apiKey?: string;
    // OAuth2
    clientId?: string;
    clientSecret?: string;
  }) {
    this.method = config.method;
    this.sharedSecret = config.sharedSecret 
      ? Buffer.from(config.sharedSecret, 'base64') 
      : undefined;
    this.bucketPeriod = config.bucketPeriod || 900;
    this.apiEndpoint = config.apiEndpoint;
    this.apiKey = config.apiKey;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
  }
  
  async getBucketKeys(tier: string): Promise<BucketKeys> {
    // Check cache first
    const cached = this.cache.get(tier);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.keys;
    }
    
    let keys: BucketKeys;
    
    switch (this.method) {
      case 'totp':
        keys = this.deriveTotpKeys(tier);
        break;
      case 'api-key':
        keys = await this.fetchWithApiKey(tier);
        break;
      case 'oauth2':
        keys = await this.fetchWithOAuth(tier);
        break;
    }
    
    this.cache.set(tier, { 
      keys, 
      expiresAt: keys.current.expiresAt.getTime() 
    });
    
    return keys;
  }
  
  private deriveTotpKeys(tier: string): BucketKeys {
    const now = Math.floor(Date.now() / 1000);
    const currentBucket = Math.floor(now / this.bucketPeriod);
    const nextBucket = currentBucket + 1;
    
    return {
      current: {
        bucketId: currentBucket.toString(),
        key: this.hkdf(currentBucket.toString(), tier),
        expiresAt: new Date((currentBucket + 1) * this.bucketPeriod * 1000)
      },
      next: {
        bucketId: nextBucket.toString(),
        key: this.hkdf(nextBucket.toString(), tier),
        expiresAt: new Date((nextBucket + 1) * this.bucketPeriod * 1000)
      }
    };
  }
  
  private hkdf(salt: string, info: string): Buffer {
    const prk = createHmac('sha256', salt).update(this.sharedSecret!).digest();
    const hmac = createHmac('sha256', prk);
    hmac.update(\`capsule-bucket-\${info}\`);
    hmac.update(Buffer.from([1]));
    return hmac.digest().subarray(0, 32);
  }
  
  private async fetchWithApiKey(tier: string): Promise<BucketKeys> {
    const res = await fetch(\`\${this.apiEndpoint}/bucket-keys\`, {
      method: 'POST',
      headers: {
        'Authorization': \`Bearer \${this.apiKey}\`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ tier })
    });
    return this.parseKeyResponse(await res.json());
  }
  
  private async fetchWithOAuth(tier: string): Promise<BucketKeys> {
    // Refresh token if needed
    if (!this.accessToken || Date.now() > (this.tokenExpiresAt || 0)) {
      await this.refreshOAuthToken();
    }
    
    const res = await fetch(\`\${this.apiEndpoint}/bucket-keys\`, {
      method: 'POST',
      headers: {
        'Authorization': \`Bearer \${this.accessToken}\`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ tier })
    });
    return this.parseKeyResponse(await res.json());
  }
  
  private async refreshOAuthToken(): Promise<void> {
    const res = await fetch(\`\${this.apiEndpoint}/oauth/token\`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.clientId!,
        client_secret: this.clientSecret!,
        scope: 'bucket-keys:read'
      })
    });
    const { access_token, expires_in } = await res.json();
    this.accessToken = access_token;
    this.tokenExpiresAt = Date.now() + (expires_in - 60) * 1000;
  }
  
  private parseKeyResponse(data: any): BucketKeys {
    return {
      current: {
        bucketId: data.current.bucketId,
        key: Buffer.from(data.current.key, 'base64'),
        expiresAt: new Date(data.current.expiresAt)
      },
      next: {
        bucketId: data.next.bucketId,
        key: Buffer.from(data.next.key, 'base64'),
        expiresAt: new Date(data.next.expiresAt)
      }
    };
  }
}`}</CodeBlock>

      <h3>Using the Client</h3>
      <CodeBlock>{`// TOTP - no API calls
const totpClient = new BucketKeyClient({
  method: 'totp',
  sharedSecret: process.env.CAPSULE_SHARED_SECRET,
  bucketPeriod: 900  // 15 minutes
});

// API Key
const apiClient = new BucketKeyClient({
  method: 'api-key',
  apiEndpoint: 'https://subscription.example.com/api',
  apiKey: process.env.CAPSULE_API_KEY
});

// OAuth2
const oauthClient = new BucketKeyClient({
  method: 'oauth2',
  apiEndpoint: 'https://subscription.example.com',
  clientId: process.env.CAPSULE_CLIENT_ID,
  clientSecret: process.env.CAPSULE_CLIENT_SECRET
});

// All three work the same way
const { current, next } = await client.getBucketKeys('premium');`}</CodeBlock>

      <h3>Encrypting Articles</h3>
      <CodeBlock>{`class CapsuleEncryption {
  constructor(private keyClient: BucketKeyClient) {}
  
  async encryptArticle(content: string, tier: string) {
    const { current, next } = await this.keyClient.getBucketKeys(tier);
    
    // Generate article DEK
    const articleDek = randomBytes(32);
    
    // Encrypt content with AES-256-GCM
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', articleDek, iv);
    const encrypted = Buffer.concat([
      cipher.update(content, 'utf8'),
      cipher.final(),
      cipher.getAuthTag()
    ]);
    
    // Wrap DEK with both bucket keys (for rotation overlap)
    const wrappedCurrent = this.wrapDek(articleDek, current.key);
    const wrappedNext = this.wrapDek(articleDek, next.key);
    
    return {
      encryptedContent: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      tier,
      wrappedDeks: {
        [current.bucketId]: wrappedCurrent,
        [next.bucketId]: wrappedNext
      }
    };
  }
  
  wrapDek(dek: Buffer, bucketKey: Buffer): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', bucketKey, iv);
    const wrapped = Buffer.concat([
      iv,
      cipher.update(dek),
      cipher.final(),
      cipher.getAuthTag()
    ]);
    return wrapped.toString('base64');
  }
}`}</CodeBlock>

      <h2>Subscription Server Implementation</h2>

      <h3>Shared Secret / Master Key Setup</h3>
      <CodeBlock>{`// For TOTP: shared between CMS and Subscription Server
// For API/OAuth: only on Subscription Server (it's the master key)
const SHARED_SECRET = process.env.CAPSULE_SHARED_SECRET 
  ? Buffer.from(process.env.CAPSULE_SHARED_SECRET, 'base64')
  : crypto.randomBytes(32);

// Store securely in KMS (AWS Secrets Manager, HashiCorp Vault, etc.)
console.log('Secret:', SHARED_SECRET.toString('base64'));`}</CodeBlock>

      <h3>Bucket Key Derivation (All Methods)</h3>
      <CodeBlock>{`import { createHmac } from 'crypto';

// For TOTP: period is fixed at setup
// For API/OAuth: server controls period dynamically
const DEFAULT_BUCKET_PERIOD = 900; // 15 minutes in seconds

function hkdf(secret: Buffer, salt: string, info: string): Buffer {
  const prk = createHmac('sha256', salt).update(secret).digest();
  const hmac = createHmac('sha256', prk);
  hmac.update(info);
  hmac.update(Buffer.from([0x01]));
  return hmac.digest().subarray(0, 32);
}

function deriveBucketKey(tier: string, bucketId: string): Buffer {
  return hkdf(SHARED_SECRET, bucketId, \`capsule-bucket-\${tier}\`);
}`}</CodeBlock>

      <h3>Bucket Keys Endpoint (API Key / OAuth2)</h3>
      <p>
        Only needed for API Key and OAuth2 methods. TOTP clients derive keys locally.
      </p>
      <CodeBlock>{`// POST /api/bucket-keys
app.post('/api/bucket-keys', authenticate, async (req, res) => {
  const { tier } = req.body;
  
  // Server controls rotation period
  const bucketPeriod = getBucketPeriodForTier(tier); // Could be 5 min, 15 min, 1 hour...
  const now = Math.floor(Date.now() / 1000);
  const currentBucket = Math.floor(now / bucketPeriod);
  const nextBucket = currentBucket + 1;
  
  const currentKey = deriveBucketKey(tier, currentBucket.toString());
  const nextKey = deriveBucketKey(tier, nextBucket.toString());
  
  res.json({
    tier,
    current: {
      bucketId: currentBucket.toString(),
      key: currentKey.toString('base64'),
      expiresAt: new Date((currentBucket + 1) * bucketPeriod * 1000)
    },
    next: {
      bucketId: nextBucket.toString(),
      key: nextKey.toString('base64'),
      expiresAt: new Date((nextBucket + 1) * bucketPeriod * 1000)
    }
  });
});

// authenticate middleware supports both API Key and OAuth2
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization' });
  }
  
  const token = auth.slice(7);
  
  // Check if it's an API key
  if (isValidApiKey(token)) {
    return next();
  }
  
  // Check if it's an OAuth2 access token
  if (isValidAccessToken(token)) {
    return next();
  }
  
  return res.status(401).json({ error: 'Invalid credentials' });
}`}</CodeBlock>

      <h3>User Unlock Endpoint</h3>
      <p>
        The main endpoint users call. Works with any key exchange method - it just needs
        to derive the same bucket key the CMS used.
      </p>
      <CodeBlock>{`// POST /api/unlock
app.post('/api/unlock', async (req, res) => {
  const { tier, bucket, articleId, publicKey, wrappedDek } = req.body;
  
  // 1. Validate user subscription
  const user = await getUserFromSession(req);
  if (!user || !hasActiveSubscription(user, tier)) {
    return res.status(403).json({ error: 'Invalid subscription' });
  }
  
  // 2. Derive bucket key (same as CMS used)
  const bucketKey = deriveBucketKey(tier, bucket);
  
  // 3. Unwrap DEK with bucket key
  const articleDek = unwrapDek(Buffer.from(wrappedDek, 'base64'), bucketKey);
  
  // 4. Re-wrap with user's RSA public key
  const publicKeyPem = convertSpkiToPem(publicKey);
  const encryptedForUser = publicEncrypt(
    {
      key: publicKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    articleDek
  );
  
  res.json({
    encryptedDek: encryptedForUser.toString('base64'),
    bucket,
    tier
  });
});

function unwrapDek(wrappedDek: Buffer, bucketKey: Buffer): Buffer {
  const iv = wrappedDek.subarray(0, 12);
  const authTag = wrappedDek.subarray(wrappedDek.length - 16);
  const ciphertext = wrappedDek.subarray(12, wrappedDek.length - 16);
  
  const decipher = createDecipheriv('aes-256-gcm', bucketKey, iv);
  decipher.setAuthTag(authTag);
  
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
}`}</CodeBlock>

      <h2>Testing</h2>

      <h3>Test TOTP Key Derivation</h3>
      <p>
        Run on both CMS and Subscription Server - output should match:
      </p>
      <CodeBlock>{`const crypto = require('crypto');

const SHARED_SECRET = Buffer.from(process.env.CAPSULE_SHARED_SECRET, 'base64');
const BUCKET_PERIOD = 900; // 15 min

function hkdf(secret, salt, info) {
  const prk = crypto.createHmac('sha256', salt).update(secret).digest();
  const hmac = crypto.createHmac('sha256', prk);
  hmac.update(info);
  hmac.update(Buffer.from([1]));
  return hmac.digest().subarray(0, 32);
}

const bucketId = Math.floor(Date.now() / 1000 / BUCKET_PERIOD).toString();
const bucketKey = hkdf(SHARED_SECRET, bucketId, 'capsule-bucket-premium');

console.log('Bucket ID:', bucketId);
console.log('Bucket Key:', bucketKey.toString('base64'));`}</CodeBlock>

      <h3>Test API Key / OAuth2 Flow</h3>
      <CodeBlock>{`# Fetch bucket keys with API key
curl -X POST http://localhost:3000/api/bucket-keys \\
  -H "Authorization: Bearer cms_live_abc123..." \\
  -H "Content-Type: application/json" \\
  -d '{"tier": "premium"}'

# Or with OAuth2 (first get token)
curl -X POST http://localhost:3000/oauth/token \\
  -d "grant_type=client_credentials" \\
  -d "client_id=my-cms" \\
  -d "client_secret=secret123"

# Then use token to fetch keys
curl -X POST http://localhost:3000/api/bucket-keys \\
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \\
  -H "Content-Type: application/json" \\
  -d '{"tier": "premium"}'`}</CodeBlock>

      <h3>Test User Unlock</h3>
      <CodeBlock>{`# User unlock request (with RSA public key)
curl -X POST http://localhost:3000/api/unlock \\
  -H "Content-Type: application/json" \\
  -d '{
    "tier": "premium",
    "bucket": "1234567",
    "wrappedDek": "base64...",
    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
  }'`}</CodeBlock>

      <h2>Security Best Practices</h2>
      <ul>
        <li>🔒 <strong>Store secrets in KMS</strong> (AWS Secrets Manager, Google Secret Manager, HashiCorp Vault)</li>
        <li>🔒 <strong>Use HTTPS</strong> for all API endpoints</li>
        <li>🔒 <strong>Rate limit</strong> bucket-keys and unlock endpoints</li>
        <li>🔒 <strong>Log all requests</strong> for audit trails</li>
        <li>🔒 <strong>Rotate secrets periodically</strong></li>
      </ul>
      
      <h4>Method-Specific</h4>
      <ul>
        <li><strong>TOTP:</strong> Sync clocks via NTP (servers must agree on time bucket)</li>
        <li><strong>API Key:</strong> Rotate keys every 90 days, use different keys per environment</li>
        <li><strong>OAuth2:</strong> Use short token expiry (5-15 min), implement token revocation</li>
      </ul>

      <h2>Node.js</h2>
      <p>
        The Node.js implementation uses the built-in <code>crypto</code> module for
        maximum performance and minimal dependencies.
      </p>

      <h3>Installation</h3>
      <CodeBlock language="bash">{`npm install capsule`}</CodeBlock>

      <h3>Basic Usage</h3>
      <CodeBlock>{`import { ArticleEncryptor } from 'capsule';

// Encrypt content for a specific client
const encryptor = new ArticleEncryptor(clientPublicKey);
const encrypted = await encryptor.encrypt(content);

// Result: { encryptedContent, iv, encryptedDek }`}</CodeBlock>

      <h3>API Routes (Next.js Example)</h3>
      <CodeBlock>{`// app/api/unlock/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { publicEncrypt, constants } from 'crypto';

export async function POST(request: NextRequest) {
  const { tier, publicKey } = await request.json();
  
  // Get the DEK for this subscription tier
  const dek = getSubscriptionDek(tier);
  
  // Convert Base64 SPKI to PEM
  const publicKeyPem = convertToPem(publicKey);
  
  // Wrap DEK with client's public key
  const encryptedDek = publicEncrypt(
    {
      key: publicKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    dek
  );
  
  return NextResponse.json({
    encryptedDek: encryptedDek.toString('base64'),
    tier
  });
}`}</CodeBlock>

      <h3>Pre-Encrypting Content</h3>
      <CodeBlock>{`import { createCipheriv, randomBytes } from 'crypto';

function encryptArticle(content: string, dek: Buffer) {
  const iv = randomBytes(12); // 96-bit IV
  
  const cipher = createCipheriv('aes-256-gcm', dek, iv, {
    authTagLength: 16
  });
  
  const encrypted = Buffer.concat([
    cipher.update(content, 'utf8'),
    cipher.final(),
    cipher.getAuthTag()
  ]);
  
  return {
    encryptedContent: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tier: 'premium'
  };
}

// At build time or when content is published:
const articles = [
  { id: '1', content: '...' },
  { id: '2', content: '...' }
];

const premiumDek = randomBytes(32); // Generate once per tier
const encrypted = articles.map(article =>
  encryptArticle(article.content, premiumDek)
);`}</CodeBlock>

      <h2>PHP</h2>
      <p>
        PHP implementation using OpenSSL for cryptographic operations.
      </p>

      <h3>Installation</h3>
      <CodeBlock language="bash">{`composer require capsule/capsule-php`}</CodeBlock>

      <h3>Basic Usage</h3>
      <CodeBlock language="php">{`<?php

use Capsule\\ArticleEncryptor;

// Encrypt content
$dek = random_bytes(32); // AES-256 key
$iv = random_bytes(12);  // GCM IV

$encrypted = openssl_encrypt(
    $content,
    'aes-256-gcm',
    $dek,
    OPENSSL_RAW_DATA,
    $iv,
    $tag
);

$result = [
    'encryptedContent' => base64_encode($encrypted . $tag),
    'iv' => base64_encode($iv),
    'tier' => 'premium'
];`}</CodeBlock>

      <h3>Key Exchange Endpoint</h3>
      <CodeBlock language="php">{`<?php

// api/unlock.php
header('Content-Type: application/json');

$input = json_decode(file_get_contents('php://input'), true);
$tier = $input['tier'];
$publicKey = $input['publicKey'];

// Get DEK for tier
$dek = getSubscriptionDek($tier);

// Convert SPKI to PEM
$publicKeyPem = convertSpkiToPem($publicKey);

// Wrap DEK with RSA-OAEP
$encryptedDek = '';
openssl_public_encrypt(
    $dek,
    $encryptedDek,
    $publicKeyPem,
    OPENSSL_PKCS1_OAEP_PADDING
);

echo json_encode([
    'encryptedDek' => base64_encode($encryptedDek),
    'tier' => $tier
]);

function convertSpkiToPem($base64Spki) {
    $der = base64_decode($base64Spki);
    $pem = "-----BEGIN PUBLIC KEY-----\\n";
    $pem .= chunk_split(base64_encode($der), 64);
    $pem .= "-----END PUBLIC KEY-----";
    return $pem;
}`}</CodeBlock>

      <h2>Python</h2>
      <p>Python support using the <code>cryptography</code> library.</p>

      <h3>Installation</h3>
      <CodeBlock language="bash">{`pip install capsule-py`}</CodeBlock>

      <h3>Basic Usage</h3>
      <CodeBlock language="python">{`from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import base64

# Encrypt content
def encrypt_article(content: str, dek: bytes) -> dict:
    iv = os.urandom(12)
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(iv, content.encode(), None)
    
    return {
        'encryptedContent': base64.b64encode(ciphertext).decode(),
        'iv': base64.b64encode(iv).decode(),
        'tier': 'premium'
    }

# Wrap DEK
def wrap_dek(dek: bytes, public_key_spki: str) -> str:
    # Load public key from SPKI
    public_key = serialization.load_der_public_key(
        base64.b64decode(public_key_spki)
    )
    
    # Wrap with RSA-OAEP
    encrypted = public_key.encrypt(
        dek,
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
        Want to contribute an implementation? Check out the{' '}
        <a href="https://github.com/capsule-standard/capsule">GitHub repository</a>.
      </p>
    </main>
  );
}
