import { CodeBlock } from "@/components/CodeBlock";
import { PageWithToc } from "@/components/PageWithToc";

export default function ServersPage() {
  return (
    <PageWithToc>
      <main className="content-page">
        <h1>Server Implementations</h1>
        <p>
          Capsule uses a two-server architecture: a <strong>CMS Server</strong>{" "}
          that encrypts content and a <strong>Subscription Server</strong> that
          manages keys and user access. This separation ensures strong security
          while keeping the CMS simple.
        </p>

        <h2>Quick Start with @sesamy/capsule-server</h2>
        <p>
          The <code>@sesamy/capsule-server</code> package provides a high-level
          API for both CMS encryption and subscription server functionality. The
          CMS just works with key IDs - it doesn&apos;t know or care about
          subscriptions or how keys are derived.
        </p>
        <CodeBlock language="bash">{`npm install @sesamy/capsule-server`}</CodeBlock>

        <h3>CMS: Encrypting Content</h3>
        <CodeBlock>{`import { createCmsServer } from '@sesamy/capsule-server';

// CMS fetches period keys from the Subscription Server
// (authenticated via Ed25519 JWT — see "CMS Authentication" below)
const cms = createCmsServer({
  getKeys: async (keyIds) => {
    const response = await fetchPeriodKeys(keyIds); // Your authenticated fetch
    return response;
  },
});

// Encrypt with specific key IDs
const encrypted = await cms.encrypt('article-123', premiumContent, {
  keyIds: ['premium', 'enterprise'],  // Just key IDs - CMS doesn't know what they mean
});

// Result: { resourceId, encryptedContent, iv, wrappedKeys: [...] }

// Or get HTML ready for templates
const html = await cms.encrypt('article-123', content, {
  keyIds: ['premium'],
  format: 'html',
  placeholder: '<p>Subscribe to unlock...</p>',
});`}</CodeBlock>

        <h3>Subscription Server: Unlock Endpoint</h3>
        <CodeBlock>{`import { createSubscriptionServer } from '@sesamy/capsule-server';

const server = createSubscriptionServer({
  periodSecret: process.env.PERIOD_SECRET,
  periodDurationSeconds: 30,
});

// POST /api/unlock
app.post('/api/unlock', async (req, res) => {
  // 1. Validate user subscription here!
  const { keyId, wrappedContentKey, publicKey } = req.body;
  
  // 2. Unwrap content key and re-wrap with user's RSA public key
  const result = await server.unlockForUser(
    { keyId, wrappedContentKey },
    publicKey
  );
  
  // 3. Return encrypted content key for client
  res.json(result);
  // { encryptedContentKey, expiresAt, periodId }
});`}</CodeBlock>

        <h3>Output Formats</h3>
        <CodeBlock>{`// JSON (default) - for API responses
const data = await cms.encrypt(id, content, { keyIds: ['premium'] });

// HTML - ready to embed
const html = await cms.encrypt(id, content, {
  keyIds: ['premium'],
  format: 'html',
  htmlClass: 'premium-content',
  placeholder: 'Loading...',
});
// <div class="premium-content" data-capsule='{...}' data-capsule-id="...">Loading...</div>

// Template helper - get all formats
const { data, json, attribute, html } = await cms.encryptForTemplate(id, content, {
  keyIds: ['premium'],
});`}</CodeBlock>

        <h2>Architecture Overview</h2>

        <h3>CMS Server (Content Management)</h3>
        <ul>
          <li>✅ Has plaintext article content</li>
          <li>✅ Gets time-period keys from the Subscription Server (authenticated via Ed25519 JWT)</li>
          <li>✅ Encrypts articles with AES-256-GCM</li>
          <li>✅ Embeds encrypted content in static HTML</li>
          <li>❌ Never has user keys or subscription data</li>
        </ul>

        <h3>Subscription Server (Key Management)</h3>
        <ul>
          <li>✅ Controls period key generation and rotation</li>
          <li>✅ Validates user subscriptions</li>
          <li>✅ Unwraps content keys and wraps with user RSA keys</li>
          <li>❌ Never sees article content</li>
        </ul>

        <h3>Flow Diagram</h3>
        <pre className="diagram">{`
┌─────────────────────────┐
│  Subscription Server    │
│  (User Auth + Keys)     │
│                         │
│  Verifies CMS identity  │
│  via Ed25519 JWT        │
└───────────┬─────────────┘
      ▲     │
      │     │ 4. User requests unlock
      │     │    (sends RSA public key)
      │     │
      │     │ 5. Returns content key wrapped
      │     │    with user's RSA public key
      │     ▼
┌─────────────────┐     ┌─────────────────┐
│   CMS Server    │     │     Browser     │
│  (Issuer Key)   │────►│  (RSA Key Pair) │
│                 │     │                 │
└─────────────────┘     └─────────────────┘
  │     ▲                 │
  │     │ 1. Fetch period │ 2. Request page
  │     │    keys (JWT)   │
  │     │                 │
  └─────┴─────────────────┘
          3. Returns encrypted HTML
             + content key wrapped with period key
      `}</pre>

        <h2>CMS Authentication</h2>
        <p>
          The CMS authenticates to the Subscription Server using an{" "}
          <strong>Ed25519 issuer key pair</strong>. The CMS holds a private key
          and signs short-lived JWTs. The Subscription Server verifies these
          JWTs using the CMS&apos;s public key, which is registered ahead of
          time (manually or via a <code>/.well-known/jwks.json</code> endpoint).
        </p>

        <h3>How It Works</h3>
        <ol>
          <li>
            <strong>CMS generates an Ed25519 key pair</strong> (once, at setup)
          </li>
          <li>
            <strong>Public key is registered</strong> with the Subscription
            Server (via API call, config file, or JWKS discovery)
          </li>
          <li>
            <strong>CMS signs a JWT</strong> with its private key for each
            request to the Subscription Server
          </li>
          <li>
            <strong>Subscription Server verifies</strong> the JWT signature
            using the registered public key
          </li>
        </ol>

        <h3>CMS Setup</h3>
        <CodeBlock>{`import { generateSigningKeyPair, createAsymmetricTokenManager } from '@sesamy/capsule-server';

// Generate a key pair once and store the private key securely
const { privateKey, publicKey, keyId } = await generateSigningKeyPair();

// Create a token manager for signing requests to the Subscription Server
const issuerTokens = await createAsymmetricTokenManager({
  issuer: 'https://cms.example.com',
  privateKey,
  publicKey,
  keyId,
});

// Fetch period keys with a signed JWT
const token = await issuerTokens.generate({
  contentId: 'premium',
  expiresIn: '5m',  // Short-lived
});

const response = await fetch('https://subscription.example.com/api/period-keys', {
  method: 'POST',
  headers: {
    'Authorization': \`Bearer \${token}\`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ contentId: 'premium' }),
});

const { current, next } = await response.json();
// {
//   current: { periodId: "56789", key: "base64...", expiresAt: "2026-01-16T12:30:00Z" },
//   next:    { periodId: "56790", key: "base64...", expiresAt: "2026-01-16T12:45:00Z" }
// }`}</CodeBlock>

        <h3>Registering the CMS Public Key</h3>
        <p>
          The Subscription Server needs to know the CMS&apos;s public key to
          verify JWTs. There are two approaches:
        </p>
        <h4>Option A: Manual Registration</h4>
        <CodeBlock>{`// Register via API (protected admin endpoint)
await fetch('https://subscription.example.com/api/cms/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    cmsId: 'https://cms.example.com',
    publicKey: publicKey,  // PEM-encoded Ed25519 public key
  }),
});`}</CodeBlock>

        <h4>Option B: JWKS Discovery</h4>
        <p>
          Expose a <code>/.well-known/jwks.json</code> endpoint on the CMS
          so the Subscription Server can automatically discover and rotate
          public keys:
        </p>
        <CodeBlock>{`// CMS: app/.well-known/jwks.json/route.ts
import { issuerTokens } from '@/lib/tokens';

export async function GET() {
  return Response.json(await issuerTokens.getJwks());
}

// Returns:
// {
//   "keys": [{
//     "kty": "OKP",
//     "crv": "Ed25519",
//     "kid": "key-2026-01",
//     "x": "base64url-public-key",
//     "use": "sig",
//     "alg": "EdDSA"
//   }]
// }

// Subscription Server fetches and caches this periodically
// to verify incoming JWTs from the CMS`}</CodeBlock>

        <h2>Time-Period Keys</h2>
        <p>
          Regardless of the method used, Capsule uses{" "}
          <strong>time-period keys</strong> that rotate periodically. This
          enables automatic access revocation without re-encrypting content.
        </p>

        <h3>How It Works</h3>
        <CodeBlock>{`// CMS fetches period keys from Subscription Server (authenticated via Ed25519 JWT)
const { current, next } = await fetchPeriodKeys('premium');

// CMS encrypts article content key with period keys
const wrappedContentKey = wrapContentKey(contentKey, current.key);

// User requests unlock from Subscription Server:
// 1. Server checks subscription is active
// 2. Derives the same period key
// 3. Unwraps content key with period key
// 4. Re-wraps with user's RSA public key
// 5. Browser unwraps and decrypts content

// If subscription cancelled:
// - Server refuses to unwrap content key for user
// - Access revoked within one key rotation period
// - No need to re-encrypt content`}</CodeBlock>

        <h2>CMS Server Implementation</h2>

        <h3>Period Key Client</h3>
        <p>The CMS fetches period keys from the Subscription Server, authenticated with a signed JWT:</p>
        <CodeBlock>{`import { createAsymmetricTokenManager, AsymmetricTokenManager } from '@sesamy/capsule-server';

interface PeriodKeys {
  current: { periodId: string; key: Buffer; expiresAt: Date };
  next: { periodId: string; key: Buffer; expiresAt: Date };
}

class PeriodKeyClient {
  private cache = new Map<string, { keys: PeriodKeys; expiresAt: number }>();
  private tokenManager: AsymmetricTokenManager;
  private apiEndpoint: string;
  
  constructor(config: {
    apiEndpoint: string;
    privateKey: string;
    publicKey: string;
    keyId: string;
    issuer: string;
  }) {
    this.apiEndpoint = config.apiEndpoint;
    this.tokenManager = createAsymmetricTokenManager({
      issuer: config.issuer,
      privateKey: config.privateKey,
      publicKey: config.publicKey,
      keyId: config.keyId,
    });
  }
  
  async getPeriodKeys(contentId: string): Promise<PeriodKeys> {
    // Check cache first
    const cached = this.cache.get(contentId);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.keys;
    }
    
    // Sign a short-lived JWT for authentication
    const token = await this.tokenManager.generate({
      contentId,
      expiresIn: '5m',
    });
    
    const res = await fetch(\`\${this.apiEndpoint}/period-keys\`, {
      method: 'POST',
      headers: {
        'Authorization': \`Bearer \${token}\`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ contentId }),
    });
    
    const data = await res.json();
    const keys: PeriodKeys = {
      current: {
        periodId: data.current.periodId,
        key: Buffer.from(data.current.key, 'base64'),
        expiresAt: new Date(data.current.expiresAt),
      },
      next: {
        periodId: data.next.periodId,
        key: Buffer.from(data.next.key, 'base64'),
        expiresAt: new Date(data.next.expiresAt),
      },
    };
    
    this.cache.set(contentId, {
      keys,
      expiresAt: keys.current.expiresAt.getTime(),
    });
    
    return keys;
  }
}`}</CodeBlock>

        <h3>Using the Client</h3>
        <CodeBlock>{`const periodClient = new PeriodKeyClient({
  apiEndpoint: 'https://subscription.example.com/api',
  privateKey: process.env.CAPSULE_ISSUER_PRIVATE_KEY!,
  publicKey: process.env.CAPSULE_ISSUER_PUBLIC_KEY!,
  keyId: 'key-2026-01',
  issuer: 'https://cms.example.com',
});

// Fetches keys with Ed25519-signed JWT authentication
const { current, next } = await periodClient.getPeriodKeys('premium');`}</CodeBlock>

        <h3>Encrypting Articles</h3>
        <CodeBlock>{`class CapsuleEncryption {
  constructor(private keyClient: PeriodKeyClient) {}
  
  async encryptArticle(content: string, contentId: string) {
    const { current, next } = await this.keyClient.getPeriodKeys(contentId);
    
    // Generate content key
    const contentKey = randomBytes(32);
    
    // Encrypt content with AES-256-GCM
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', contentKey, iv);
    const encrypted = Buffer.concat([
      cipher.update(content, 'utf8'),
      cipher.final(),
      cipher.getAuthTag()
    ]);
    
    // Wrap content key with both period keys (for rotation overlap)
    const wrappedCurrent = this.wrapContentKey(contentKey, current.key);
    const wrappedNext = this.wrapContentKey(contentKey, next.key);
    
    return {
      encryptedContent: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      contentId,
      wrappedContentKeys: {
        [current.periodId]: wrappedCurrent,
        [next.periodId]: wrappedNext
      }
    };
  }
  
  wrapContentKey(contentKey: Buffer, periodKey: Buffer): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', periodKey, iv);
    const wrapped = Buffer.concat([
      iv,
      cipher.update(contentKey),
      cipher.final(),
      cipher.getAuthTag()
    ]);
    return wrapped.toString('base64');
  }
}`}</CodeBlock>

        <h2>Subscription Server Implementation</h2>

        <h3>Period Secret Setup</h3>
        <CodeBlock>{`// The period secret lives ONLY on the Subscription Server.
// The CMS never sees it — it fetches derived period keys via authenticated API calls.
const PERIOD_SECRET = process.env.PERIOD_SECRET
  ? Buffer.from(process.env.PERIOD_SECRET, 'base64')
  : crypto.randomBytes(32);

// Store securely in KMS (AWS Secrets Manager, HashiCorp Vault, etc.)`}</CodeBlock>

        <h3>Period Key Derivation</h3>
        <CodeBlock>{`import { createHmac } from 'crypto';

const DEFAULT_PERIOD_DURATION = 900; // 15 minutes in seconds

function hkdf(secret: Buffer, salt: string, info: string): Buffer {
  const prk = createHmac('sha256', salt).update(secret).digest();
  const hmac = createHmac('sha256', prk);
  hmac.update(info);
  hmac.update(Buffer.from([0x01]));
  return hmac.digest().subarray(0, 32);
}

function derivePeriodKey(contentId: string, periodId: string): Buffer {
  return hkdf(PERIOD_SECRET, periodId, \`capsule-period-\${contentId}\`);
}`}</CodeBlock>

        <h3>Period Keys Endpoint</h3>
        <p>
          The CMS fetches period keys from this endpoint, authenticated via
          Ed25519 JWT.
        </p>
        <CodeBlock>{`// POST /api/period-keys
app.post('/api/period-keys', verifyIssuerJwt, async (req, res) => {
  const { contentId } = req.body;
  
  // Server controls rotation period
  const rotationPeriod = 900; // 15 minutes
  const now = Math.floor(Date.now() / 1000);
  const currentPeriod = Math.floor(now / rotationPeriod);
  const nextPeriod = currentPeriod + 1;
  
  const currentKey = derivePeriodKey(contentId, currentPeriod.toString());
  const nextKey = derivePeriodKey(contentId, nextPeriod.toString());
  
  res.json({
    contentId,
    current: {
      periodId: currentPeriod.toString(),
      key: currentKey.toString('base64'),
      expiresAt: new Date((currentPeriod + 1) * rotationPeriod * 1000)
    },
    next: {
      periodId: nextPeriod.toString(),
      key: nextKey.toString('base64'),
      expiresAt: new Date((nextPeriod + 1) * rotationPeriod * 1000)
    }
  });
});

// Verify Ed25519 JWT from the CMS issuer
function verifyIssuerJwt(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization' });
  }
  
  const token = auth.slice(7);
  
  // Verify Ed25519 signature against registered CMS public keys
  const payload = verifyEdDsaToken(token, registeredCmsPublicKeys);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired JWT' });
  }
  
  req.cmsId = payload.iss;
  return next();
}`}</CodeBlock>

        <h3>User Unlock Endpoint</h3>
        <p>
          The main endpoint users call. Works with any key exchange method - it
          just needs to derive the same period key the CMS used.
        </p>
        <CodeBlock>{`// POST /api/unlock
app.post('/api/unlock', async (req, res) => {
  const { contentId, period, publicKey, wrappedContentKey } = req.body;
  
  // 1. Validate user subscription
  const user = await getUserFromSession(req);
  if (!user || !hasActiveSubscription(user, contentId)) {
    return res.status(403).json({ error: 'Invalid subscription' });
  }
  
  // 2. Derive period key (same as CMS used)
  const periodKey = derivePeriodKey(contentId, period);
  
  // 3. Unwrap content key with period key
  const contentKey = unwrapContentKey(Buffer.from(wrappedContentKey, 'base64'), periodKey);
  
  // 4. Re-wrap with user's RSA public key
  const publicKeyPem = convertSpkiToPem(publicKey);
  const encryptedForUser = publicEncrypt(
    {
      key: publicKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    contentKey
  );
  
  res.json({
    encryptedContentKey: encryptedForUser.toString('base64'),
    period,
    contentId
  });
});

function unwrapContentKey(wrappedContentKey: Buffer, periodKey: Buffer): Buffer {
  const iv = wrappedContentKey.subarray(0, 12);
  const authTag = wrappedContentKey.subarray(wrappedContentKey.length - 16);
  const ciphertext = wrappedContentKey.subarray(12, wrappedContentKey.length - 16);
  
  const decipher = createDecipheriv('aes-256-gcm', periodKey, iv);
  decipher.setAuthTag(authTag);
  
  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
}`}</CodeBlock>

        <h2>Testing</h2>

        <h3>Test CMS Authentication</h3>
        <p>Generate a key pair, register the public key, and fetch period keys with a signed JWT:</p>
        <CodeBlock>{`import { generateSigningKeyPair, createAsymmetricTokenManager } from '@sesamy/capsule-server';

// 1. Generate a key pair
const { privateKey, publicKey, keyId } = await generateSigningKeyPair();

// 2. Register public key with Subscription Server
await fetch('http://localhost:3000/api/cms/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ cmsId: 'test-cms', publicKey }),
});

// 3. Create token manager and sign a JWT
const tokens = await createAsymmetricTokenManager({
  issuer: 'test-cms',
  privateKey,
  publicKey,
  keyId,
});

const jwt = await tokens.generate({ contentId: 'premium', expiresIn: '5m' });

// 4. Fetch period keys
const res = await fetch('http://localhost:3000/api/period-keys', {
  method: 'POST',
  headers: {
    'Authorization': \`Bearer \${jwt}\`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ contentId: 'premium' }),
});

console.log(await res.json());
// { contentId, current: { periodId, key, expiresAt }, next: { ... } }`}</CodeBlock>

        <h3>Test User Unlock</h3>
        <CodeBlock>{`# User unlock request (with RSA public key)
curl -X POST http://localhost:3000/api/unlock \\
  -H "Content-Type: application/json" \\
  -d '{
    "contentId": "premium",
    "period": "1234567",
    "wrappedContentKey": "base64...",
    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
  }'`}</CodeBlock>

        <h2>Security Best Practices</h2>
        <ul>
          <li>
            🔒 <strong>Store secrets in KMS</strong> (AWS Secrets Manager,
            Google Secret Manager, HashiCorp Vault)
          </li>
          <li>
            🔒 <strong>Use HTTPS</strong> for all API endpoints
          </li>
          <li>
            🔒 <strong>Rate limit</strong> period-keys and unlock endpoints
          </li>
          <li>
            🔒 <strong>Log requests with redaction</strong> — never log raw
            tokens, keys, or credentials; mask Authorization headers and
            truncate identifiers in audit logs
          </li>
          <li>
            🔒 <strong>Rotate secrets periodically</strong>
          </li>
        </ul>

        <h4>Issuer Key Management</h4>
        <ul>
          <li>
            <strong>Store private keys in KMS</strong> — never in source code or
            environment variables in plaintext
          </li>
          <li>
            <strong>Use short-lived JWTs</strong> (5 minutes or less) for CMS
            authentication requests
          </li>
          <li>
            <strong>Rotate issuer key pairs</strong> annually — use JWKS with
            multiple keys during the transition window
          </li>
          <li>
            <strong>One key pair per CMS</strong> — do not share private keys
            across CMS instances
          </li>
        </ul>

        <h2>Share Link Tokens</h2>
        <p>
          Share links allow pre-authenticated access to premium content. Tokens
          can be signed with <strong>HMAC-SHA256</strong> (symmetric) or{" "}
          <strong>Ed25519</strong> (asymmetric with JWKS).
        </p>

        <h3>HMAC Token Generation</h3>
        <p>Simple shared-secret signing for first-party tokens:</p>
        <CodeBlock>{`import { createTokenManager } from '@sesamy/capsule-server';

const tokens = createTokenManager({
  secret: process.env.TOKEN_SECRET,
  issuer: 'my-publisher',
  keyId: 'key-2026-01',
});

// Generate a share token
const token = await tokens.generate({
  contentId: 'premium',
  expiresIn: '7d',
  maxUses: 100,
});

// Create shareable URL
const url = \`https://example.com/article/123?token=\${token}\`;`}</CodeBlock>

        <h3>Ed25519 Token Generation (Asymmetric)</h3>
        <p>
          For cross-domain validation without sharing secrets, use Ed25519
          signing with JWKS public key discovery:
        </p>
        <CodeBlock>{`import { 
  AsymmetricTokenManager, 
  generateSigningKeyPair 
} from '@sesamy/capsule-server';

// Generate or load a key pair (store the private key securely!)
const { privateKey, publicKey, keyId } = await generateSigningKeyPair();

const tokenManager = new AsymmetricTokenManager({
  issuer: 'https://api.example.com',  // URL used for JWKS discovery
  privateKey,
  publicKey,
  keyId,
});

// Generate an Ed25519-signed token
const token = await tokenManager.generate({
  contentId: 'premium',
  expiresIn: '30d',  // Tokens can be long-lived
});`}</CodeBlock>

        <h3>Exposing JWKS Endpoint</h3>
        <p>
          Expose your public keys at <code>/.well-known/jwks.json</code> so
          clients can validate tokens without needing your secret:
        </p>
        <CodeBlock>{`// Next.js: app/.well-known/jwks.json/route.ts
import { tokenManager } from '@/lib/tokens';

export async function GET() {
  return Response.json(await tokenManager.getJwks());
}

// Returns:
// {
//   "keys": [{
//     "kty": "OKP",
//     "crv": "Ed25519",
//     "kid": "key-2026-01",
//     "x": "base64url-public-key",
//     "use": "sig",
//     "alg": "EdDSA"
//   }]
// }`}</CodeBlock>

        <h3>Key Rotation with JWKS</h3>
        <p>
          Token signing keys are <strong>separate from time period keys</strong>
          . Signing keys should be long-lived (months/years) since tokens may be
          valid for 30+ days. For rotation, add new keys to JWKS before using
          them:
        </p>
        <CodeBlock>{`// Support multiple signing keys during rotation
const currentKeyPair = await generateSigningKeyPair();
const previousKeyPair = loadPreviousKeyPair();

// Create managers for both keys
const currentManager = new AsymmetricTokenManager({
  issuer: 'https://api.example.com',
  privateKey: currentKeyPair.privateKey,
  publicKey: currentKeyPair.publicKey,
  keyId: currentKeyPair.keyId,
});

const previousManager = new AsymmetricTokenManager({
  issuer: 'https://api.example.com',
  privateKey: previousKeyPair.privateKey,
  publicKey: previousKeyPair.publicKey,
  keyId: previousKeyPair.keyId,
});

// Expose both public keys in JWKS
export async function GET() {
  return Response.json({
    keys: [
      ...(await currentManager.getJwks()).keys,   // Current signing key
      ...(await previousManager.getJwks()).keys,  // Previous (still validating old tokens)
    ]
  });
}

// Sign new tokens with current key only
const token = await currentManager.generate({ ... });`}</CodeBlock>

        <h3>Token Validation (Server-Side)</h3>
        <CodeBlock>{`import { createTokenManager } from '@sesamy/capsule-server';

const tokens = createTokenManager({
  secret: process.env.TOKEN_SECRET,
  issuer: 'my-publisher',
  keyId: 'key-2026-01',
});

// Validate HMAC token
const result = await tokens.validate(token);
if (!result.valid) {
  throw new Error(result.message);
}

// Use validated payload
const { contentId, exp, userId } = result.payload;`}</CodeBlock>

        <h2>Node.js</h2>
        <p>
          The Node.js implementation uses the built-in <code>crypto</code>{" "}
          module for maximum performance and minimal dependencies.
        </p>

        <h3>Installation</h3>
        <CodeBlock language="bash">{`npm install @sesamy/capsule-server`}</CodeBlock>

        <h3>Basic Usage</h3>
        <CodeBlock>{`import { createCmsServer, createPeriodKeyProvider } from '@sesamy/capsule-server';

const keyProvider = createPeriodKeyProvider({
  periodSecret: process.env.PERIOD_SECRET,
});

const cms = createCmsServer({
  getKeys: (keyIds) => keyProvider.getKeys(keyIds),
});

// Encrypt content with period-based keys
const encrypted = await cms.encrypt('article-123', content, {
  keyIds: ['premium'],
  contentId: 'premium',
});

// Result: EncryptedArticle with wrappedKeys and encrypted payload`}</CodeBlock>

        <h3>API Routes (Next.js Example)</h3>
        <CodeBlock>{`// app/api/unlock/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { publicEncrypt, constants } from 'crypto';

export async function POST(request: NextRequest) {
  const { contentId, publicKey } = await request.json();
  
  // Get the content key for this contentId
  const contentKey = getContentKeyForContentId(contentId);
  
  // Convert Base64 SPKI to PEM
  const publicKeyPem = convertToPem(publicKey);
  
  // Wrap content key with client's RSA public key
  const encryptedContentKey = publicEncrypt(
    {
      key: publicKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    contentKey
  );
  
  return NextResponse.json({
    encryptedContentKey: encryptedContentKey.toString('base64'),
    contentId
  });
}`}</CodeBlock>

        <h3>Pre-Encrypting Content</h3>
        <CodeBlock>{`import { createCipheriv, randomBytes } from 'crypto';

function encryptArticle(content: string, contentKey: Buffer) {
  const iv = randomBytes(12); // 96-bit IV
  
  const cipher = createCipheriv('aes-256-gcm', contentKey, iv, {
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
    contentId: 'premium'
  };
}

// At build time or when content is published:
const articles = [
  { id: '1', content: '...' },
  { id: '2', content: '...' }
];

const premiumContentKey = randomBytes(32); // Generate once per contentId
const encrypted = articles.map(article =>
  encryptArticle(article.content, premiumContentKey)
);`}</CodeBlock>

        <h2>PHP</h2>
        <p>PHP implementation using OpenSSL for cryptographic operations.</p>

        <h3>Basic Usage</h3>
        <CodeBlock language="php">{`<?php

// Encrypt content
$contentKey = random_bytes(32); // AES-256 key
$iv = random_bytes(12);  // GCM IV

$encrypted = openssl_encrypt(
    $content,
    'aes-256-gcm',
    $contentKey,
    OPENSSL_RAW_DATA,
    $iv,
    $tag
);

$result = [
    'encryptedContent' => base64_encode($encrypted . $tag),
    'iv' => base64_encode($iv),
    'contentId' => 'premium'
];`}</CodeBlock>

        <h3>Key Exchange Endpoint</h3>
        <CodeBlock language="php">{`<?php

// api/unlock.php
header('Content-Type: application/json');

$input = json_decode(file_get_contents('php://input'), true);
$contentId = $input['contentId'];
$publicKey = $input['publicKey'];

// Get content key for contentId
$contentKey = getContentKeyForContentId($contentId);

// Convert SPKI to PEM
$publicKeyPem = convertSpkiToPem($publicKey);

// Wrap content key with RSA-OAEP
$encryptedContentKey = '';
openssl_public_encrypt(
    $contentKey,
    $encryptedContentKey,
    $publicKeyPem,
    OPENSSL_PKCS1_OAEP_PADDING
);

echo json_encode([
    'encryptedContentKey' => base64_encode($encryptedContentKey),
    'contentId' => $contentId
]);

function convertSpkiToPem($base64Spki) {
    $der = base64_decode($base64Spki);
    $pem = "-----BEGIN PUBLIC KEY-----\\n";
    $pem .= chunk_split(base64_encode($der), 64);
    $pem .= "-----END PUBLIC KEY-----";
    return $pem;
}`}</CodeBlock>

        <h2>Python</h2>
        <p>
          Python support using the <code>cryptography</code> library.
        </p>

        <h3>Installation</h3>
        <CodeBlock language="bash">{`pip install cryptography`}</CodeBlock>

        <h3>Basic Usage</h3>
        <CodeBlock language="python">{`from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import base64

# Encrypt content
def encrypt_article(content: str, contentKey: bytes) -> dict:
    iv = os.urandom(12)
    aesgcm = AESGCM(contentKey)
    ciphertext = aesgcm.encrypt(iv, content.encode(), None)
    
    return {
        'encryptedContent': base64.b64encode(ciphertext).decode(),
        'iv': base64.b64encode(iv).decode(),
        'contentId': 'premium'
    }

# Wrap content key
def wrap_content_key(content_key: bytes, public_key_spki: str) -> str:
    # Load public key from SPKI
    public_key = serialization.load_der_public_key(
        base64.b64decode(public_key_spki)
    )
    
    # Wrap with RSA-OAEP
    encrypted = public_key.encrypt(
        content_key,
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
          Want to contribute an implementation? Check out the{" "}
          <a href="https://github.com/capsule-standard/capsule">
            GitHub repository
          </a>
          .
        </p>
      </main>
    </PageWithToc>
  );
}
