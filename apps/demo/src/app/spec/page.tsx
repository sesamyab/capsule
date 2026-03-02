import { CodeBlock } from "@/components/CodeBlock";
import { PageWithToc } from "@/components/PageWithToc";

export default function SpecPage() {
  return (
    <PageWithToc>
      <main className="content-page">
        <h1>Specification</h1>
        <p>
          Capsule is an open standard for client-side article encryption using
          envelope encryption. It enables secure content delivery without
          requiring server-side authentication or permission systems.
        </p>

        <h2>Architecture Overview</h2>
        <p>
          Capsule uses the <strong>Delegated Content Access (DCA)</strong>{" "}
          protocol, which separates content encryption (publisher) from access
          control (issuer). The publisher encrypts content with AES-256-GCM and
          seals keys for each issuer using ECDH P-256. Issuers unseal keys only
          when access is granted, and the client decrypts content locally in the
          browser.
        </p>
        <h3>Roles</h3>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "1rem",
            marginBottom: "1rem",
          }}
        >
          <thead>
            <tr>
              <th style={{ textAlign: "left", padding: "0.5rem", borderBottom: "2px solid #333" }}>Role</th>
              <th style={{ textAlign: "left", padding: "0.5rem", borderBottom: "2px solid #333" }}>Responsibility</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}><strong>Publisher</strong></td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>Encrypts content at render time. Seals per-content keys for each issuer with ECDH P-256. Signs a <code>resourceJWT</code> (ES256) binding metadata and an <code>issuerJWT</code> proving sealed-blob integrity (SHA-256 hashes).</td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}><strong>Issuer</strong></td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>Owns an ECDH P-256 key pair. On unlock, verifies both JWTs, checks integrity proofs, unseals keys, and returns them to the client.</td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}><strong>Client</strong></td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>Parses DCA data from the page, calls the issuer's unlock endpoint, receives keys, and decrypts content locally with AES-256-GCM.</td>
            </tr>
          </tbody>
        </table>

        <h2>Encryption Flow</h2>
        <h3>Content Encryption</h3>
        <p>
          The publisher generates a random <strong>contentKey</strong> (256-bit AES)
          and optional rotating <strong>periodKeys</strong> per content item, then
          encrypts content with AES-256-GCM using a random nonce and an AAD string.
          The contentKey is additionally wrapped with each periodKey so the issuer
          can grant either content-level or period-level access.
        </p>
        <CodeBlock>{`// Publisher render (server-side)
const result = await publisher.render({
  resourceId: "article-123",
  contentItems: [
    { contentName: "bodytext", content: "<p>Premium content…</p>" },
  ],
  issuers: [
    {
      issuerName: "sesamy",
      publicKeyPem: ISSUER_ECDH_PUBLIC_KEY_PEM,
      keyId: "issuer-key-1",
      unlockUrl: "https://issuer.example.com/api/unlock",
      contentNames: ["bodytext"],
    },
  ],
});

// result.html.dcaDataScript → <script class="dca-data">…</script>
// result.html.sealedContentTemplate → <template class="dca-sealed-content">…</template>`}</CodeBlock>

        <h3>Key Sealing (Publisher → Issuer)</h3>
        <p>
          For each issuer, the publisher uses <strong>ECDH P-256</strong> key
          agreement to derive a shared secret, then wraps the contentKey and
          periodKeys with AES-256-GCM. The resulting opaque blobs are stored in{" "}
          <code>issuerData</code>. Only the matching issuer private key can
          unseal them.
        </p>
        <CodeBlock>{`// Sealing internals (automatic during render)
// 1. Ephemeral ECDH P-256 key pair generated per seal operation
// 2. ECDH shared secret derived: ephemeralPrivate × issuerPublic
// 3. HKDF extract-and-expand → 256-bit wrapping key
// 4. AES-256-GCM wrap each key with a unique 12-byte nonce
// 5. Sealed blob = ephemeralPublicKey ‖ nonce ‖ ciphertext ‖ tag`}</CodeBlock>

        <h3>Integrity Proofs</h3>
        <p>
          The publisher signs an <code>issuerJWT</code> for each issuer containing
          SHA-256 hashes of every sealed blob. On unlock, the issuer verifies these
          hashes before unsealing — preventing a tampered page from tricking the
          issuer into revealing keys for content it didn't encrypt.
        </p>
        <CodeBlock>{`// issuerJWT payload (signed by publisher's ES256 key)
{
  "renderId": "abc123…",           // Binds to resourceJWT
  "issuerName": "sesamy",
  "proof": {
    "bodytext": {
      "contentKey": "base64url(SHA-256(sealedContentKeyBlob))",
      "periodKeys": {
        "251023T13": "base64url(SHA-256(sealedPeriodKeyBlob))"
      }
    }
  }
}`}</CodeBlock>

        <h3>DCA HTML Embedding</h3>
        <p>
          DCA data and sealed content are embedded using two elements. The{" "}
          <code>&lt;script&gt;</code> tag holds all metadata, JWTs, and sealed keys.
          The <code>&lt;template&gt;</code> tag holds the encrypted content blobs
          (inert — no scripts execute, no images load).
        </p>
        <CodeBlock>{`<!-- DCA metadata + sealed keys -->
<script type="application/json" class="dca-data">
{
  "version": "1",
  "resource": {
    "renderId": "abc123",
    "domain": "news.example.com",
    "resourceId": "article-123",
    "issuedAt": "2025-01-15T12:00:00Z",
    "data": { "tier": "premium" }
  },
  "resourceJWT": "eyJ…",
  "issuerJWT": { "sesamy": "eyJ…" },
  "contentSealData": {
    "bodytext": { "contentType": "text/html", "nonce": "…", "aad": "…" }
  },
  "sealedContentKeys": {
    "bodytext": [{ "t": "251023T13", "nonce": "…", "key": "…" }]
  },
  "issuerData": {
    "sesamy": {
      "sealed": {
        "bodytext": {
          "contentKey": "base64url-sealed-blob",
          "periodKeys": { "251023T13": "base64url-sealed-blob" }
        }
      },
      "unlockUrl": "https://issuer.example.com/api/unlock",
      "keyId": "issuer-key-1"
    }
  }
}
</script>

<!-- Encrypted content (inert) -->
<template class="dca-sealed-content">
  <div data-dca-content-name="bodytext">base64url-encrypted-content…</div>
</template>`}</CodeBlock>

        <h3>Unlock Flow</h3>
        <p>
          When the client calls the issuer's unlock endpoint, the issuer performs
          a multi-step verification before returning keys:
        </p>
        <ol>
          <li>Verify <code>resourceJWT</code> signature (ES256) using the publisher's public key, looked up by <code>resource.domain</code>.</li>
          <li>Verify <code>issuerJWT</code> signature with the same publisher key; check that <code>renderId</code> matches.</li>
          <li>Verify integrity proofs — SHA-256 of each sealed blob must match the signed hashes in <code>issuerJWT</code>.</li>
          <li>Unseal keys using the issuer's ECDH private key (reverse of the sealing process).</li>
          <li>Return keys to the client — either as plaintext (direct) or RSA-OAEP wrapped (client-bound).</li>
        </ol>

        <CodeBlock>{`// Client → Issuer
POST /api/unlock
{
  "resource": { "domain": "news.example.com", "resourceId": "article-123", … },
  "resourceJWT": "eyJ…",
  "issuerJWT": "eyJ…",
  "sealed": { "bodytext": { "contentKey": "…", "periodKeys": { "251023T13": "…" } } },
  "keyId": "issuer-key-1",
  "issuerName": "sesamy",
  "clientPublicKey": "base64url-SPKI-RSA-public-key"   // ← enables client-bound mode
}

// Issuer → Client
{
  "keys": {
    "bodytext": {
      "contentKey": "base64url-key-or-wrapped-key",
      "periodKeys": { "251023T13": "base64url-key-or-wrapped-key" }
    }
  },
  "transport": "client-bound"    // or "direct" (default)
}`}</CodeBlock>

        <h3>Transport Modes</h3>
        <p>
          DCA deliberately leaves the issuer → client transport unspecified. Capsule
          implements two modes:
        </p>

        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "1rem",
            marginBottom: "1rem",
          }}
        >
          <thead>
            <tr>
              <th style={{ textAlign: "left", padding: "0.5rem", borderBottom: "2px solid #333" }}>Mode</th>
              <th style={{ textAlign: "left", padding: "0.5rem", borderBottom: "2px solid #333" }}>Key Delivery</th>
              <th style={{ textAlign: "left", padding: "0.5rem", borderBottom: "2px solid #333" }}>Security</th>
              <th style={{ textAlign: "left", padding: "0.5rem", borderBottom: "2px solid #333" }}>Best For</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}><strong>Direct</strong></td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>Plaintext base64url keys in HTTPS response</td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>TLS only — keys visible in server logs, CDN edges, DevTools</td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>Simple deployments, trusted infrastructure</td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}><strong>Client-bound</strong></td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>RSA-OAEP wrapped with client's browser public key</td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>End-to-end — only the originating browser can unwrap</td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>High-security content, zero-trust environments</td>
            </tr>
          </tbody>
        </table>

        <h3>Client-Bound Transport</h3>
        <p>
          Client-bound transport adds an RSA-OAEP encryption layer on the
          issuer → client leg. The client generates an RSA key pair once and
          stores the <strong>non-extractable</strong> private key in IndexedDB.
          The public key is sent with every unlock request.
        </p>

        <h4>Key Pair Lifecycle</h4>
        <CodeBlock>{`// DcaClient with client-bound transport enabled
const client = new DcaClient({
  clientBound: true,       // Enable RSA key wrapping
  rsaKeySize: 2048,        // RSA modulus length (default: 2048)
  keyDbName: "dca-keys",   // IndexedDB database name
});

// First unlock triggers key pair generation:
// 1. crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, … })
// 2. Private key re-imported as non-extractable (extractable: false)
// 3. Key pair stored in IndexedDB

// Subsequent visits: key pair loaded from IndexedDB automatically`}</CodeBlock>

        <h4>Wrapping Flow</h4>
        <CodeBlock>{`// Client-bound unlock sequence:

// 1. Client includes RSA public key in unlock request
POST /api/unlock {
  …dcaFields,
  "clientPublicKey": "base64url(SPKI-encoded RSA-OAEP public key)"
}

// 2. Issuer unseals keys normally, then wraps each with client's public key
for each key in unsealedKeys:
  wrappedKey = RSA-OAEP-Encrypt(clientPublicKey, rawKeyBytes)
  response.keys[contentName][keyType] = base64url(wrappedKey)
response.transport = "client-bound"

// 3. Client receives wrapped keys — opaque ciphertext, useless without private key
// 4. Client unwraps each key with its non-extractable private key
rawKey = RSA-OAEP-Decrypt(privateKey, wrappedKeyBytes)
// → AES-256 key material, ready for content decryption`}</CodeBlock>

        <h4>Security Properties of Client-Bound Transport</h4>
        <ul>
          <li>✅ <strong>End-to-end encryption:</strong> Key material is never in plaintext outside the browser's crypto engine</li>
          <li>✅ <strong>Non-extractable private key:</strong> Even XSS or DevTools cannot read the raw RSA private key bytes</li>
          <li>✅ <strong>Server-side opacity:</strong> The issuer sees only the client's public key — it cannot observe which keys the client actually uses</li>
          <li>✅ <strong>Replay resistance:</strong> Wrapped keys are bound to one browser's key pair</li>
          <li>✅ <strong>Backward compatible:</strong> If <code>clientPublicKey</code> is absent, the issuer falls back to direct transport</li>
          <li>⚠️ <strong>Device-bound:</strong> Keys cannot be transferred between browsers/devices (by design)</li>
        </ul>

        <h3>Client-Side Decryption</h3>
        <p>
          After receiving keys (direct or unwrapped), the client decrypts content
          using AES-256-GCM with the original nonce and AAD from <code>contentSealData</code>:
        </p>
        <CodeBlock>{`// 1. Parse DCA data from the page
const page = client.parsePage();

// 2. Unlock via issuer (sends sealed keys + optional clientPublicKey)
const response = await client.unlock("sesamy");

// 3. Decrypt content (handles unwrapping if client-bound)
const html = await client.decrypt("sesamy", "bodytext", response);

// 4. Replace placeholder with decrypted content
document.querySelector('[data-dca-content-name="bodytext"]')
  .innerHTML = html;`}</CodeBlock>

        <h3>Handling Decrypted Content in Scripts</h3>
        <p>
          Since content is decrypted client-side <em>after</em> the initial page
          load, any scripts that need to process the content (syntax
          highlighting, analytics, interactive widgets, etc.) must run after
          decryption completes. There are two approaches:
        </p>

        <h4>
          Option A: Listen for the <code>capsule:unlocked</code> Event
        </h4>
        <p>
          Capsule dispatches a custom event when content is decrypted and added
          to the DOM:
        </p>
        <CodeBlock>{`document.addEventListener("capsule:unlocked", (event) => {
  const { resourceId, element, keyId } = event.detail;
  
  // element is the DOM container with the decrypted content
  // Run your initialization code here
  highlightCodeBlocks(element);
  initializeWidgets(element);
  
  console.log(\`Article "\${resourceId}" unlocked with key: \${keyId}\`);
});`}</CodeBlock>

        <h4>Option B: Use a MutationObserver</h4>
        <p>
          For more generic DOM change detection, use a{" "}
          <code>MutationObserver</code>:
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


        <h2>Share Link Tokens</h2>
        <p>
          Share links allow pre-authenticated access to premium content without
          requiring the recipient to have a subscription. This enables social
          media sharing, email distribution, and promotional campaigns.
        </p>

        <h3>The Share Link Problem</h3>
        <p>
          When creating a shareable link, you need to grant access to content
          that the link creator doesn't have access to yet. The solution:{" "}
          <strong>signed tokens</strong> that encode the content ID, enabling
          any holder to unlock content.
        </p>

        <CodeBlock>{`// Share Link Flow
Publisher → creates token → shares URL → Recipient clicks → content unlocks

// Key Insight: Token contains contentId, not the content key
// The content key comes from the encrypted article at unlock time`}</CodeBlock>

        <h3>Token Structure</h3>
        <p>
          Tokens are HMAC-SHA256 signed, base64url-encoded payloads containing:
        </p>

        <CodeBlock>{`{
  "v": 1,                      // Token version
  "tid": "abc123...",          // Unique token ID (for tracking/revocation)
  "iss": "my-publisher",       // Issuer (who created the token)
  "kid": "key-2026-01",        // Key ID (which signing key was used)
  "contentId": "premium",           // Required: content ID
  "url": "https://...",        // Optional: full URL for the content
  "maxUses": 100,              // Optional: usage limit
  "userId": "publisher-123",   // Optional: for analytics
  "meta": { "campaign": "fb" },// Optional: custom metadata
  "iat": 1707400800,           // Issued at (Unix timestamp)
  "exp": 1708005600            // Expires at (Unix timestamp)
}`}</CodeBlock>

        <h3>Token Generation</h3>
        <CodeBlock>{`import { createTokenManager } from '@sesamy/capsule-server';

// Create manager with signing secret, issuer, and key ID
const tokens = createTokenManager({
  secret: process.env.TOKEN_SECRET,
  issuer: 'my-publisher',      // Identifies who issues tokens
  keyId: 'key-2026-01',        // Enables key rotation
});

// Generate a share token
const token = await tokens.generate({
  tier: 'premium',             // Required: which tier this token grants access to
  contentId: 'crypto-guide',   // Required: which content this token unlocks
  url: 'https://example.com/article/crypto-guide', // Optional
  expiresIn: '24h',
  maxUses: 50,
  userId: 'publisher-123',
  meta: { campaign: 'twitter-launch' }
});

// Create shareable URL
const shareUrl = \`https://example.com/article/crypto-guide?token=\${token}\`;`}</CodeBlock>

        <h3>Client-Side Token Validation</h3>
        <p>
          Clients can validate tokens locally without calling the server. This
          enables:
        </p>
        <ul>
          <li>Checking expiry before making network requests</li>
          <li>Redirecting to the correct content URL</li>
          <li>Displaying issuer/attribution info in the UI</li>
          <li>Validating that the token matches the current content</li>
        </ul>

        <CodeBlock>{`import { parseShareToken, validateTokenForContent } from '@sesamy/capsule';

// Parse token from URL
const token = new URLSearchParams(window.location.search).get('token');
if (token) {
  const result = parseShareToken(token);
  
  if (!result.valid) {
    showError('Invalid share link');
    return;
  }
  
  if (result.expired) {
    showError('This share link has expired');
    return;
  }
  
  // Validate it's for the current content
  const validation = validateTokenForContent(result, currentResourceId);
  if (!validation.valid) {
    // Redirect to correct content
    window.location.href = result.payload.url || \`/article/\${result.payload.contentId}\`;
    return;
  }
  
  // Token is valid - proceed with unlock
  console.log(\`Shared by \${result.payload.iss}, expires in \${result.expiresIn}s\`);
}`}</CodeBlock>

        <h3>HMAC Signature Validation (Server-Side Only)</h3>
        <p>
          <strong>⚠️ Security Warning:</strong> HMAC uses symmetric secrets -
          anyone with the secret can <em>forge</em> tokens. Never expose the
          signing secret in client-side code (no <code>NEXT_PUBLIC_</code> env
          vars). Use <code>TokenValidator</code> only in server-side code (API
          routes, middleware). For client-side validation, use{" "}
          <code>JwksTokenValidator</code> with Ed25519.
        </p>

        <CodeBlock>{`// ⚠️ SERVER-SIDE ONLY - app/api/validate-token/route.ts
import { TokenValidator } from '@sesamy/capsule';

const validator = new TokenValidator({
  trustedKeys: {
    'my-publisher:key-2026-01': process.env.TOKEN_SECRET, // Server-only env var!
  },
  requireTrustedIssuer: true,
});

export async function POST(request: Request) {
  const { token } = await request.json();
  const result = await validator.validate(token);

  if (!result.valid) {
    return Response.json({ error: result.message }, { status: 401 });
  }

  if (result.expired) {
    return Response.json({ error: 'Token expired' }, { status: 401 });
  }

  return Response.json({ 
    valid: true, 
    issuer: result.payload.iss,
    contentId: result.payload.contentId,
  });
}`}</CodeBlock>

        <h3>JWKS-Based Validation (Ed25519) - Client-Side Safe</h3>
        <p>
          For asymmetric key signing with automatic public key discovery, use
          the <code>JwksTokenValidator</code>. This approach:
        </p>
        <ul>
          <li>
            Uses <strong>Ed25519 asymmetric signing</strong> instead of shared
            secrets
          </li>
          <li>
            Fetches public keys from the issuer's{" "}
            <code>/.well-known/jwks.json</code> endpoint
          </li>
          <li>Requires only the issuer URL, not the actual secret</li>
          <li>Enables cross-domain token validation without sharing secrets</li>
        </ul>

        <h4>Server-Side: Expose JWKS Endpoint</h4>
        <p>
          Generate Ed25519 key pairs and expose the public key at a well-known
          URL:
        </p>

        <CodeBlock>{`import { 
  AsymmetricTokenManager, 
  generateSigningKeyPair 
} from '@sesamy/capsule-server';

// Generate or load a key pair (store securely!)
const { privateKey, publicKey, keyId } = await generateSigningKeyPair();

const tokenManager = new AsymmetricTokenManager({
  issuer: 'https://api.example.com',
  privateKey,
  publicKey,
  keyId,
});

// Generate an Ed25519-signed token
const token = await tokenManager.generate({
  contentId: 'article-123',
  expiresIn: '7d',
});

// /.well-known/jwks.json endpoint
export async function GET() {
  return Response.json(await tokenManager.getJwks());
}

// Returns:
// {
//   "keys": [{
//     "kty": "OKP",
//     "crv": "Ed25519",
//     "kid": "key-2025-01",
//     "x": "base64url-encoded-public-key",
//     "use": "sig",
//     "alg": "EdDSA"
//   }]
// }`}</CodeBlock>

        <h4>Client-Side: JWKS Validation</h4>
        <p>
          Use <code>JwksTokenValidator</code> to validate tokens from trusted
          issuers. The client automatically fetches the issuer's JWKS endpoint
          and verifies signatures:
        </p>

        <CodeBlock>{`import { JwksTokenValidator } from '@sesamy/capsule';

// Whitelist trusted issuers by URL
const validator = new JwksTokenValidator({
  trustedIssuers: [
    'https://api.example.com',
    'https://partner.example.org',
  ],
});

// Validate a token
const result = await validator.validate(token);

if (result.valid && !result.expired) {
  console.log(\`Verified token from \${result.issuer}\`);
  console.log(\`Key ID: \${result.keyId}\`);
  console.log(\`Content: \${result.payload.contentId}\`);
}

// JWKS Discovery Flow:
// 1. Token contains iss = "https://api.example.com"
// 2. Client checks iss is in trustedIssuers (security!)
// 3. Client fetches https://api.example.com/.well-known/jwks.json
// 4. Client finds key with matching kid
// 5. Client verifies Ed25519 signature using public key`}</CodeBlock>

        <h4>Key Rotation: Signing Keys vs Time Period Keys</h4>
        <p>
          Token signing keys are <strong>separate from time period keys</strong>{" "}
          and have different rotation schedules:
        </p>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "1rem",
            marginBottom: "1rem",
          }}
        >
          <thead>
            <tr>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Key Type
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Purpose
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Rotation
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Time period keys
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Wrap content keys for subscriptions
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Every 15 minutes (controls subscription window)
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Token signing keys
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Sign share link tokens
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Infrequently (months/years)
              </td>
            </tr>
          </tbody>
        </table>
        <p>
          Signing keys must be <strong>long-lived</strong> because share links
          may be valid for 30+ days. If you rotate the signing key, old tokens
          would fail validation. For key rotation, add the new key to JWKS
          first, then start using it for new tokens. Keep old keys in JWKS until
          all tokens signed with them have expired.
        </p>

        <CodeBlock>{`// JWKS can contain multiple keys for rotation
{
  "keys": [
    { "kid": "key-2026-01", "x": "...", ... },  // Current signing key
    { "kid": "key-2025-01", "x": "...", ... },  // Previous key (still validating old tokens)
  ]
}`}</CodeBlock>

        <h4>Choosing HMAC vs Ed25519</h4>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "1rem",
            marginBottom: "1rem",
          }}
        >
          <thead>
            <tr>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Feature
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                TokenValidator (HMAC)
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                JwksTokenValidator (Ed25519)
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Signing
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Symmetric (shared secret)
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Asymmetric (public/private)
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Secret sharing
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Client needs secret
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Client only needs issuer URL
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Key discovery
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Manual configuration
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Automatic via JWKS
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Cross-domain
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Requires secret sharing
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Works without sharing secrets
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Best for
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                First-party tokens
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Third-party/partner tokens
              </td>
            </tr>
          </tbody>
        </table>

        <h3>Token-Based Unlock Flow</h3>
        <p>
          When a user clicks a share link with a token, the unlock flow differs
          from the standard subscription flow:
        </p>

        <CodeBlock>{`// Standard Flow:
// Client → Issuer /api/unlock { dcaFields, clientPublicKey } → validates access → returns keys

// Token-Based Flow:
// Client → /api/unlock { token, wrappedContentKey, publicKey } → validates token → returns content key`}</CodeBlock>

        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "1rem",
            marginBottom: "1rem",
          }}
        >
          <thead>
            <tr>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Step
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Action
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                1. Client extracts token
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Parses <code>?token=...</code> from URL
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                2. Client sends unlock request
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Includes token + wrapped content key from article
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                3. Server validates token
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Verifies signature, expiry, usage limits
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                4. Server unwraps content key
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Uses period key from token's contentId to unwrap
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                5. Server re-wraps for client
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Wraps content key with client's public key
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                6. Client decrypts content
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Uses content key to decrypt article
              </td>
            </tr>
          </tbody>
        </table>

        <h3>Server-Side Token Validation</h3>
        <CodeBlock>{`import { createTokenManager, createSubscriptionServer } from '@sesamy/capsule-server';

// Create token manager (same config as generation)
const tokens = createTokenManager({
  secret: process.env.TOKEN_SECRET,
  issuer: 'my-publisher',
  keyId: 'key-2026-01',
});

const server = createSubscriptionServer({
  periodSecret: process.env.PERIOD_SECRET,
});

// Validate token
const validation = await tokens.validate(token);
if (!validation.valid) {
  throw new Error(validation.message); // "Token has expired", etc.
}

// Unlock using validated token payload
const result = await server.unlockWithToken(
  validation.payload,      // Validated token payload
  wrappedContentKey,       // From article.wrappedKeys[keyId]
  userPublicKey,           // Client's RSA public key (Base64 SPKI)
  contentId,               // Validates against token.contentId
);

// result contains:
// - encryptedContentKey: content key wrapped with user's public key
// - keyId: Which key was used
// - expiresAt: When the unlock expires`}</CodeBlock>

        <h3>Analytics & Audit Trail</h3>
        <p>Token-based unlocks provide full audit trail capability:</p>
        <ul>
          <li>
            <strong>Token issuer:</strong> <code>iss</code> field
          </li>
          <li>
            <strong>Signing key:</strong> <code>kid</code> for key rotation
            tracking
          </li>
          <li>
            <strong>Who created the link:</strong> <code>userId</code> in token
          </li>
          <li>
            <strong>What content:</strong> <code>contentId</code> (required)
          </li>
          <li>
            <strong>Campaign tracking:</strong> <code>meta</code> field
          </li>
          <li>
            <strong>Usage counting:</strong> <code>maxUses</code> limit
          </li>
        </ul>

        <CodeBlock>{`// Example: Log token unlock for analytics
console.log('[UNLOCK] Token used', {
  tokenId: payload.tid,
  issuer: payload.iss,
  keyId: payload.kid,
  contentId: payload.contentId,
  userId: payload.userId,
  campaign: payload.meta?.campaign,
  contentId: payload.contentId,
  timestamp: new Date().toISOString(),
});`}</CodeBlock>

        <h3>Security Considerations for Share Links</h3>
        <ul>
          <li>
            ✅ Tokens are cryptographically signed (HMAC-SHA256 or Ed25519)
          </li>
          <li>✅ Expiration limits exposure window</li>
          <li>✅ Usage limits prevent unlimited sharing</li>
          <li>✅ Content ID binding prevents token reuse across content</li>
          <li>
            ✅ Key ID (<code>kid</code>) enables signing key rotation
          </li>
          <li>✅ Client-side validation without server round-trip</li>
          <li>✅ Full audit trail for analytics and abuse detection</li>
          <li>✅ JWKS enables public key discovery without secret sharing</li>
          <li>
            ✅ Issuer whitelist (<code>trustedIssuers</code>) prevents arbitrary
            token acceptance
          </li>
          <li>
            ⚠️ Token secret (HMAC) or private key (Ed25519) must be kept secure
          </li>
          <li>
            ⚠️ Tokens are bearer credentials - anyone with the URL has access
          </li>
        </ul>

        <h2>Security Considerations</h2>

        <h3>Period Secret Protection</h3>
        <p>
          The period secret is the root of all security. If compromised,
          attackers can derive all future period keys. Only the publisher
          should hold the period secret.
        </p>

        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            marginTop: "1rem",
            marginBottom: "1rem",
          }}
        >
          <thead>
            <tr>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Component
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Public/Secret
              </th>
              <th
                style={{
                  textAlign: "left",
                  padding: "0.5rem",
                  borderBottom: "2px solid #333",
                }}
              >
                Storage
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Period Secret
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                🔒 SECRET
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                KMS only (Publisher server)
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Period Derivation Algorithm
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                ✅ Public
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Open source code
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Period Keys
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                🔒 SECRET
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Derived on-demand, cached briefly
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Content Keys
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                🔒 SECRET
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Wrapped (never in plaintext)
              </td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                User Private Keys
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                🔒 SECRET
              </td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>
                Browser IndexedDB (non-extractable)
              </td>
            </tr>
          </tbody>
        </table>

        <h3>Access Revocation</h3>
        <p>
          With time-period keys, access is automatically revoked within the
          period duration (15 minutes):
        </p>
        <ul>
          <li>User's browser caches unwrapped content key until period expires</li>
          <li>
            When subscription cancelled, issuer refuses new unlock requests
          </li>
          <li>Cached content key expires → user can no longer decrypt new content</li>
          <li>No content re-encryption needed</li>
        </ul>

        <h3>Publisher Compromise Scenarios</h3>
        <p>
          <strong>If the publisher is compromised, attacker gets:</strong>
        </p>
        <ul>
          <li>❌ Plaintext content (publisher already has this)</li>
          <li>❌ Period secret and derived period keys</li>
          <li>✅ Cannot unseal keys without issuer private key</li>
          <li>✅ Cannot decrypt for other users (no user private keys)</li>
        </ul>

        <h3>Issuer Compromise Scenarios</h3>
        <p>
          <strong>If the issuer is compromised, attacker gets:</strong>
        </p>
        <ul>
          <li>❌ ECDH private key → can unseal content keys and period keys</li>
          <li>❌ Can decrypt content if they also have the encrypted content</li>
          <li>✅ Cannot access content without the encrypted HTML (publisher-side)</li>
          <li>✅ Cannot forge publisher JWTs (no ES256 signing key)</li>
        </ul>

        <p>
          <strong>Mitigation:</strong> Use separate infrastructure, rotate issuer
          key pairs, audit logs
        </p>

        <h3>Private Key Protection</h3>
        <p>
          Private keys must be stored with <code>extractable: false</code> in
          the Web Crypto API. This prevents JavaScript from accessing the raw
          key material.
        </p>

        <h3>Key Storage</h3>
        <p>
          The period secret and signing keys should be stored in a secure key
          management system (KMS) in production. Never hardcode secrets in
          source code.
        </p>

        <h3>Transport Security</h3>
        <p>
          The key exchange endpoint must use HTTPS. While the wrapped content key is
          encrypted, HTTPS prevents MITM attacks on the public key exchange.
        </p>

        <h3>IV Uniqueness</h3>
        <p>
          Each encrypted article must use a unique initialization vector (IV).
          Never reuse IVs with the same content key, as this breaks AES-GCM security.
        </p>

        <h2>Security Properties</h2>

        <h3>What Capsule Provides</h3>
        <ul>
          <li>
            ✅ <strong>Confidentiality:</strong> Content encrypted at rest and
            in transit
          </li>
          <li>
            ✅ <strong>Integrity:</strong> AES-GCM authentication detects
            tampering
          </li>
          <li>
            ✅ <strong>Forward Secrecy:</strong> Time periods limit exposure
            window
          </li>
          <li>
            ✅ <strong>Secure Key Transport:</strong> ECDH P-256 sealing + optional RSA-OAEP client-bound wrapping
          </li>
          <li>
            ✅ <strong>Offline Access:</strong> Cached keys work without network
          </li>
          <li>
            ✅ <strong>No Server-Side User Tracking:</strong> Keys are bearer
            tokens
          </li>
        </ul>

        <h3>What Capsule Does NOT Provide</h3>
        <ul>
          <li>
            ❌ <strong>DRM:</strong> Determined users can extract decrypted
            content
          </li>
          <li>
            ❌ <strong>Copy Protection:</strong> Once decrypted, content can be
            copied
          </li>
          <li>
            ❌ <strong>Watermarking:</strong> No user-specific content marking
          </li>
        </ul>
        <p>
          Capsule is designed for honest users who want convenient access, not
          for preventing determined adversaries from extracting content.
        </p>

        <h2>Implementation Checklist</h2>
        <ul>
          <li>✅ AES-256-GCM for content encryption</li>
          <li>✅ ECDH P-256 for key sealing</li>
          <li>✅ ES256 (ECDSA P-256) for JWT signing</li>
          <li>✅ Unique 96-bit IV per encrypted content</li>
          <li>✅ 128-bit authentication tag (GCM)</li>
          <li>✅ Private keys stored with extractable: false</li>
          <li>✅ HTTPS for key exchange endpoint</li>
          <li>✅ Proper error handling and validation</li>
        </ul>
      </main>
    </PageWithToc>
  );
}
