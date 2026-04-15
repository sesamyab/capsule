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
          wraps keys for each issuer using ECDH P-256. Issuers unwrap keys only
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
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>Encrypts content at render time. Wraps per-content keys for each issuer with ECDH P-256, using <code>scope</code> as wrap AAD. Signs a <code>resourceJWT</code> (ES256) binding metadata.</td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}><strong>Issuer</strong></td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>Owns an ECDH P-256 key pair. On unlock, reads <code>scope</code> from each entry, unwraps keys using <code>scope</code> as wrap AAD, and returns them to the client. Optionally verifies <code>resourceJWT</code> for publisher trust.</td>
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
          and optional rotating <strong>wrapKeys</strong> per content item, then
          encrypts content with AES-256-GCM using a random iv and an AAD string.
          The contentKey is additionally wrapped with each wrapKey so the issuer
          can grant either content-level or rotation-version-level access.
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

// result.html.dcaManifestScript → <script class="dca-manifest">…</script>`}</CodeBlock>

        <h3>Key Wrapping (Publisher → Issuer)</h3>
        <p>
          For each issuer, the publisher uses <strong>ECDH P-256</strong> key
          agreement to derive a shared secret, then wraps the contentKey and
          wrapKeys with AES-256-GCM. The resulting opaque blobs are stored in{" "}
          <code>issuers</code>. Only the matching issuer private key can
          unwrap them.
        </p>
        <CodeBlock>{`// Wrapping internals (automatic during render)
// 1. Ephemeral ECDH P-256 key pair generated per wrap operation
// 2. ECDH shared secret derived: ephemeralPrivate × issuerPublic
// 3. HKDF-SHA256(secret, salt="dca-wrap", info="dca-wrap-aes256gcm") → 256-bit wrapping key
// 4. AES-256-GCM wrap each key with a unique 12-byte iv
//    AAD = scope (binds wrapped blob to this access tier)
// 5. Wrapped blob = ephemeralPublicKey(65B) ‖ iv(12B) ‖ ciphertext+tag`}</CodeBlock>

        <h3>Wrap AAD (Additional Authenticated Data)</h3>
        <p>
          When wrapping contentKeys and wrapKeys for issuers, the publisher
          passes the <code>scope</code> (access tier) as AAD to the AES-GCM
          encryption (for ECDH P-256 wrapping) or as the RSA-OAEP label (for
          RSA-based wrapping). This cryptographically binds each wrapped key blob
          to its access tier.
        </p>
        <p>
          On unlock, the issuer reads <code>scope</code> from each
          entry and provides it as AAD when unwrapping. If the{" "}
          <code>scope</code> has been tampered with, AES-GCM decryption fails
          with an authentication error.
        </p>
        <p>
          <strong>Why this matters:</strong> Wrap AAD prevents{" "}
          <em>cross-tier key substitution attacks</em>. Without it, an
          attacker could change <code>scope</code> from &quot;free&quot; to
          &quot;premium&quot; on a wrapped entry, tricking the issuer into
          unwrapping keys for a tier they don&apos;t have access to. With wrap
          AAD, the wrapped blobs are bound to the original{" "}
          <code>scope</code> and cannot be unwrapped under a different tier.
        </p>
        <CodeBlock>{`// Wrap AAD binding
// Publisher (during render):
//   wrappedBlob = AES-256-GCM-Encrypt(wrappingKey, contentKey, iv, aad=scope)
//
// Issuer (during unlock):
//   1. Read scope from each keys entry
//   2. contentKey = AES-256-GCM-Decrypt(wrappingKey, wrappedBlob, iv, aad=scope)
//   3. If scope was tampered with → GCM auth tag check fails → reject`}</CodeBlock>

        <h3>Integrity Protection</h3>
        <p>
          Integrity of wrapped key blobs is guaranteed by{" "}
          <strong>wrap AAD</strong> rather than a separate <code>issuerJWT</code>.
          The <code>scope</code> (from each wrapped-key entry) is
          used as AAD during AES-GCM wrapping, so any substitution or tampering of
          wrapped blobs causes a GCM authentication failure at unwrap time. This
          replaces the older approach of signing per-issuer SHA-256 hash proofs in
          a separate JWT.
        </p>
        <CodeBlock>{`// Integrity: wrap AAD binds keys to access tier
//
// Old approach (deprecated): publisher signed an issuerJWT with SHA-256 hashes of wrapped blobs
//   → issuer verified hashes before unwrapping
//
// Current approach: publisher passes scope as AAD during AES-GCM wrapping
//   → issuer provides scope (from each entry) as AAD during unwrapping
//   → GCM authentication tag rejects any blob wrapped for a different tier
//
// Result: each entry is self-describing and tamper-proof, no separate mapping needed`}</CodeBlock>

        <h3>DCA HTML Embedding</h3>
        <p>
          The DCA manifest is embedded in a single <code>&lt;script&gt;</code>{" "}
          tag. It holds all metadata, the <code>resourceJWT</code>, wrapped keys,
          and the encrypted content ciphertext inline under each{" "}
          <code>content[name]</code> entry. The target elements on the page
          (e.g. <code>&lt;div data-dca-content-name=&quot;bodytext&quot;&gt;&lt;/div&gt;</code>)
          are empty placeholders that the client fills in after decryption.
        </p>
        <CodeBlock>{`<!-- DCA manifest: metadata + wrapped keys + ciphertext -->
<script type="application/json" class="dca-manifest">
{
  "version": "0.10",
  "resourceJWT": "eyJ…",
  "content": {
    "bodytext": {
      "contentType": "text/html",
      "iv": "…",
      "aad": "…",
      "ciphertext": "base64url-encrypted-content…",
      "wrappedContentKey": [
        { "kid": "251023T13", "iv": "…", "ciphertext": "…" }
      ]
    }
  },
  "issuers": {
    "sesamy": {
      "unlockUrl": "https://issuer.example.com/api/unlock",
      "keyId": "issuer-key-1",
      "keys": [
        {
          "contentName": "bodytext",
          "scope": "premium",
          "contentKey": "base64url-wrapped-blob",
          "wrapKeys": [
            { "kid": "251023T13", "key": "base64url-wrapped-blob" }
          ]
        }
      ]
    }
  }
}
</script>

<!-- Target placeholder (filled in by the client after decryption) -->
<div data-dca-content-name="bodytext"></div>`}</CodeBlock>

        <h3>Unlock Flow</h3>
        <p>
          When the client calls the issuer's unlock endpoint, the issuer performs
          a multi-step verification before returning keys:
        </p>
        <ol>
          <li>Optionally verify <code>resourceJWT</code> signature (ES256) using the publisher's public key, looked up by <code>resource.domain</code>.</li>
          <li>Read <code>scope</code> from each <code>keys</code> entry.</li>
          <li>Unwrap keys using the issuer's ECDH private key, providing <code>scope</code> as AAD (GCM auth tag validates the blob was wrapped for this access tier).</li>
          <li>Return keys to the client — either as plaintext (direct) or RSA-OAEP wrapped (client-bound).</li>
        </ol>

        <CodeBlock>{`// Client → Issuer
POST /api/unlock
{
  "resourceJWT": "eyJ…",             // optional — for publisher trust verification
  "keys": [
    {
      "contentName": "bodytext",
      "scope": "premium",             // AAD-bound access tier
      "contentKey": "base64url-wrapped-blob",
      "wrapKeys": [
        { "kid": "251023T13", "key": "base64url-wrapped-blob" }
      ]
    }
  ],
  "clientPublicKey": "base64url-SPKI-RSA-public-key"   // ← enables client-bound mode
}

// Issuer verification:
// 1. Optionally verify resourceJWT → extract domain, resourceId
// 2. Unwrap each key blob with ECDH private key + scope as AAD
//    (mismatched scope → GCM auth failure → reject)
// 3. Return keys

// Issuer → Client (one delivery form per entry)
//   deliveryMode: "direct"  → returns contentKey only
//   deliveryMode: "wrapKey" → returns wrapKeys only (cacheable, 1-hour rotation versions)
{
  "keys": [
    { "contentName": "bodytext", "scope": "premium", "contentKey": "base64url-key-or-wrapped-key" }
  ],
  "transport": "client-bound"    // or "direct" (default)
}
// — or with wrapKey delivery —
{
  "keys": [
    {
      "contentName": "bodytext",
      "scope": "premium",
      "wrapKeys": [
        { "kid": "251023T13", "key": "base64url-key-or-wrapped-key" }
      ]
    }
  ]
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

// 2. Issuer unwraps keys normally, then wraps each with client's public key
for each key in unwrappedKeys:
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
          using AES-256-GCM with the original iv and AAD from{" "}
          <code>content[name]</code>:
        </p>
        <CodeBlock>{`// 1. Parse DCA manifest from the page
const page = client.parsePage();

// 2. Unlock via issuer (sends wrapped keys + optional clientPublicKey)
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

        <h3>DCA-Compatible Design</h3>
        <p>
          The critical design insight: a share link token is <strong>purely an
            authorization grant</strong>, not a key-delivery mechanism. The
          publisher&apos;s <code>rotationSecret</code> never leaves the publisher.
          Key material flows through the normal DCA wrap/unwrap channel — the
          wrapped keys are already embedded in the page&apos;s DCA manifest, and
          the issuer unwraps them as usual.
        </p>
        <p>
          This is DCA-compatible because the issuer never needs the publisher&apos;s{" "}
          <code>rotationSecret</code>. The publisher creates a signed JWT that says
          &ldquo;this bearer may access these content items for this resource.&rdquo;
          The issuer validates the token signature (the publisher already has a
          trusted signing key in the allowlist), uses the token&apos;s claims as the
          access decision, and returns unwrapped keys from the normal DCA manifest.
        </p>

        <CodeBlock>{`// Share Link Flow (DCA-compatible)
//
// 1. Publisher signs a share token (ES256 JWT) granting access
// 2. User clicks the share link → loads page with normal DCA-wrapped content
// 3. Client includes the share token in the unlock request
// 4. Issuer verifies token (publisher-signed, trusted key) → access decision
// 5. Issuer unwraps keys from normal DCA manifest → returns to client
// 6. Client decrypts content locally
//
// Key insight: rotationSecret never leaves the publisher.
// The token is authorization only — key material uses normal DCA channels.`}</CodeBlock>

        <h3>Token Structure</h3>
        <p>
          Share link tokens are ES256 (ECDSA P-256) signed JWTs, using the
          same publisher signing key that signs <code>resourceJWT</code>.
          The issuer already trusts this key via its{" "}
          <code>trustedPublisherKeys</code> allowlist.
        </p>

        <CodeBlock>{`// DcaShareLinkTokenPayload (ES256 JWT payload)
{
  "type": "dca-share",                // Type discriminator
  "domain": "news.example.com",       // Publisher domain (must match resource)
  "resourceId": "article-123",        // Resource this token grants access to
  "contentNames": ["bodytext"],        // Content items to unlock
  "iat": 1707400800,                  // Issued at (Unix timestamp)
  "exp": 1708005600,                  // Expires at (Unix timestamp)
  "maxUses": 100,                     // Optional: usage limit (advisory)
  "jti": "share-abc123",              // Optional: unique ID (for tracking/revocation)
  "data": { "campaign": "twitter" }   // Optional: publisher-defined metadata
}`}</CodeBlock>

        <h3>Token Generation (Publisher)</h3>
        <p>
          The publisher creates share tokens using the same{" "}
          <code>createDcaPublisher</code> instance that renders pages:
        </p>
        <CodeBlock>{`import { createDcaPublisher } from '@sesamy/capsule-server';

const publisher = createDcaPublisher({
  domain: "news.example.com",
  signingKeyPem: process.env.PUBLISHER_ES256_PRIVATE_KEY!,
  rotationSecret: process.env.ROTATION_SECRET!,
});

// Generate a share link token
const token = await publisher.createShareLinkToken({
  resourceId: "article-123",
  contentNames: ["bodytext"],
  expiresIn: 7 * 24 * 3600,             // 7 days (default)
  maxUses: 50,                           // Optional
  jti: "share-" + crypto.randomUUID(),   // Optional: for tracking
  data: { sharedBy: "user-42" },         // Optional: metadata
});

// Create shareable URL
const shareUrl = \`https://news.example.com/article/123?share=\${token}\`;`}</CodeBlock>

        <h3>Issuer-Side Validation</h3>
        <p>
          The issuer validates the share token using the publisher&apos;s signing
          key (already in <code>trustedPublisherKeys</code>). No new secrets
          or key material are needed:
        </p>
        <CodeBlock>{`import { createDcaIssuer } from '@sesamy/capsule-server';

const issuer = createDcaIssuer({
  issuerName: "sesamy",
  privateKeyPem: process.env.ISSUER_ECDH_P256_PRIVATE_KEY!,
  keyId: "2025-10",
  trustedPublisherKeys: {
    "news.example.com": process.env.PUBLISHER_ES256_PUBLIC_KEY!,
  },
});

// In unlock endpoint:
export async function POST(request: Request) {
  const body = await request.json();

  if (body.shareToken) {
    // Share link flow: token IS the access decision
    const result = await issuer.unlockWithShareToken(body, {
      deliveryMode: "direct",            // or "wrapKey" for caching
      onShareToken: async (payload, resource) => {
        // Optional: use-count tracking, audit logging
        console.log(\`Share token used: \${payload.jti}\`);
        // Throw to reject: throw new Error("Usage limit exceeded");
      },
    });
    return Response.json(result);
  }

  // Normal subscription flow...
}`}</CodeBlock>

        <p>The issuer performs these validation steps:</p>
        <ol>
          <li>Verifies <code>resourceJWT</code> and extracts <code>renderId</code> (same as normal unlock)</li>
          <li>Verifies share token signature with the publisher&apos;s ES256 key</li>
          <li>Validates type discriminator (<code>&quot;dca-share&quot;</code>)</li>
          <li>Validates domain binding (token domain must match resource domain)</li>
          <li>Validates resourceId binding (token must be for this resource)</li>
          <li>Checks expiry (reject expired tokens)</li>
          <li>Invokes optional <code>onShareToken</code> callback (use-count, audit)</li>
          <li>Grants access to content names listed in token ∩ available wrapped data</li>
          <li>Unwraps keys from normal DCA wrapped blobs and returns them</li>
        </ol>

        <h3>Unlock Request with Share Token</h3>
        <CodeBlock>{`// Client → Issuer
POST /api/unlock
{
  "resourceJWT": "eyJ…",
  "keys": [
    { "contentName": "bodytext", "contentKey": "…", "wrapKeys": [{ "kid": "…", "key": "…" }] }
  ],
  "shareToken": "eyJ…",                  // ← Share link token
  "clientPublicKey": "base64url-SPKI…"   // Optional: client-bound transport
}

// Issuer → Client (same response format as normal unlock)
{
  "keys": [
    { "contentName": "bodytext", "contentKey": "base64url-key-or-wrapped-key" }
  ],
  "transport": "client-bound"
}`}</CodeBlock>

        <h3>Client-Side Share Link Handling</h3>
        <CodeBlock>{`import { DcaClient } from '@sesamy/capsule';

const client = new DcaClient();
const page = client.parsePage();

// Check for share token in URL
const shareToken = DcaClient.getShareTokenFromUrl(); // reads ?share= param

if (shareToken) {
  // Unlock with share token (auto-includes token in unlock request)
  const keys = await client.unlockWithShareToken(page, "sesamy", shareToken);
  const html = await client.decrypt(page, "bodytext", keys);
  document.querySelector('[data-dca-content-name="bodytext"]')!.innerHTML = html;

  // Clean up URL (cosmetic)
  const url = new URL(window.location.href);
  url.searchParams.delete("share");
  history.replaceState({}, "", url);
}`}</CodeBlock>

        <h3>Use-Count Tracking</h3>
        <p>
          The <code>maxUses</code> field is advisory — enforcement is the
          issuer&apos;s responsibility. Use the <code>onShareToken</code> callback
          to implement tracking:
        </p>
        <CodeBlock>{`// Example: Redis-based use-count tracking
const result = await issuer.unlockWithShareToken(body, {
  onShareToken: async (payload) => {
    if (!payload.jti) return; // No tracking without token ID

    const key = \`share-uses:\${payload.jti}\`;
    const count = await redis.incr(key);

    // Set TTL on first use
    if (count === 1) {
      await redis.expire(key, payload.exp - Math.floor(Date.now() / 1000));
    }

    if (payload.maxUses && count > payload.maxUses) {
      throw new Error("Share link usage limit exceeded");
    }
  },
});`}</CodeBlock>

        <h3>Standalone Token Verification</h3>
        <p>
          The issuer can verify a share token without performing a full unlock,
          useful for pre-flight checks:
        </p>
        <CodeBlock>{`const payload = await issuer.verifyShareToken(shareToken, "news.example.com");
// payload: { type, domain, resourceId, contentNames, iat, exp, jti?, maxUses?, data? }`}</CodeBlock>

        <h3>Security Considerations for Share Links</h3>
        <ul>
          <li>
            ✅ Tokens are ES256-signed using the publisher&apos;s existing signing key
          </li>
          <li>✅ Issuer validates signature via the trusted-publisher allowlist (no new secrets)</li>
          <li>✅ <code>rotationSecret</code> never leaves the publisher — DCA boundary intact</li>
          <li>✅ Expiration limits exposure window</li>
          <li>✅ Usage limits via <code>maxUses</code> + <code>onShareToken</code> callback</li>
          <li>✅ Resource and domain binding prevent token reuse across content</li>
          <li>✅ Content-name scoping limits what each token can unlock</li>
          <li>✅ Full audit trail via <code>jti</code>, <code>data</code>, and callback</li>
          <li>✅ Key material uses the same DCA wrap/unwrap channel (no new attack surface)</li>
          <li>
            ⚠️ Tokens are bearer credentials — anyone with the URL has access
          </li>
          <li>
            ⚠️ Publisher signing key must be protected (same requirement as normal DCA)
          </li>
        </ul>

        <h2>Security Considerations</h2>

        <h3>Rotation Secret Protection</h3>
        <p>
          The rotation secret is the root of all security. If compromised,
          attackers can derive all future wrapKeys. Only the publisher
          should hold the rotation secret.
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
                Rotation Secret
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
                WrapKey Derivation Algorithm
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
                WrapKeys
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
          With rotating wrapKeys, access is automatically revoked within the
          rotation interval (default: 1 hour):
        </p>
        <ul>
          <li>User's browser caches unwrapped content key until the rotation version expires</li>
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
          <li>❌ Rotation secret and derived wrapKeys</li>
          <li>✅ Cannot unwrap keys without issuer private key</li>
          <li>✅ Cannot decrypt for other users (no user private keys)</li>
        </ul>

        <h3>Issuer Compromise Scenarios</h3>
        <p>
          <strong>If the issuer is compromised, attacker gets:</strong>
        </p>
        <ul>
          <li>❌ ECDH private key → can unwrap content keys and wrapKeys</li>
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
          The rotation secret and signing keys should be stored in a secure key
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
            ✅ <strong>Forward Secrecy:</strong> Rotation versions limit exposure
            window
          </li>
          <li>
            ✅ <strong>Secure Key Transport:</strong> ECDH P-256 wrapping + optional RSA-OAEP client-bound wrapping
          </li>
          <li>
            ✅ <strong>Content Key Binding:</strong> Two layers of AAD prevent
            substitution — content AAD (<code>domain|resourceId|contentName|scope</code>)
            binds ciphertext to resource context, wrap AAD (<code>scope</code>)
            binds wrapped key material to the access tier
          </li>
          <li>
            ✅ <strong>Cross-Tier Protection:</strong> Wrap AAD prevents
            key substitution between access tiers — wrapped blobs cannot be
            unwrapped under a different tier&apos;s context
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
          <li>✅ ECDH P-256 for key wrapping (with scope as wrap AAD)</li>
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
