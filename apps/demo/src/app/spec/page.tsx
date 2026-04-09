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
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>Encrypts content at render time. Seals per-content keys for each issuer with ECDH P-256, using <code>renderId</code> as seal AAD. Signs a <code>resourceJWT</code> (ES256) binding metadata.</td>
            </tr>
            <tr>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}><strong>Issuer</strong></td>
              <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>Owns an ECDH P-256 key pair. On unlock, verifies <code>resourceJWT</code>, extracts <code>renderId</code>, unseals keys using <code>renderId</code> as seal AAD, and returns them to the client.</td>
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
// 3. HKDF-SHA256(secret, salt="dca-seal", info="dca-seal-aes256gcm") → 256-bit wrapping key
// 4. AES-256-GCM wrap each key with a unique 12-byte nonce
//    AAD = renderId (binds sealed blob to this specific render)
// 5. Sealed blob = ephemeralPublicKey(65B) ‖ nonce(12B) ‖ ciphertext+tag`}</CodeBlock>

        <h3>Seal AAD (Additional Authenticated Data)</h3>
        <p>
          When sealing contentKeys and periodKeys for issuers, the publisher
          passes the <code>renderId</code> as AAD to the AES-GCM encryption
          (for ECDH P-256 sealing) or as the RSA-OAEP label (for RSA-based
          sealing). This cryptographically binds each sealed key blob to the
          specific render that produced it.
        </p>
        <p>
          On unlock, the issuer extracts <code>renderId</code> from the
          verified <code>resourceJWT</code> and provides it as AAD when
          unsealing. If the <code>renderId</code> does not match, AES-GCM
          decryption fails with an authentication error.
        </p>
        <p>
          <strong>Why this matters:</strong> Seal AAD prevents{" "}
          <em>cross-resource key substitution attacks</em>. Without it, an
          attacker could swap sealed contentKeys from resource B into a request
          authorized for resource A. The issuer would unseal the wrong keys
          without detecting the substitution. With seal AAD, the sealed blobs
          from resource B are bound to resource B&apos;s <code>renderId</code> and
          cannot be unsealed under resource A&apos;s <code>renderId</code>.
        </p>
        <CodeBlock>{`// Seal AAD binding
// Publisher (during render):
//   sealedBlob = AES-256-GCM-Encrypt(wrappingKey, contentKey, nonce, aad=renderId)
//
// Issuer (during unlock):
//   1. Verify resourceJWT → extract renderId from payload
//   2. contentKey = AES-256-GCM-Decrypt(wrappingKey, sealedBlob, nonce, aad=renderId)
//   3. If renderId mismatches → GCM auth tag check fails → reject`}</CodeBlock>

        <h3>Integrity Protection</h3>
        <p>
          In v2, integrity of sealed key blobs is guaranteed by{" "}
          <strong>seal AAD</strong> rather than a separate <code>issuerJWT</code>.
          The <code>renderId</code> (from the signed <code>resourceJWT</code>) is
          used as AAD during AES-GCM sealing, so any substitution or tampering of
          sealed blobs causes a GCM authentication failure at unseal time. This
          replaces the v1 approach of signing per-issuer SHA-256 hash proofs in a
          separate JWT.
        </p>
        <CodeBlock>{`// v2 integrity: seal AAD replaces issuerJWT
//
// v1 (deprecated): publisher signed an issuerJWT with SHA-256 hashes of sealed blobs
//   → issuer verified hashes before unsealing
//
// v2 (current): publisher passes renderId as AAD during AES-GCM sealing
//   → issuer provides renderId (from verified resourceJWT) as AAD during unsealing
//   → GCM authentication tag rejects any blob not sealed for this render
//
// Result: same protection against key substitution, fewer JWTs, simpler flow`}</CodeBlock>

        <h3>DCA HTML Embedding</h3>
        <p>
          DCA data and sealed content are embedded using two elements. The{" "}
          <code>&lt;script&gt;</code> tag holds all metadata, the <code>resourceJWT</code>, and sealed keys.
          The <code>&lt;template&gt;</code> tag holds the encrypted content blobs
          (inert — no scripts execute, no images load).
        </p>
        <CodeBlock>{`<!-- DCA metadata + sealed keys -->
<script type="application/json" class="dca-data">
{
  "version": "2",
  "resourceJWT": "eyJ…",
  "contentSealData": {
    "bodytext": { "contentType": "text/html", "nonce": "…", "aad": "…" }
  },
  "sealedContentKeys": {
    "bodytext": [{ "t": "251023T13", "nonce": "…", "key": "…" }]
  },
  "issuerData": {
    "sesamy": {
      "contentEncryptionKeys": [
        {
          "contentName": "bodytext",
          "contentKey": "base64url-sealed-blob",
          "periodKeys": [
            { "bucket": "251023T13", "key": "base64url-sealed-blob" }
          ]
        }
      ],
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
          <li>Extract <code>renderId</code> from the verified <code>resourceJWT</code> payload.</li>
          <li>Unseal keys using the issuer's ECDH private key, providing <code>renderId</code> as AAD (GCM auth tag validates the blob was sealed for this render).</li>
          <li>Return keys to the client — either as plaintext (direct) or RSA-OAEP wrapped (client-bound).</li>
        </ol>

        <CodeBlock>{`// Client → Issuer
POST /api/unlock
{
  "resourceJWT": "eyJ…",
  "contentEncryptionKeys": [
    {
      "contentName": "bodytext",
      "contentKey": "base64url-sealed-blob",
      "periodKeys": [
        { "bucket": "251023T13", "key": "base64url-sealed-blob" }
      ]
    }
  ],
  "clientPublicKey": "base64url-SPKI-RSA-public-key"   // ← enables client-bound mode
}

// Issuer verification:
// 1. Verify resourceJWT → extract renderId, domain, resourceId, keyNames
// 2. Unseal each key blob with ECDH private key + renderId as AAD
//    (mismatched renderId → GCM auth failure → reject)
// 3. Return keys

// Issuer → Client
{
  "contentEncryptionKeys": [
    {
      "contentName": "bodytext",
      "contentKey": "base64url-key-or-wrapped-key",
      "periodKeys": [
        { "bucket": "251023T13", "key": "base64url-key-or-wrapped-key" }
      ]
    }
  ],
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

        <h3>DCA-Compatible Design</h3>
        <p>
          The critical design insight: a share link token is <strong>purely an
            authorization grant</strong>, not a key-delivery mechanism. The
          publisher&apos;s <code>periodSecret</code> never leaves the publisher.
          Key material flows through the normal DCA seal/unseal channel — the
          sealed keys are already embedded in the page&apos;s DCA data, and the
          issuer unseals them as usual.
        </p>
        <p>
          This is DCA-compatible because the issuer never needs the publisher&apos;s{" "}
          <code>periodSecret</code>. The publisher creates a signed JWT that says
          &ldquo;this bearer may access these content items for this resource.&rdquo;
          The issuer validates the token signature (the publisher already has a
          trusted signing key in the allowlist), uses the token&apos;s claims as the
          access decision, and returns unsealed keys from the normal DCA sealed data.
        </p>

        <CodeBlock>{`// Share Link Flow (DCA-compatible)
//
// 1. Publisher signs a share token (ES256 JWT) granting access
// 2. User clicks the share link → loads page with normal DCA-sealed content
// 3. Client includes the share token in the unlock request
// 4. Issuer verifies token (publisher-signed, trusted key) → access decision
// 5. Issuer unseals keys from normal DCA sealed data → returns to client
// 6. Client decrypts content locally
//
// Key insight: periodSecret never leaves the publisher.
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
  periodSecret: process.env.PERIOD_SECRET!,
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
      deliveryMode: "contentKey",        // or "periodKey" for caching
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
          <li>Grants access to content names listed in token ∩ available sealed data</li>
          <li>Unseals keys from normal DCA sealed blobs and returns them</li>
        </ol>

        <h3>Unlock Request with Share Token</h3>
        <CodeBlock>{`// Client → Issuer
POST /api/unlock
{
  "resourceJWT": "eyJ…",
  "contentEncryptionKeys": [
    { "contentName": "bodytext", "contentKey": "…", "periodKeys": [{ "bucket": "…", "key": "…" }] }
  ],
  "shareToken": "eyJ…",                  // ← Share link token
  "clientPublicKey": "base64url-SPKI…"   // Optional: client-bound transport
}

// Issuer → Client (same response format as normal unlock)
{
  "contentEncryptionKeys": [
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
          <li>✅ <code>periodSecret</code> never leaves the publisher — DCA boundary intact</li>
          <li>✅ Expiration limits exposure window</li>
          <li>✅ Usage limits via <code>maxUses</code> + <code>onShareToken</code> callback</li>
          <li>✅ Resource and domain binding prevent token reuse across content</li>
          <li>✅ Content-name scoping limits what each token can unlock</li>
          <li>✅ Full audit trail via <code>jti</code>, <code>data</code>, and callback</li>
          <li>✅ Key material uses the same DCA seal/unseal channel (no new attack surface)</li>
          <li>
            ⚠️ Tokens are bearer credentials — anyone with the URL has access
          </li>
          <li>
            ⚠️ Publisher signing key must be protected (same requirement as normal DCA)
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
            ✅ <strong>Content Key Binding:</strong> Two layers of AAD prevent
            substitution — content AAD (<code>domain|resourceId|contentName|version</code>)
            binds ciphertext to resource context, seal AAD (<code>renderId</code>)
            binds sealed key material to the render
          </li>
          <li>
            ✅ <strong>Cross-Resource Protection:</strong> Seal AAD prevents
            content key substitution between resources — sealed blobs cannot be
            unsealed under a different render&apos;s context
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
          <li>✅ ECDH P-256 for key sealing (with renderId as seal AAD)</li>
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
