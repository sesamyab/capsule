import { Metadata } from "next";

export const metadata: Metadata = {
  title: "Cryptography Glossary - Capsule",
  description:
    "Understanding the cryptographic concepts and key hierarchy used in Capsule.",
};

export default function GlossaryPage() {
  return (
    <main className="content-page">
      <h1>Capsule Cryptography Glossary</h1>
      <p className="glossary-subtitle">
        Understanding the cryptographic concepts and key hierarchy used in
        Capsule.
      </p>

      <nav className="glossary-toc">
        <h2>Contents</h2>
        <ul>
          <li>
            <a href="#key-hierarchy">Key Hierarchy</a>
          </li>
          <li>
            <a href="#encryption-algorithms">Encryption Algorithms</a>
          </li>
          <li>
            <a href="#key-derivation">Key Derivation</a>
          </li>
          <li>
            <a href="#key-wrapping">Key Wrapping &amp; Sealing</a>
          </li>
          <li>
            <a href="#time-periods">Time Periods &amp; Buckets</a>
          </li>
          <li>
            <a href="#dca">DCA (Delegated Content Access)</a>
          </li>
          <li>
            <a href="#jwt-integrity">JWT Signing &amp; Integrity Proofs</a>
          </li>
        </ul>
      </nav>

      <section id="key-hierarchy">
        <h2>🔑 Key Hierarchy</h2>

        <div className="concept-card">
          <h3>Period Secret</h3>
          <p>
            The root secret from which all period keys are derived. Stored
            securely on the publisher&apos;s server (ideally in a KMS like AWS
            Secrets Manager, HashiCorp Vault, etc.). Called{" "}
            <code>periodSecret</code> in the codebase.
          </p>
          <div className="properties">
            <span className="property">Size: 256 bits</span>
            <span className="property">Storage: Server-side only</span>
            <span className="property">
              Rotation: Rarely (causes key migration)
            </span>
          </div>
          <p className="security-note">
            ⚠️ Never expose the period secret to clients or embed it in client
            code.
          </p>
        </div>

        <div className="concept-card">
          <h3>Period Key</h3>
          <p>
            A time-derived AES-256 key that wraps (encrypts) the content key.
            Derived from the period secret using HKDF with a time-based label
            as context. Clients can cache period keys to enable offline access
            and &ldquo;unlock once, access all&rdquo; within a time window.
          </p>
          <div className="properties">
            <span className="property">Algorithm: AES-256</span>
            <span className="property">Purpose: Wrap content keys</span>
            <span className="property">Scope: Per-content-name, per-time-bucket</span>
            <span className="property">
              Client caching: Yes (enables offline access)
            </span>
          </div>
          <p>
            In the DCA model, period keys are content-specific by construction
            &mdash; the content name is used as the HKDF salt, so{" "}
            <code>&quot;bodytext&quot;</code> and <code>&quot;sidebar&quot;</code>{" "}
            produce different period keys even for the same time bucket.
          </p>
          <pre className="code-example">
            {`// Period key derivation (DCA)
periodKey = HKDF(
  IKM:  periodSecret,
  salt: "bodytext",          // content name
  info: "dca|251023T13",     // "dca|" + time bucket
  len:  32                   // AES-256
)`}
          </pre>
        </div>

        <div className="concept-card">
          <h3>Content Key</h3>
          <p>
            The key that actually encrypts article content. Each article (or
            content item) gets its own unique content key, generated randomly at
            encryption time. In envelope encryption terminology this is the Data
            Encryption Key (DEK).
          </p>
          <div className="properties">
            <span className="property">Algorithm: AES-256-GCM</span>
            <span className="property">Purpose: Encrypt content</span>
            <span className="property">Scope: Per-article / per-content-item</span>
            <span className="property">
              Generation: Random (crypto.getRandomValues)
            </span>
          </div>
          <p>
            The content key is wrapped with one or more period keys and stored
            alongside the encrypted content. Clients unwrap the content key
            using a period key they received from the issuer.
          </p>
          <pre className="code-example">
            {`// Content key usage
contentKey = randomBytes(32)
ciphertext = AES-GCM(contentKey, plaintext, iv, aad)
wrappedKey = AES-GCM(periodKey, contentKey, wrapIv)`}
          </pre>
        </div>

        <div className="concept-card">
          <h3>Issuer Key Pair</h3>
          <p>
            Each issuer (subscription provider) holds an asymmetric key pair
            used for <strong>sealing</strong>. The publisher encrypts
            content keys and period keys with the issuer&apos;s public key so only
            that issuer can unseal them.
          </p>
          <div className="properties">
            <span className="property">Algorithm: ECDH P-256 or RSA-OAEP</span>
            <span className="property">Storage: Issuer server</span>
            <span className="property">Purpose: Key sealing / unsealing</span>
          </div>
          <p>
            ECDH P-256 is the preferred algorithm for DCA. Each seal operation
            generates a fresh ephemeral key pair, producing a self-contained
            blob that only the issuer&apos;s private key can decrypt.
          </p>
        </div>

        <div className="concept-card">
          <h3>Publisher Signing Key</h3>
          <p>
            An ECDSA P-256 key pair used by the publisher to sign JWTs
            (ES256). The publisher signs a <code>resourceJWT</code> and
            per-issuer <code>issuerJWT</code>s. Issuers verify these signatures
            using the publisher&apos;s public key (looked up by domain).
          </p>
          <div className="properties">
            <span className="property">Algorithm: ECDSA P-256 (ES256)</span>
            <span className="property">Storage: Publisher server (private key)</span>
            <span className="property">Purpose: JWT signing &amp; verification</span>
          </div>
        </div>


      </section>

      <section id="encryption-algorithms">
        <h2>🔐 Encryption Algorithms</h2>

        <div className="concept-card">
          <h3>AES-256-GCM</h3>
          <p>
            Symmetric authenticated encryption (AEAD). AES-256-GCM is used for
            both content encryption and key wrapping in Capsule. It provides
            confidentiality <em>and</em> authenticity in a single operation.
          </p>
          <div className="properties">
            <span className="property">Key size: 256 bits</span>
            <span className="property">IV size: 96 bits (12 bytes)</span>
            <span className="property">Auth tag: 128 bits</span>
            <span className="property">AAD: Optional (used in DCA)</span>
          </div>
          <p>
            In the DCA model, content encryption includes{" "}
            <strong>Additional Authenticated Data (AAD)</strong> that binds the
            ciphertext to its context &mdash; preventing content from being
            relocated to a different page or domain.
          </p>
        </div>

        <div className="concept-card">
          <h3>AAD (Additional Authenticated Data)</h3>
          <p>
            An AES-GCM feature that authenticates extra context alongside the
            ciphertext. The AAD is not encrypted, but decryption will fail if
            the AAD provided at decrypt time doesn&apos;t match what was used at
            encrypt time.
          </p>
          <div className="properties">
            <span className="property">
              Format: <code>domain|resourceId|contentName|version</code>
            </span>
            <span className="property">Encoding: UTF-8 bytes</span>
            <span className="property">Storage: In contentSealData.aad</span>
          </div>
          <pre className="code-example">
            {`// AAD example
aad = "www.news-site.com|article-123|bodytext|1"

// Encrypt with AAD
ciphertext = AES-GCM(contentKey, plaintext, iv, aad)

// Decrypt — must provide the same AAD
plaintext = AES-GCM-Decrypt(contentKey, ciphertext, iv, aad)
// Fails if AAD doesn't match → prevents content relocation`}
          </pre>
        </div>

        <div className="concept-card">
          <h3>ECDH P-256 (Elliptic Curve Diffie-Hellman)</h3>
          <p>
            Asymmetric key agreement used for <strong>sealing</strong> key
            material for issuers. For each seal operation a fresh ephemeral
            key pair is generated, and the shared secret is used directly as an
            AES-256-GCM key.
          </p>
          <div className="properties">
            <span className="property">Curve: P-256 (secp256r1)</span>
            <span className="property">Shared secret: 32 bytes (x-coordinate)</span>
            <span className="property">Ephemeral: Fresh key per seal</span>
          </div>
          <pre className="code-example">
            {`// ECDH P-256 sealed blob format
| 0-64  | Ephemeral public key (65 bytes, uncompressed) |
| 65-76 | AES-GCM IV (12 bytes)                         |
| 77+   | Ciphertext + 16-byte GCM auth tag             |`}
          </pre>
        </div>

        <div className="concept-card">
          <h3>RSA-OAEP</h3>
          <p>
            Asymmetric encryption using RSA with Optimal Asymmetric Encryption
            Padding. Used as an alternative sealing algorithm for DCA issuers.
          </p>
          <div className="properties">
            <span className="property">Key size: 2048+ bits</span>
            <span className="property">Padding: OAEP</span>
            <span className="property">Hash: SHA-256</span>
            <span className="property">Max payload: ~190 bytes (2048-bit key)</span>
          </div>
        </div>

        <div className="concept-card">
          <h3>ECDSA P-256 (ES256)</h3>
          <p>
            Elliptic curve digital signature algorithm used for signing DCA
            JWTs. The publisher signs <code>resourceJWT</code> and{" "}
            <code>issuerJWT</code> tokens with ES256; issuers verify them
            before unsealing keys.
          </p>
          <div className="properties">
            <span className="property">Curve: P-256</span>
            <span className="property">Hash: SHA-256</span>
            <span className="property">
              Signature: 64 bytes (IEEE P1363 format, r||s)
            </span>
            <span className="property">JWT header: {`{"alg":"ES256","typ":"JWT"}`}</span>
          </div>
        </div>
      </section>

      <section id="key-derivation">
        <h2>🧮 Key Derivation</h2>

        <div className="concept-card">
          <h3>HKDF (HMAC-based Key Derivation Function)</h3>
          <p>
            RFC 5869 standard for deriving cryptographic keys from a master
            secret. Capsule uses HKDF-SHA256 to derive period keys from the
            period secret.
          </p>
          <div className="properties">
            <span className="property">Hash: SHA-256</span>
            <span className="property">Input: Period secret + context</span>
            <span className="property">Output: 256-bit keys</span>
          </div>
          <pre className="code-example">
            {`// DCA period key derivation
periodKey = HKDF-SHA256(
  IKM:  periodSecret,
  salt: contentName,        // e.g., "bodytext"
  info: "dca|251023T13",    // "dca|" + time bucket label
  len:  32
)`}
          </pre>
          <p>
            In the DCA model, the <code>salt</code> is the content name,
            making period keys content-specific by construction. The{" "}
            <code>info</code> parameter encodes the time bucket, ensuring each
            time window gets a unique key.
          </p>
        </div>

        <div className="concept-card">
          <h3>Time-Based Key Rotation</h3>
          <p>
            Capsule rotates keys automatically using time periods. Each period
            has its own derived key, providing forward secrecy &mdash; old
            period keys can&apos;t decrypt future content.
          </p>
          <div className="properties">
            <span className="property">
              Hourly buckets (YYMMDDTHH format)
            </span>
            <span className="property">
              Window: Current + next bucket always available
            </span>
          </div>
          <pre className="code-example">
            {`// Time bucket format
"251023T13"     // Oct 23, 2025 at 13:00 UTC (hourly)
"251023T1430"   // Sub-hour variant (30-min)`}
          </pre>
        </div>
      </section>

      <section id="key-wrapping">
        <h2>📦 Key Wrapping &amp; Sealing</h2>

        <div className="concept-card">
          <h3>Content Key Wrapping</h3>
          <p>
            The content key is wrapped (encrypted) with a period key using
            AES-256-GCM. Each article stores multiple wrapped copies of its
            content key &mdash; one per active time bucket &mdash; so clients
            can unwrap using whichever period key they have cached.
          </p>
          <div className="properties">
            <span className="property">Algorithm: AES-256-GCM</span>
            <span className="property">
              Nonce: Unique 12-byte IV per wrap
            </span>
            <span className="property">
              Wrapped copies: 2 (current + next period)
            </span>
          </div>
          <pre className="code-example">
            {`// DCA sealedContentKeys structure
sealedContentKeys: {
  "bodytext": [
    { t: "251023T13", nonce: "...", key: "..." },
    { t: "251023T14", nonce: "...", key: "..." }
  ]
}`}
          </pre>
        </div>

        <div className="concept-card">
          <h3>Issuer Sealing</h3>
          <p>
            Key material (content keys and period keys) is <strong>sealed</strong>{" "}
            with the issuer&apos;s public key. Only the issuer holding the
            matching private key can unseal them. Each issuer gets its own
            sealed copies, enabling multi-issuer support.
          </p>
          <div className="properties">
            <span className="property">ECDH P-256: Ephemeral key per seal</span>
            <span className="property">RSA-OAEP: Standard ciphertext</span>
            <span className="property">Auto-detection: From PEM key type</span>
          </div>
          <pre className="code-example">
            {`// Issuer sealed structure
issuerData: {
  "sesamy": {
    sealed: {
      "bodytext": {
        contentKey: "base64url...",   // sealed with issuer pubkey
        periodKeys: {
          "251023T13": "base64url...",
          "251023T14": "base64url..."
        }
      }
    },
    unlockUrl: "https://api.sesamy.com/unlock",
    keyId: "2025-10"
  }
}`}
          </pre>
        </div>

        <div className="concept-card">
          <h3>Envelope Encryption</h3>
          <p>
            The pattern of encrypting data with a content key, then wrapping
            the content key with a period key. This enables &ldquo;unlock once,
            access all&rdquo; &mdash; a single period key can unwrap the
            content key for any article encrypted in that time window.
          </p>
          <ul>
            <li>Content encrypted with random content key (fast, symmetric)</li>
            <li>Content key wrapped with period key (enables time-based access)</li>
            <li>Period key sealed with issuer&apos;s public key (delegated access)</li>
          </ul>
        </div>
      </section>

      <section id="time-periods">
        <h2>⏱️ Time Periods &amp; Buckets</h2>

        <div className="concept-card">
          <h3>Why Time Periods?</h3>
          <p>Time periods provide several security benefits:</p>
          <ul>
            <li>
              <strong>Forward Secrecy:</strong> Old period keys can&apos;t decrypt
              new content. If a key is compromised, only that period&apos;s content
              is at risk.
            </li>
            <li>
              <strong>Automatic Revocation:</strong> Keys expire naturally. No
              need to maintain revocation lists.
            </li>
            <li>
              <strong>Subscription Enforcement:</strong> Users must have an
              active subscription to get current period keys.
            </li>
          </ul>
        </div>

        <div className="concept-card">
          <h3>Period Duration Selection</h3>
          <table className="info-table">
            <thead>
              <tr>
                <th>Period</th>
                <th>Use Case</th>
                <th>Trade-offs</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>30 seconds</td>
                <td>Demo/testing</td>
                <td>Frequent rotation visible, more server requests</td>
              </tr>
              <tr>
                <td>1 hour</td>
                <td>News sites (DCA default)</td>
                <td>Balance of security and UX</td>
              </tr>
              <tr>
                <td>24 hours</td>
                <td>Magazines</td>
                <td>Daily access pattern, minimal overhead</td>
              </tr>
              <tr>
                <td>30 days</td>
                <td>Monthly subscriptions</td>
                <td>Aligns with billing cycle</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="concept-card">
          <h3>Clock Drift Handling</h3>
          <p>
            To handle clock differences between publisher and client, Capsule
            always encrypts content keys with both the current <em>and</em> next
            period key. This ensures content remains accessible during the
            transition between time buckets.
          </p>
          <ul>
            <li>Publisher wraps content key with current + next period keys</li>
            <li>Client tries each wrapped key until one succeeds</li>
            <li>Period key cache uses the time bucket label as key</li>
          </ul>
        </div>
      </section>

      <section id="dca">
        <h2>🔄 DCA (Delegated Content Access)</h2>

        <div className="concept-card">
          <h3>What is DCA?</h3>
          <p>
            DCA is an open standard for encrypted content delivery with
            multi-issuer support. It separates the roles of{" "}
            <strong>publisher</strong> (encrypts content),{" "}
            <strong>issuer</strong> (manages access), and{" "}
            <strong>client</strong> (decrypts content).
          </p>
          <ul>
            <li>
              <strong>Publisher:</strong> Encrypts content at build time,
              seals keys for each issuer, signs JWTs
            </li>
            <li>
              <strong>Issuer:</strong> Verifies JWTs, checks integrity proofs,
              makes access decisions, unseals and returns keys
            </li>
            <li>
              <strong>Client:</strong> Parses DCA data from the page, calls an
              issuer&apos;s unlock endpoint, decrypts content
            </li>
          </ul>
        </div>

        <div className="concept-card">
          <h3>Multiple Content Items</h3>
          <p>
            A single page can contain multiple named content items (e.g.,{" "}
            <code>&quot;bodytext&quot;</code>, <code>&quot;sidebar&quot;</code>,{" "}
            <code>&quot;data&quot;</code>). Each item gets its own content key,
            IV, AAD, and sealed copies. Issuers can grant access to a subset of
            items per request.
          </p>
          <pre className="code-example">
            {`// Multiple content items
contentItems: [
  { contentName: "bodytext", content: "<p>Article...</p>" },
  { contentName: "sidebar", content: "<aside>Premium ...</aside>" },
  { contentName: "data",    content: '{"stats": [...]}',
    contentType: "application/json" }
]`}
          </pre>
        </div>

        <div className="concept-card">
          <h3>Key Delivery Modes</h3>
          <p>
            When a client requests access, the issuer can return keys in two
            modes:
          </p>
          <ul>
            <li>
              <strong>contentKey mode:</strong> Returns the raw content key
              directly. Simplest path &mdash; client decrypts immediately.
            </li>
            <li>
              <strong>periodKey mode:</strong> Returns period keys that the
              client uses to unwrap the content key from{" "}
              <code>sealedContentKeys</code>. Enables client-side caching:
              a cached period key can unlock any article in that time window.
            </li>
          </ul>
        </div>

        <div className="concept-card">
          <h3>Wire Format (HTML)</h3>
          <p>
            DCA data is embedded in the page as standard HTML elements:
          </p>
          <pre className="code-example">
            {`<!-- DCA metadata and keys -->
<script type="application/json" class="dca-data">
  { "version": "1", "resource": {...}, "resourceJWT": "...", ... }
</script>

<!-- Encrypted content -->
<template class="dca-sealed-content">
  <div data-dca-content-name="bodytext">base64url_ciphertext...</div>
  <div data-dca-content-name="sidebar">base64url_ciphertext...</div>
</template>`}
          </pre>
        </div>
      </section>

      <section id="jwt-integrity">
        <h2>🛡️ JWT Signing &amp; Integrity Proofs</h2>

        <div className="concept-card">
          <h3>resourceJWT</h3>
          <p>
            An ES256 JWT signed by the publisher containing resource metadata.
            Shared across all issuers. The issuer verifies this JWT to confirm
            the request originates from a trusted publisher.
          </p>
          <pre className="code-example">
            {`// resourceJWT payload
{
  "renderId": "base64url...",        // binds request
  "domain": "www.news-site.com",     // publisher domain
  "issuedAt": "2025-10-23T13:00:00Z",
  "resourceId": "article-123",
  "data": { "section": "politics" }  // access metadata
}`}
          </pre>
        </div>

        <div className="concept-card">
          <h3>issuerJWT</h3>
          <p>
            A per-issuer ES256 JWT containing SHA-256 integrity proofs of
            every sealed blob for that issuer. The issuer verifies these hashes
            before unsealing, ensuring the sealed keys haven&apos;t been tampered
            with in transit.
          </p>
          <pre className="code-example">
            {`// issuerJWT payload
{
  "renderId": "base64url...",          // must match resourceJWT
  "issuerName": "sesamy",
  "proof": {
    "bodytext": {
      "contentKey": "sha256_hash...",  // hash of sealed blob
      "periodKeys": {
        "251023T13": "sha256_hash...",
        "251023T14": "sha256_hash..."
      }
    }
  }
}`}
          </pre>
        </div>

        <div className="concept-card">
          <h3>SHA-256 Integrity Proofs</h3>
          <p>
            Each sealed blob&apos;s base64url string is hashed with SHA-256 and
            included in the issuerJWT. Before unsealing, the issuer recomputes
            the hashes and compares them &mdash; any mismatch indicates
            tampering and the request is rejected.
          </p>
          <pre className="code-example">
            {`// Proof hash computation
proofHash = base64url(SHA-256(utf8_bytes_of_base64url_string))

// Note: hashes the base64url STRING as UTF-8 bytes,
// not the decoded binary data`}
          </pre>
        </div>

        <div className="concept-card">
          <h3>renderId (Binding Token)</h3>
          <p>
            A random base64url string (16 bytes) generated fresh each render.
            Present in both the <code>resourceJWT</code> and{" "}
            <code>issuerJWT</code> payloads, the issuer verifies they match
            &mdash; binding the two JWTs together and preventing replay of
            mismatched tokens.
          </p>
        </div>
      </section>
    </main>
  );
}
