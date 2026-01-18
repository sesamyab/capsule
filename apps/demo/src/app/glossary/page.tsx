import { Metadata } from "next";

export const metadata: Metadata = {
  title: "Cryptography Glossary - Capsule",
  description: "Understanding the cryptographic concepts and key hierarchy used in Capsule.",
};

export default function GlossaryPage() {
  return (
    <main className="content-page">
        <h1>Capsule Cryptography Glossary</h1>
        <p className="glossary-subtitle">
          Understanding the cryptographic concepts and key hierarchy used in Capsule.
        </p>

        <nav className="glossary-toc">
          <h2>Contents</h2>
          <ul>
            <li><a href="#key-hierarchy">Key Hierarchy</a></li>
            <li><a href="#encryption-algorithms">Encryption Algorithms</a></li>
            <li><a href="#key-derivation">Key Derivation</a></li>
            <li><a href="#key-wrapping">Key Wrapping</a></li>
            <li><a href="#time-buckets">Time Buckets</a></li>
          </ul>
        </nav>

        <section id="key-hierarchy">
          <h2>🔑 Key Hierarchy</h2>
          
          <div className="concept-card">
            <h3>Master Secret</h3>
            <p>
              The root secret from which all other keys are derived. Stored securely on the 
              subscription server (ideally in a KMS like AWS Secrets Manager, HashiCorp Vault, etc.).
            </p>
            <div className="properties">
              <span className="property">Size: 256 bits</span>
              <span className="property">Storage: Server-side only</span>
              <span className="property">Rotation: Rarely (causes key migration)</span>
            </div>
            <p className="security-note">
              ⚠️ Never expose the master secret to clients or embed in client code.
            </p>
          </div>

          <div className="concept-card">
            <h3>KEK (Key-Encrypting Key)</h3>
            <p>
              Also called the <strong>Key-Wrapping Key</strong>. Derived from the master secret 
              using HKDF with the tier name and bucket ID as context. Used to wrap/unwrap DEKs.
            </p>
            <div className="properties">
              <span className="property">Algorithm: AES-256</span>
              <span className="property">Purpose: Wrap DEKs</span>
              <span className="property">Scope: Per-tier, per-bucket</span>
              <span className="property">Client caching: Yes (enables offline access)</span>
            </div>
            <p>
              When a user unlocks "premium" tier content, they receive the KEK. This single key 
              can unwrap the DEK for <em>any</em> premium article in that time bucket.
            </p>
            <pre className="code-example">
{`// KEK derivation (server-side)
KEK = HKDF(
  secret: masterSecret,
  salt: "capsule-kek",
  info: "premium:1737190200"  // tier:bucketId
)`}
            </pre>
          </div>

          <div className="concept-card">
            <h3>DEK (Data Encryption Key)</h3>
            <p>
              The key that actually encrypts the article content. Each article has its own 
              unique DEK, generated randomly at encryption time.
            </p>
            <div className="properties">
              <span className="property">Algorithm: AES-256-GCM</span>
              <span className="property">Purpose: Encrypt content</span>
              <span className="property">Scope: Per-article</span>
              <span className="property">Generation: Random (crypto.getRandomValues)</span>
            </div>
            <p>
              The DEK is wrapped with one or more KEKs (tier keys) and stored alongside 
              the encrypted content. Clients unwrap the DEK using their cached KEK.
            </p>
            <pre className="code-example">
{`// DEK usage
wrappedDek = AES-KW(KEK, DEK)        // Wrap DEK with KEK
ciphertext = AES-GCM(DEK, plaintext)  // Encrypt content with DEK`}
            </pre>
          </div>

          <div className="concept-card">
            <h3>RSA Key Pair (Client)</h3>
            <p>
              Each client generates an RSA-2048 key pair stored in IndexedDB. The public key 
              is sent to the server during unlock; the private key never leaves the browser.
            </p>
            <div className="properties">
              <span className="property">Algorithm: RSA-OAEP (SHA-256)</span>
              <span className="property">Key size: 2048 bits</span>
              <span className="property">Storage: IndexedDB (browser)</span>
              <span className="property">Purpose: Secure key transport</span>
            </div>
            <p>
              The server wraps the KEK (or DEK for article keys) with the client's public key. 
              Only that specific client can unwrap it with their private key.
            </p>
          </div>
        </section>

        <section id="encryption-algorithms">
          <h2>🔐 Encryption Algorithms</h2>

          <div className="concept-card">
            <h3>AES (Advanced Encryption Standard)</h3>
            <p>
              Symmetric block cipher adopted by NIST. Capsule uses AES-256 (256-bit keys) 
              in two modes:
            </p>
            <ul>
              <li>
                <strong>AES-GCM</strong> (Galois/Counter Mode): For content encryption. 
                Provides both confidentiality and authenticity (AEAD).
              </li>
              <li>
                <strong>AES-KW</strong> (Key Wrap): For wrapping DEKs. RFC 3394 standard 
                for secure key transport.
              </li>
            </ul>
            <div className="properties">
              <span className="property">Block size: 128 bits</span>
              <span className="property">Key size: 256 bits</span>
              <span className="property">IV size: 96 bits (GCM)</span>
              <span className="property">Auth tag: 128 bits (GCM)</span>
            </div>
          </div>

          <div className="concept-card">
            <h3>RSA-OAEP</h3>
            <p>
              Asymmetric encryption using RSA with Optimal Asymmetric Encryption Padding. 
              Used for secure key transport from server to client.
            </p>
            <div className="properties">
              <span className="property">Key size: 2048 bits</span>
              <span className="property">Padding: OAEP</span>
              <span className="property">Hash: SHA-256</span>
              <span className="property">Max payload: ~190 bytes</span>
            </div>
            <p>
              The server encrypts the KEK with the client's public key. Only the client's 
              private key can decrypt it, ensuring secure key exchange over untrusted channels.
            </p>
          </div>
        </section>

        <section id="key-derivation">
          <h2>🧮 Key Derivation</h2>

          <div className="concept-card">
            <h3>HKDF (HMAC-based Key Derivation Function)</h3>
            <p>
              RFC 5869 standard for deriving cryptographic keys from a master secret. 
              Capsule uses HKDF-SHA256 to derive KEKs.
            </p>
            <div className="properties">
              <span className="property">Hash: SHA-256</span>
              <span className="property">Input: Master secret + context</span>
              <span className="property">Output: 256-bit keys</span>
            </div>
            <pre className="code-example">
{`// HKDF structure
Extract: PRK = HMAC-SHA256(salt, masterSecret)
Expand:  KEK = HMAC-SHA256(PRK, info || 0x01)`}
            </pre>
            <p>
              The <code>info</code> parameter includes the tier name and bucket ID, ensuring 
              each tier/time combination gets a unique key.
            </p>
          </div>

          <div className="concept-card">
            <h3>TOTP-like Key Rotation</h3>
            <p>
              Inspired by TOTP (Time-based One-Time Password, RFC 6238), Capsule uses 
              time buckets to rotate keys automatically.
            </p>
            <div className="properties">
              <span className="property">Bucket period: Configurable (30s demo, longer in production)</span>
              <span className="property">Bucket ID: Unix timestamp / period</span>
              <span className="property">Window: Current + adjacent buckets valid</span>
            </div>
            <p>
              Unlike TOTP which generates short codes, Capsule derives full 256-bit keys 
              for each bucket. This provides forward secrecy - old bucket keys can't 
              decrypt future content.
            </p>
            <pre className="code-example">
{`// Bucket calculation
bucketId = floor(unixTimestamp / bucketPeriodSeconds)

// Example with 30-second buckets
timestamp: 1737190215
bucketId:  57906340
keyId:     "premium:57906340"`}
            </pre>
          </div>
        </section>

        <section id="key-wrapping">
          <h2>📦 Key Wrapping</h2>

          <div className="concept-card">
            <h3>AES-KW (AES Key Wrap)</h3>
            <p>
              RFC 3394 algorithm for securely wrapping cryptographic keys. Provides 
              integrity protection - tampering is detected during unwrap.
            </p>
            <div className="properties">
              <span className="property">Standard: RFC 3394 / NIST SP 800-38F</span>
              <span className="property">Overhead: 8 bytes (IV)</span>
              <span className="property">Integrity: Built-in verification</span>
            </div>
            <pre className="code-example">
{`// Key wrapping flow
Server (CMS):
  DEK = randomBytes(32)           // Generate random DEK
  wrappedDek = AES-KW(KEK, DEK)   // Wrap with tier KEK
  
Client (Browser):
  KEK = RSA-Decrypt(encryptedKek) // Unwrap KEK from server
  DEK = AES-KW-Unwrap(KEK, wrappedDek)  // Unwrap DEK locally`}
            </pre>
          </div>

          <div className="concept-card">
            <h3>Envelope Encryption</h3>
            <p>
              The pattern of encrypting data with a DEK, then wrapping the DEK with a KEK. 
              This is how Capsule enables "unlock once, access all" for tier content.
            </p>
            <ul>
              <li>Content encrypted with random DEK (fast, symmetric)</li>
              <li>DEK wrapped with tier KEK (enables access control)</li>
              <li>KEK wrapped with client's RSA key (secure transport)</li>
            </ul>
            <pre className="code-example">
{`Article Payload:
{
  articleId: "crypto-basics",
  encryptedContent: "base64...",  // AES-GCM(DEK, content)
  iv: "base64...",                // 12-byte nonce
  wrappedKeys: [
    { keyId: "premium:57906340", wrappedDek: "base64..." },
    { keyId: "premium:57906341", wrappedDek: "base64..." },
    { keyId: "article:crypto-basics", wrappedDek: "base64..." }
  ]
}`}
            </pre>
          </div>
        </section>

        <section id="time-buckets">
          <h2>⏱️ Time Buckets</h2>

          <div className="concept-card">
            <h3>Why Time Buckets?</h3>
            <p>
              Time buckets provide several security benefits:
            </p>
            <ul>
              <li>
                <strong>Forward Secrecy:</strong> Old bucket keys can't decrypt new content. 
                If a key is compromised, only that bucket's content is at risk.
              </li>
              <li>
                <strong>Automatic Revocation:</strong> Keys expire naturally. No need to 
                maintain revocation lists.
              </li>
              <li>
                <strong>Subscription Enforcement:</strong> Users must have an active 
                subscription to get current bucket keys.
              </li>
            </ul>
          </div>

          <div className="concept-card">
            <h3>Bucket Period Selection</h3>
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
                  <td>News sites</td>
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
              To handle clock differences between server and client, Capsule:
            </p>
            <ul>
              <li>Encrypts with both current AND next bucket keys</li>
              <li>Accepts current, previous, and next bucket IDs as valid</li>
              <li>Returns bucket expiration time so clients can auto-renew</li>
            </ul>
          </div>
        </section>
      </main>
  );
}
