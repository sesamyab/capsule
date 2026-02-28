import Link from "next/link";

export default function Home() {
  return (
    <main className="home-page">
      <section className="hero">
        <h1>Capsule</h1>
        <p className="tagline">
          An open standard for secure, client-side article encryption
        </p>
      </section>

      <section className="features">
        <div className="feature-grid">
          <div className="feature-card">
            <div className="feature-icon">⚡</div>
            <h3>Easy & Fast</h3>
            <p>
              Simple integration with any web stack. Pre-encrypt content at build time,
              decrypt instantly in the browser.
            </p>
          </div>
          
          <div className="feature-card">
            <div className="feature-icon">🔒</div>
            <h3>Secure by Design</h3>
            <p>
              Uses Web Crypto API with envelope encryption. Private keys never leave
              the browser, stored with extractable: false.
            </p>
          </div>
          
          <div className="feature-card">
            <div className="feature-icon">🌐</div>
            <h3>Open Standard</h3>
            <p>
              Language-agnostic specification. Implement in any language—Node.js,
              PHP, Python, or Go.
            </p>
          </div>
          
          <div className="feature-card">
            <div className="feature-icon">🔌</div>
            <h3>No Dependencies</h3>
            <p>
              Works independently of CMS, authentication, or permission systems.
              Pure encryption, nothing else.
            </p>
          </div>
        </div>
      </section>

      <section className="how-it-works">
        <h2>How It Works</h2>
        <p style={{ textAlign: "center", maxWidth: "700px", margin: "0 auto 2rem", opacity: 0.8 }}>
          Capsule implements <strong>Delegated Content Access (DCA)</strong> — a
          delegation protocol that separates content encryption (publisher) from
          access control (issuer). Publishers seal keys with ECDH P-256; issuers
          unseal them only when access is granted.
        </p>
        <div className="flow-steps">
          <div className="flow-step">
            <div className="step-number">1</div>
            <div className="step-content">
              <h4>Publisher Encrypts</h4>
              <p>Content encrypted with AES-256-GCM. Keys sealed per issuer using ECDH P-256, with signed integrity proofs.</p>
            </div>
          </div>
          <div className="flow-arrow">→</div>
          <div className="flow-step">
            <div className="step-number">2</div>
            <div className="step-content">
              <h4>Embed in HTML</h4>
              <p>DCA data and sealed content embedded in inert template elements. Works with caching and CDNs.</p>
            </div>
          </div>
          <div className="flow-arrow">→</div>
          <div className="flow-step">
            <div className="step-number">3</div>
            <div className="step-content">
              <h4>Issuer Unlocks</h4>
              <p>Client sends sealed keys to the issuer. Keys returned via client-bound transport — RSA-OAEP wrapped with the browser&apos;s public key.</p>
            </div>
          </div>
          <div className="flow-arrow">→</div>
          <div className="flow-step">
            <div className="step-number">4</div>
            <div className="step-content">
              <h4>Decrypt Locally</h4>
              <p>Browser unwraps keys with its non-extractable private key stored in IndexedDB, then decrypts content locally.</p>
            </div>
          </div>
        </div>
      </section>

      <section className="dca-highlight" style={{ padding: "2rem 1rem", textAlign: "center" }}>
        <h2>Client-Bound Key Management</h2>
        <p style={{ maxWidth: "700px", margin: "0 auto 1rem" }}>
          Capsule extends DCA with <strong>client-bound transport</strong>: each
          browser generates an RSA-OAEP key pair with the private key marked{" "}
          <code>extractable: false</code>. Unsealed keys are RSA-wrapped before
          leaving the issuer, so no readable key material ever crosses the
          network. Even XSS or DevTools cannot extract the private key bytes.
        </p>
        <p style={{ maxWidth: "700px", margin: "0 auto", opacity: 0.7, fontSize: "0.9rem" }}>
          Read more in the <Link href="/spec#delegated-content-access-dca">DCA specification</Link>.
        </p>
      </section>

      <section className="cta-section">
        <h2>Get Started</h2>
        <div className="cta-buttons">
          <Link href="/demo" className="cta-button primary">
            Try the Demo
          </Link>
          <Link href="/spec" className="cta-button secondary">
            Read the Spec
          </Link>
          <Link href="/client" className="cta-button secondary">
            Client Documentation
          </Link>
        </div>
      </section>
    </main>
  );
}
