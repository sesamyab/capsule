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
        <div className="flow-steps">
          <div className="flow-step">
            <div className="step-number">1</div>
            <div className="step-content">
              <h4>Pre-encrypt Content</h4>
              <p>Server encrypts articles with AES-256-GCM keys per subscription tier</p>
            </div>
          </div>
          <div className="flow-arrow">→</div>
          <div className="flow-step">
            <div className="step-number">2</div>
            <div className="step-content">
              <h4>Embed in HTML</h4>
              <p>Encrypted content embedded in page, works offline and with caching</p>
            </div>
          </div>
          <div className="flow-arrow">→</div>
          <div className="flow-step">
            <div className="step-number">3</div>
            <div className="step-content">
              <h4>Key Exchange</h4>
              <p>Browser sends public key, receives wrapped decryption key</p>
            </div>
          </div>
          <div className="flow-arrow">→</div>
          <div className="flow-step">
            <div className="step-number">4</div>
            <div className="step-content">
              <h4>Decrypt Locally</h4>
              <p>Client decrypts content using cached keys, even offline</p>
            </div>
          </div>
        </div>
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
