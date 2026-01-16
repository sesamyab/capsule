import Link from "next/link";

export default function DemoPage() {
  return (
    <main className="content-page">
      <h1>Interactive Demo</h1>
      <p>
        Try Capsule with these demo articles. Unlock individual articles or get a 
        subscription key to unlock all premium content at once.
      </p>

      <div style={{ 
        background: 'var(--border)', 
        padding: '1.5rem', 
        borderRadius: '12px',
        marginBottom: '2rem'
      }}>
        <h3 style={{ marginTop: 0 }}>📊 Your Keys</h3>
        <p style={{ fontSize: '0.9rem', color: 'var(--muted)', marginBottom: '1rem' }}>
          Keys are stored securely in your browser's IndexedDB.
        </p>
        <div id="key-status">
          {/* This will be populated by client component */}
        </div>
      </div>

      <h2>Demo Articles</h2>
      <p>
        Each article has a free preview and encrypted premium content. 
        Try unlocking them to see Capsule in action.
      </p>

      <div style={{ 
        display: 'flex', 
        flexDirection: 'column', 
        gap: '1rem',
        marginTop: '2rem'
      }}>
        <Link 
          href="/article/premium-guide"
          style={{
            display: 'block',
            padding: '1.5rem',
            border: '2px solid var(--border)',
            borderRadius: '12px',
            transition: 'all 0.2s'
          }}
          className="article-card"
        >
          <h3 style={{ marginBottom: '0.5rem', color: 'var(--accent)' }}>
            The Complete Guide to Web Security
          </h3>
          <p style={{ color: 'var(--muted)', fontSize: '0.9rem', marginBottom: '1rem' }}>
            Learn about encryption fundamentals, envelope encryption, and how Capsule 
            implements client-side decryption.
          </p>
          <div style={{ 
            display: 'inline-block',
            padding: '0.25rem 0.75rem',
            background: '#fef3c7',
            color: '#92400e',
            borderRadius: '20px',
            fontSize: '0.8rem',
            fontWeight: '600'
          }}>
            🔒 Premium Content
          </div>
        </Link>

        <Link 
          href="/article/crypto-basics"
          style={{
            display: 'block',
            padding: '1.5rem',
            border: '2px solid var(--border)',
            borderRadius: '12px',
            transition: 'all 0.2s'
          }}
          className="article-card"
        >
          <h3 style={{ marginBottom: '0.5rem', color: 'var(--accent)' }}>
            Understanding Cryptography Basics
          </h3>
          <p style={{ color: 'var(--muted)', fontSize: '0.9rem', marginBottom: '1rem' }}>
            A beginner-friendly introduction to symmetric and asymmetric encryption, 
            and how the Web Crypto API makes it all accessible.
          </p>
          <div style={{ 
            display: 'inline-block',
            padding: '0.25rem 0.75rem',
            background: '#fef3c7',
            color: '#92400e',
            borderRadius: '20px',
            fontSize: '0.8rem',
            fontWeight: '600'
          }}>
            🔒 Premium Content
          </div>
        </Link>
      </div>

      <div style={{ 
        marginTop: '3rem',
        padding: '2rem',
        background: 'linear-gradient(135deg, rgba(0, 112, 243, 0.05) 0%, rgba(99, 102, 241, 0.05) 100%)',
        border: '2px solid var(--accent)',
        borderRadius: '12px'
      }}>
        <h3 style={{ color: 'var(--accent)', marginTop: 0 }}>
          🔑 How the Demo Works
        </h3>
        <ol style={{ paddingLeft: '1.5rem', lineHeight: '1.8' }}>
          <li>
            <strong>First visit:</strong> Your browser generates an RSA key pair, stored 
            securely in IndexedDB with <code>extractable: false</code>.
          </li>
          <li>
            <strong>Click unlock:</strong> Your public key is sent to the server, which 
            returns the encrypted decryption key for the premium tier.
          </li>
          <li>
            <strong>Decrypt locally:</strong> Your browser unwraps the key and decrypts 
            the content. The unwrapped key is cached for the session.
          </li>
          <li>
            <strong>Subsequent articles:</strong> Since the key is cached, other premium 
            articles decrypt instantly—even offline!
          </li>
        </ol>
        <p style={{ 
          marginTop: '1.5rem', 
          padding: '1rem',
          background: 'white',
          borderRadius: '8px',
          fontSize: '0.9rem'
        }}>
          💡 <strong>Try this:</strong> Unlock one article, then open another in a new tab. 
          You'll see it decrypts immediately without contacting the server.
        </p>
      </div>

      <style>{`
        .article-card:hover {
          border-color: var(--accent);
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(0, 112, 243, 0.15);
        }
      `}</style>
    </main>
  );
}
