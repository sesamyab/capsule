import Link from "next/link";

export default function DemoPage() {
  return (
    <main className="content-page">
      <h1>Interactive Demo</h1>
      <p>
        Try the DCA demo with these articles. Each article has a free preview and 
        encrypted premium content. Unlock them to see DCA in action.
      </p>

      <div style={{ 
        background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(147, 51, 234, 0.1))',
        border: '1px solid rgba(59, 130, 246, 0.3)',
        padding: '1rem 1.25rem', 
        borderRadius: '8px',
        marginBottom: '1.5rem',
        fontSize: '0.85rem'
      }}>
        <strong>🔐 DCA Mode:</strong> Content is encrypted server-side using HKDF-derived 
        period keys with <strong>1-hour</strong> rotation. Articles are grouped into 
        <strong>tiers</strong> via <code>contentName</code> — articles in the same tier share 
        period keys and can auto-unlock each other.
      </div>

      <h2>Demo Articles</h2>
      <p>
        Each article has a free preview and encrypted premium content. 
        TierA and TierB use separate period keys — unlocking one tier does not grant access to the other.
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
          <div style={{ display: 'flex', gap: '0.5rem' }}>
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
            <div style={{ 
              display: 'inline-block',
              padding: '0.25rem 0.75rem',
              background: '#dbeafe',
              color: '#1e40af',
              borderRadius: '20px',
              fontSize: '0.8rem',
              fontWeight: '600'
            }}>
              TierA
            </div>
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
          <div style={{ display: 'flex', gap: '0.5rem' }}>
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
            <div style={{ 
              display: 'inline-block',
              padding: '0.25rem 0.75rem',
              background: '#dbeafe',
              color: '#1e40af',
              borderRadius: '20px',
              fontSize: '0.8rem',
              fontWeight: '600'
            }}>
              TierA
            </div>
          </div>
        </Link>

        <Link 
          href="/article/zero-trust"
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
            Zero Trust Architecture for APIs
          </h3>
          <p style={{ color: 'var(--muted)', fontSize: '0.9rem', marginBottom: '1rem' }}>
            How Zero Trust principles apply to API design and how DCA enables 
            fine-grained cryptographic access control with independent tiers.
          </p>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
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
            <div style={{ 
              display: 'inline-block',
              padding: '0.25rem 0.75rem',
              background: '#fce7f3',
              color: '#9d174d',
              borderRadius: '20px',
              fontSize: '0.8rem',
              fontWeight: '600'
            }}>
              TierB
            </div>
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
            <strong>Unlock Article:</strong> Returns a one-time <em>contentKey</em> — 
            works for a single article, non-cacheable.
          </li>
          <li>
            <strong>Unlock Tier:</strong> Returns <em>periodKeys</em> derived via HKDF 
            from the tier&apos;s <code>contentName</code>. Cached for 1 hour and reusable 
            across all articles in the same tier.
          </li>
          <li>
            <strong>Cross-article unlock:</strong> Articles in the same tier share period 
            keys, so unlocking TierA on one article auto-unlocks all TierA articles. 
            TierB remains locked.
          </li>
        </ol>
        <p style={{ 
          marginTop: '1.5rem', 
          padding: '1rem',
          background: 'white',
          borderRadius: '8px',
          fontSize: '0.9rem'
        }}>
          💡 <strong>Try this:</strong> Unlock &quot;TierA&quot; on one article, then open 
          the other TierA article — it decrypts automatically! Then try the TierB article 
          and notice it stays locked.
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
