/**
 * Sample articles for the demo.
 * In a real app, these would come from a database.
 */

export interface Article {
  id: string;
  title: string;
  author: string;
  publishedAt: string;
  previewContent: string;
  premiumContent: string;
  /** Content tier — articles sharing a tier share period keys (e.g. "TierA", "TierB") */
  tier: string;
}

export const articles: Record<string, Article> = {
  "premium-guide": {
    id: "premium-guide",
    title: "The Complete Guide to Web Security",
    author: "Alex Security",
    publishedAt: "2026-01-15",
    tier: "TierA",
    previewContent: `
Web security is one of the most critical aspects of modern software development. 
As our digital lives become increasingly interconnected, understanding how to protect 
user data and maintain system integrity has never been more important.

In this comprehensive guide, we'll explore the fundamental concepts of web security,
from encryption basics to advanced threat mitigation strategies.
    `.trim(),
    premiumContent: `
## Chapter 1: The Foundation of Security

Security begins with understanding the threat landscape. Modern web applications 
face a variety of attack vectors, including:

- **Cross-Site Scripting (XSS)**: Malicious scripts injected into trusted websites
- **SQL Injection**: Exploiting database queries to access unauthorized data
- **Cross-Site Request Forgery (CSRF)**: Tricking users into performing unwanted actions
- **Man-in-the-Middle Attacks**: Intercepting communications between parties

### Defense in Depth

The principle of defense in depth suggests implementing multiple layers of security:

1. **Network Security**: Firewalls, intrusion detection systems
2. **Application Security**: Input validation, output encoding
3. **Data Security**: Encryption at rest and in transit
4. **Access Control**: Authentication and authorization

## Chapter 2: Encryption Fundamentals

Encryption is the process of converting plaintext into ciphertext using an algorithm and a key.

### Symmetric Encryption

Uses the same key for encryption and decryption. Common algorithms include:
- **AES (Advanced Encryption Standard)**: The gold standard, with 128, 192, or 256-bit keys
- **ChaCha20**: A modern stream cipher, excellent for mobile devices

### Asymmetric Encryption

Uses a key pair: public key for encryption, private key for decryption.
- **RSA**: The classic algorithm, widely used for key exchange
- **Elliptic Curve**: More efficient, smaller keys for equivalent security

## Chapter 3: Envelope Encryption

This is exactly what Capsule implements! Envelope encryption combines the best of both worlds:

1. Generate a random symmetric key (content key - DEK)
2. Encrypt your data with the content key (fast, efficient)
3. Encrypt the content key with the recipient's public key (secure key exchange)
4. Send both the encrypted data and encrypted DEK

The recipient can then:
1. Decrypt the content key using their private key
2. Decrypt the data using the content key

This approach provides the efficiency of symmetric encryption with the key management 
benefits of asymmetric encryption.

---

**Congratulations!** You've just decrypted this content using envelope encryption.
Your private key never left your browser, and this specific content was encrypted
just for you with a unique key.

<div id="confetti-container"></div>
<script>
(function() {
  const confetti = ['🎊', '✨', '🌟', '💫', '🎉', '🔐', '🔑'];
  const container = document.getElementById('confetti-container');
  
  // Add keyframe animation if not exists
  if (!document.getElementById('confetti-style')) {
    const style = document.createElement('style');
    style.id = 'confetti-style';
    style.textContent = \`
      @keyframes confetti-fall {
        0% { transform: translateY(0) rotate(0deg); opacity: 1; }
        100% { transform: translateY(100vh) rotate(720deg); opacity: 0; }
      }
      .confetti-piece {
        position: fixed;
        font-size: 24px;
        z-index: 1000;
        pointer-events: none;
        animation: confetti-fall 3s ease-in forwards;
      }
      .unlock-celebration {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin-top: 1rem;
        text-align: center;
      }
      .unlock-celebration .time {
        font-size: 0.9em;
        opacity: 0.9;
      }
    \`;
    document.head.appendChild(style);
  }
  
  // Spawn confetti
  for (let i = 0; i < 30; i++) {
    setTimeout(() => {
      const span = document.createElement('span');
      span.className = 'confetti-piece';
      span.textContent = confetti[Math.floor(Math.random() * confetti.length)];
      span.style.left = Math.random() * 100 + 'vw';
      span.style.top = '-30px';
      document.body.appendChild(span);
      setTimeout(() => span.remove(), 3000);
    }, i * 50);
  }
  
  // Add celebration message
  const celebration = document.createElement('div');
  celebration.className = 'unlock-celebration';
  celebration.innerHTML = \`
    <strong>🎉 Content Unlocked!</strong><br>
    <span class="time">Decrypted at \${new Date().toLocaleTimeString()} using your browser's cryptographic keys</span>
  \`;
  container.appendChild(celebration);
})();
</script>
    `.trim(),
  },
  "crypto-basics": {
    id: "crypto-basics",
    title: "Understanding Cryptography Basics",
    author: "Sarah Cipher",
    publishedAt: "2026-01-10",
    tier: "TierA",
    previewContent: `
Cryptography is the practice of securing communication and data through the use of codes.
It's been used throughout history, from ancient Rome to modern digital communications.

This article will introduce you to the fundamental concepts that make modern encryption work.
    `.trim(),
    premiumContent: `
## What is Cryptography?

At its core, cryptography is about transforming readable data (plaintext) into an 
unreadable format (ciphertext) that can only be reversed by someone with the right key.

### The Three Pillars

Modern cryptography provides three essential properties:

1. **Confidentiality**: Only authorized parties can read the data
2. **Integrity**: Data hasn't been tampered with
3. **Authentication**: Verify the identity of the sender

## Symmetric vs Asymmetric

### Symmetric Key Cryptography

Imagine you and a friend share a secret codebook. You both use the same book to 
encode and decode messages. That's symmetric encryption!

**Pros:**
- Very fast
- Simple to implement
- Efficient for large amounts of data

**Cons:**
- Key distribution problem: How do you safely share the secret key?
- Doesn't provide non-repudiation

### Asymmetric Key Cryptography

Now imagine everyone has two keys: a public one they share freely, and a private 
one they keep secret. Anyone can encrypt a message with your public key, but only 
you can decrypt it with your private key.

**Pros:**
- Solves the key distribution problem
- Enables digital signatures
- Provides non-repudiation

**Cons:**
- Much slower than symmetric encryption
- Computationally intensive

## The Web Crypto API

Modern browsers include a powerful cryptography API that you're using right now!
The SubtleCrypto interface provides:

- \`generateKey()\`: Create new cryptographic keys
- \`encrypt()\` / \`decrypt()\`: Symmetric encryption operations
- \`wrapKey()\` / \`unwrapKey()\`: Key wrapping (envelope encryption!)
- \`sign()\` / \`verify()\`: Digital signatures

Your private key is stored in IndexedDB with \`extractable: false\`, meaning 
even JavaScript can't read the raw key bytes. The browser's crypto engine 
handles all operations securely.

---

**You did it!** This content was encrypted specifically for your browser session.
The encryption happened on the server, but decryption happened entirely in your browser.
    `.trim(),
  },
  "zero-trust": {
    id: "zero-trust",
    title: "Zero Trust Architecture for APIs",
    author: "Kai Network",
    publishedAt: "2026-02-01",
    tier: "TierB",
    previewContent: `
Zero Trust is a security model that assumes no implicit trust — every request 
must be verified, regardless of where it originates. This approach has become the 
gold standard for modern API security.

In this article, we explore how Zero Trust principles apply to API design and 
how cryptographic access control enables fine-grained authorization.
    `.trim(),
    premiumContent: `
## What is Zero Trust?

The traditional security model ("castle and moat") assumes that anything inside 
the network perimeter is trustworthy. Zero Trust flips this assumption:

> **"Never trust, always verify."**

Every request — whether from inside or outside the network — must:

1. **Authenticate** the caller's identity
2. **Authorize** the specific action being requested
3. **Encrypt** all data in transit and at rest

### Zero Trust Principles

- **Least Privilege**: Grant minimum access required for each task
- **Micro-Segmentation**: Isolate resources into small, independently secured zones
- **Continuous Verification**: Re-authenticate and re-authorize on every request
- **Assume Breach**: Design systems to limit blast radius of compromise

## Applying Zero Trust to APIs

### Token-Based Access Control

Modern APIs use short-lived tokens (JWTs, opaque tokens) instead of session cookies:

\`\`\`
Authorization: Bearer eyJhbGciOiJFUzI1NiJ9...
\`\`\`

Each token carries claims that specify exactly what the bearer can access.

### Delegated Content Access (DCA)

DCA takes Zero Trust further by separating **content encryption** from **access control**:

- **Publisher** encrypts content with unique keys per time period
- **Issuer** holds sealed key material but only releases it upon authorization
- **Client** decrypts locally — the issuer never sees plaintext content

This is exactly what you're experiencing right now! The article content was 
encrypted server-side, and your browser is performing the decryption.

## Rate Limiting & Anomaly Detection

Zero Trust APIs should implement:

- **Rate limiting**: Prevent brute-force and enumeration attacks
- **Request signing**: HMAC or digital signatures on API calls
- **Anomaly detection**: Flag unusual patterns (geographic, temporal, volumetric)
- **Audit logging**: Immutable logs of all access decisions

---

**Welcome to TierB!** 🎉 This content is in a separate encryption tier.
Unlocking TierA articles does NOT grant access to TierB content — each tier 
has independent period keys derived via HKDF with a different content name.
    `.trim(),
  },
};

export function getArticle(id: string): Article | undefined {
  return articles[id];
}

export function getAllArticleIds(): string[] {
  return Object.keys(articles);
}
