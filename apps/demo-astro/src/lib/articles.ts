/**
 * Sample articles for the demo.
 */

export interface Article {
  id: string;
  title: string;
  author: string;
  publishedAt: string;
  previewContent: string;
  premiumContent: string;
}

export const articles: Record<string, Article> = {
  "premium-guide": {
    id: "premium-guide",
    title: "The Complete Guide to Web Security",
    author: "Alex Security",
    publishedAt: "2026-01-15",
    previewContent: `Web security is one of the most critical aspects of modern software development. 
As our digital lives become increasingly interconnected, understanding how to protect 
user data and maintain system integrity has never been more important.

In this comprehensive guide, we'll explore the fundamental concepts of web security,
from encryption basics to advanced threat mitigation strategies.`,
    premiumContent: `## Chapter 1: The Foundation of Security

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

---

**Congratulations!** You've just decrypted this content using envelope encryption.`,
  },
  "crypto-basics": {
    id: "crypto-basics",
    title: "Understanding Cryptography Basics",
    author: "Sarah Cipher",
    publishedAt: "2026-01-10",
    previewContent: `Cryptography is the practice of securing communication and data through the use of codes.
It's been used throughout history, from ancient Rome to modern digital communications.

This article will introduce you to the fundamental concepts that make modern encryption work.`,
    premiumContent: `## What is Cryptography?

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

---

**You did it!** This content was encrypted specifically for your browser session.`,
  },
};

export function getArticle(id: string): Article | undefined {
  return articles[id];
}

export function getAllArticleIds(): string[] {
  return Object.keys(articles);
}
