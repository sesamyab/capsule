import { CodeBlock } from "@/components/CodeBlock";

export default function ServersPage() {
  return (
    <main className="content-page">
      <h1>Server Implementations</h1>
      <p>
        Capsule servers handle content encryption and DEK wrapping. Implementations are
        available for Node.js and PHP, with more languages coming soon.
      </p>

      <h2>Node.js</h2>
      <p>
        The Node.js implementation uses the built-in <code>crypto</code> module for
        maximum performance and minimal dependencies.
      </p>

      <h3>Installation</h3>
      <CodeBlock language="bash">{`npm install capsule`}</CodeBlock>

      <h3>Basic Usage</h3>
      <CodeBlock>{`import { ArticleEncryptor } from 'capsule';

// Encrypt content for a specific client
const encryptor = new ArticleEncryptor(clientPublicKey);
const encrypted = await encryptor.encrypt(content);

// Result: { encryptedContent, iv, encryptedDek }`}</CodeBlock>

      <h3>API Routes (Next.js Example)</h3>
      <CodeBlock>{`// app/api/unlock/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { publicEncrypt, constants } from 'crypto';

export async function POST(request: NextRequest) {
  const { tier, publicKey } = await request.json();
  
  // Get the DEK for this subscription tier
  const dek = getSubscriptionDek(tier);
  
  // Convert Base64 SPKI to PEM
  const publicKeyPem = convertToPem(publicKey);
  
  // Wrap DEK with client's public key
  const encryptedDek = publicEncrypt(
    {
      key: publicKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    dek
  );
  
  return NextResponse.json({
    encryptedDek: encryptedDek.toString('base64'),
    tier
  });
}`}</CodeBlock>

      <h3>Pre-Encrypting Content</h3>
      <CodeBlock>{`import { createCipheriv, randomBytes } from 'crypto';

function encryptArticle(content: string, dek: Buffer) {
  const iv = randomBytes(12); // 96-bit IV
  
  const cipher = createCipheriv('aes-256-gcm', dek, iv, {
    authTagLength: 16
  });
  
  const encrypted = Buffer.concat([
    cipher.update(content, 'utf8'),
    cipher.final(),
    cipher.getAuthTag()
  ]);
  
  return {
    encryptedContent: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tier: 'premium'
  };
}

// At build time or when content is published:
const articles = [
  { id: '1', content: '...' },
  { id: '2', content: '...' }
];

const premiumDek = randomBytes(32); // Generate once per tier
const encrypted = articles.map(article =>
  encryptArticle(article.content, premiumDek)
);`}</CodeBlock>

      <h2>PHP</h2>
      <p>
        PHP implementation using OpenSSL for cryptographic operations.
      </p>

      <h3>Installation</h3>
      <CodeBlock language="bash">{`composer require capsule/capsule-php`}</CodeBlock>

      <h3>Basic Usage</h3>
      <CodeBlock language="php">{`<?php

use Capsule\\ArticleEncryptor;

// Encrypt content
$dek = random_bytes(32); // AES-256 key
$iv = random_bytes(12);  // GCM IV

$encrypted = openssl_encrypt(
    $content,
    'aes-256-gcm',
    $dek,
    OPENSSL_RAW_DATA,
    $iv,
    $tag
);

$result = [
    'encryptedContent' => base64_encode($encrypted . $tag),
    'iv' => base64_encode($iv),
    'tier' => 'premium'
];`}</CodeBlock>

      <h3>Key Exchange Endpoint</h3>
      <CodeBlock language="php">{`<?php

// api/unlock.php
header('Content-Type: application/json');

$input = json_decode(file_get_contents('php://input'), true);
$tier = $input['tier'];
$publicKey = $input['publicKey'];

// Get DEK for tier
$dek = getSubscriptionDek($tier);

// Convert SPKI to PEM
$publicKeyPem = convertSpkiToPem($publicKey);

// Wrap DEK with RSA-OAEP
$encryptedDek = '';
openssl_public_encrypt(
    $dek,
    $encryptedDek,
    $publicKeyPem,
    OPENSSL_PKCS1_OAEP_PADDING
);

echo json_encode([
    'encryptedDek' => base64_encode($encryptedDek),
    'tier' => $tier
]);

function convertSpkiToPem($base64Spki) {
    $der = base64_decode($base64Spki);
    $pem = "-----BEGIN PUBLIC KEY-----\\n";
    $pem .= chunk_split(base64_encode($der), 64);
    $pem .= "-----END PUBLIC KEY-----";
    return $pem;
}`}</CodeBlock>

      <h2>Python</h2>
      <p>Python support using the <code>cryptography</code> library.</p>

      <h3>Installation</h3>
      <CodeBlock language="bash">{`pip install capsule-py`}</CodeBlock>

      <h3>Basic Usage</h3>
      <CodeBlock language="python">{`from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import base64

# Encrypt content
def encrypt_article(content: str, dek: bytes) -> dict:
    iv = os.urandom(12)
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(iv, content.encode(), None)
    
    return {
        'encryptedContent': base64.b64encode(ciphertext).decode(),
        'iv': base64.b64encode(iv).decode(),
        'tier': 'premium'
    }

# Wrap DEK
def wrap_dek(dek: bytes, public_key_spki: str) -> str:
    # Load public key from SPKI
    public_key = serialization.load_der_public_key(
        base64.b64decode(public_key_spki)
    )
    
    # Wrap with RSA-OAEP
    encrypted = public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return base64.b64encode(encrypted).decode()`}</CodeBlock>

      <h2>Coming Soon</h2>
      <ul>
        <li>🔨 Go implementation</li>
        <li>🔨 Ruby implementation</li>
        <li>🔨 Rust implementation</li>
        <li>🔨 .NET implementation</li>
      </ul>

      <p>
        Want to contribute an implementation? Check out the{' '}
        <a href="https://github.com/capsule-standard/capsule">GitHub repository</a>.
      </p>
    </main>
  );
}
