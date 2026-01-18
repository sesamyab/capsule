import { NextRequest, NextResponse } from "next/server";
import { publicEncrypt, constants, createPublicKey, createDecipheriv } from "crypto";
import { getArticleKey, hasArticleKey, isValidTier } from "@/lib/encryption-keys";
import { deriveBucketKey, getCurrentBucket, getBucketExpiration, BUCKET_PERIOD_SECONDS, isBucketValid } from "@/lib/time-buckets";

/** GCM IV size in bytes */
const GCM_IV_SIZE = 12;

/** GCM authentication tag length in bytes */
const GCM_TAG_LENGTH = 16;

/**
 * Unwrap a DEK that was wrapped with AES-256-GCM.
 */
function unwrapDek(wrappedDek: Buffer, wrappingKey: Buffer): Buffer {
  const iv = wrappedDek.subarray(0, GCM_IV_SIZE);
  const ciphertext = wrappedDek.subarray(GCM_IV_SIZE, -GCM_TAG_LENGTH);
  const authTag = wrappedDek.subarray(-GCM_TAG_LENGTH);
  
  const decipher = createDecipheriv("aes-256-gcm", wrappingKey, iv, {
    authTagLength: GCM_TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);
  
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * POST /api/unlock
 *
 * Receives a wrapped DEK and client's public key, unwraps the DEK and
 * re-wraps it with the client's public key.
 *
 * Request body:
 * {
 *   keyId: string (e.g., "premium:123456" or "article:crypto-guide"),
 *   wrappedDek: string (Base64-encoded wrapped DEK from article),
 *   publicKey: string (Base64 SPKI format)
 * }
 *
 * Response:
 * {
 *   encryptedDek: string (Base64 RSA-OAEP wrapped DEK),
 *   keyId: string,
 *   bucketId?: string,
 *   expiresAt: string (ISO 8601)
 * }
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { keyId, wrappedDek, publicKey } = body;

    // Validate required fields
    if (!keyId || typeof keyId !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid keyId" },
        { status: 400 }
      );
    }

    if (!wrappedDek || typeof wrappedDek !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid wrappedDek" },
        { status: 400 }
      );
    }

    if (!publicKey || typeof publicKey !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid publicKey" },
        { status: 400 }
      );
    }

    // Parse keyId to determine type: "tier:bucketId" or "article:articleId"
    const [keyType, keySubId] = keyId.includes(":") 
      ? keyId.split(":", 2) 
      : [keyId, null];

    let keyWrappingKey: Buffer;
    let expiresAt: Date;
    let bucketId: string | undefined;

    if (keyType === "article" && keySubId) {
      // Static article key
      if (!hasArticleKey(keySubId)) {
        return NextResponse.json(
          { error: `Unknown article key: ${keySubId}` },
          { status: 400 }
        );
      }
      keyWrappingKey = getArticleKey(keySubId);
      // Static keys use current bucket expiration for client cache timing
      const currentBucket = getCurrentBucket();
      expiresAt = getBucketExpiration(currentBucket);
    } else if (keySubId) {
      // Tier key with bucket ID (e.g., "premium:123456")
      if (!isValidTier(keyType)) {
        return NextResponse.json(
          { error: `Invalid tier: ${keyType}` },
          { status: 400 }
        );
      }
      
      if (!isBucketValid(keySubId)) {
        return NextResponse.json(
          { error: `Bucket ${keySubId} is expired or invalid` },
          { status: 400 }
        );
      }
      
      bucketId = keySubId;
      keyWrappingKey = deriveBucketKey(keyType, bucketId);
      expiresAt = getBucketExpiration(bucketId);
    } else {
      return NextResponse.json(
        { error: "Invalid keyId format. Expected 'tier:bucketId' or 'article:articleId'" },
        { status: 400 }
      );
    }

    // Unwrap the DEK using the key-wrapping key
    const wrappedDekBuffer = Buffer.from(wrappedDek, "base64");
    let dek: Buffer;
    
    try {
      dek = unwrapDek(wrappedDekBuffer, keyWrappingKey);
    } catch (err) {
      console.error("Failed to unwrap DEK:", err);
      return NextResponse.json(
        { error: "Failed to unwrap DEK - key may have expired" },
        { status: 400 }
      );
    }

    // Convert Base64 SPKI to PEM format for Node.js crypto
    const publicKeyPem = convertToPem(publicKey);
    const pubKey = createPublicKey(publicKeyPem);

    // Re-wrap the DEK with the client's public key using RSA-OAEP with SHA-256
    const encryptedDek = publicEncrypt(
      {
        key: pubKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      dek
    );

    return NextResponse.json({
      encryptedDek: encryptedDek.toString("base64"),
      keyId,
      bucketId,
      expiresAt: expiresAt.toISOString(),
      bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
    });
  } catch (error) {
    console.error("Unlock error:", error);

    if (error instanceof Error) {
      if (error.message.includes("public key") || error.message.includes("SPKI")) {
        return NextResponse.json(
          { error: "Invalid public key format" },
          { status: 400 }
        );
      }
    }

    return NextResponse.json(
      { error: "Failed to process unlock request" },
      { status: 500 }
    );
  }
}

/**
 * Convert Base64 SPKI to PEM format for Node.js crypto.
 */
function convertToPem(publicKeyB64: string): string {
  const keyDer = Buffer.from(publicKeyB64, "base64");
  const base64Lines: string[] = [];
  const base64 = keyDer.toString("base64");

  for (let i = 0; i < base64.length; i += 64) {
    base64Lines.push(base64.slice(i, i + 64));
  }

  return `-----BEGIN PUBLIC KEY-----\n${base64Lines.join("\n")}\n-----END PUBLIC KEY-----`;
}
