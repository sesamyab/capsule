import { NextRequest, NextResponse } from "next/server";
import { publicEncrypt, constants, createPublicKey } from "crypto";
import { getSubscriptionKey, getArticleKey, hasArticleKey, isValidTier } from "@/lib/encryption-keys";
import { getCurrentBucket, getBucketExpiration, BUCKET_PERIOD_SECONDS, isBucketValid } from "@/lib/time-buckets";

/**
 * POST /api/unlock
 *
 * Receives a client's public key and key request, returns the DEK wrapped
 * with the client's public key.
 * 
 * For TIER keys: DEK is derived from master secret + bucketId using HKDF.
 * This provides forward secrecy - when the bucket expires, the key changes.
 * 
 * For ARTICLE keys: DEK is static (permanent access once purchased).
 *
 * Request body:
 * {
 *   keyType: "tier" | "article",
 *   keyId: string (tier name like "premium" or article ID),
 *   publicKey: string (Base64 SPKI format),
 *   bucketId?: string (optional - for requesting a specific bucket's key)
 * }
 *
 * Response:
 * {
 *   encryptedDek: string (Base64),
 *   keyType: "tier" | "article",
 *   keyId: string,
 *   expiresAt: string (ISO 8601),
 *   bucketId: string
 * }
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { keyType, keyId, publicKey, tier, bucketId } = body;
    
    // Support legacy format (tier only)
    const actualKeyType = keyType || "tier";
    const actualKeyId = keyId || tier;

    // Validate required fields
    if (!actualKeyId || typeof actualKeyId !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid keyId/tier" },
        { status: 400 }
      );
    }

    if (!publicKey || typeof publicKey !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid publicKey" },
        { status: 400 }
      );
    }

    // For tier keys, determine which bucket to use
    let targetBucketId = getCurrentBucket();
    if (actualKeyType === "tier" && bucketId) {
      // Client requested a specific bucket - validate it's current or adjacent
      if (!isBucketValid(bucketId)) {
        return NextResponse.json(
          { error: "Invalid or expired bucket" },
          { status: 400 }
        );
      }
      targetBucketId = bucketId;
    }

    // Get the appropriate DEK
    let dek: Buffer;
    let expiresAt: Date;
    let responseBucketId: string;
    
    try {
      if (actualKeyType === "article") {
        // Article keys are static (permanent access)
        if (!hasArticleKey(actualKeyId)) {
          return NextResponse.json(
            { error: "No article-specific key available" },
            { status: 400 }
          );
        }
        dek = getArticleKey(actualKeyId);
        // Article keys expire at end of current bucket but can be renewed indefinitely
        responseBucketId = targetBucketId;
        expiresAt = getBucketExpiration(targetBucketId);
      } else {
        // Tier keys are bucket-based (forward secrecy)
        if (!isValidTier(actualKeyId)) {
          return NextResponse.json(
            { error: `Invalid tier: ${actualKeyId}` },
            { status: 400 }
          );
        }
        dek = getSubscriptionKey(actualKeyId, targetBucketId);
        responseBucketId = targetBucketId;
        expiresAt = getBucketExpiration(targetBucketId);
      }
    } catch (err) {
      return NextResponse.json(
        { error: `Invalid ${actualKeyType}: ${actualKeyId}` },
        { status: 400 }
      );
    }

    // Convert Base64 SPKI to PEM format for Node.js crypto
    const publicKeyPem = convertToPem(publicKey);

    // Create public key object
    const pubKey = createPublicKey(publicKeyPem);

    // Wrap the DEK with the client's public key using RSA-OAEP with SHA-256
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
      keyType: actualKeyType,
      keyId: actualKeyId,
      bucketId: responseBucketId,
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
      { error: "Failed to wrap DEK" },
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
