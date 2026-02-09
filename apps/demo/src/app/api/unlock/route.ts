import { NextRequest, NextResponse } from "next/server";
import { createSubscriptionServer, createTokenManager } from "@sesamy/capsule-server";
import { MASTER_SECRET, BUCKET_PERIOD_SECONDS, totp, TOKEN_SECRET } from "@/lib/capsule";

/**
 * Create subscription server with the same master secret as the CMS.
 */
const server = createSubscriptionServer({
  masterSecret: MASTER_SECRET,
  bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
});

/**
 * Token manager for validating pre-signed share tokens.
 */
const tokens = createTokenManager({
  secret: TOKEN_SECRET,
});

/**
 * POST /api/unlock
 *
 * Three modes of operation:
 *
 * 1. TOKEN MODE (when `token` is provided)
 *    Validates a pre-signed token and unlocks content.
 *    Used for share links (social media, email, etc.)
 *    → Full audit trail, no user auth needed
 *
 * 2. TIER KEY MODE (mode: "tier" or default for tier keys)
 *    Returns the key-wrapping key (KEK) for a tier.
 *    Client can then unwrap any article's DEK locally.
 *    → "Unlock once, access all premium content"
 *
 * 3. ARTICLE KEY MODE (for article:xxx keys)
 *    Returns the unwrapped DEK for a specific article.
 *    → Single article access
 *
 * Request body:
 * {
 *   // For token mode:
 *   token?: string (pre-signed share token),
 *   wrappedDek: string (required for token mode),
 *   publicKey: string (Base64 SPKI format),
 *   articleId?: string (optional, for logging),
 *
 *   // For tier/article mode:
 *   keyId: string (e.g., "premium:123456" or "article:crypto-guide"),
 *   wrappedDek?: string (required for article keys, optional for tier keys),
 *   publicKey: string (Base64 SPKI format),
 *   mode?: "tier" | "article" (default: auto-detect from keyId)
 * }
 *
 * Response:
 * {
 *   encryptedDek: string (Base64 RSA-OAEP wrapped key),
 *   keyId: string,
 *   bucketId?: string,
 *   expiresAt: string (ISO 8601),
 *   keyType: "kek" | "dek" (indicates what encryptedDek contains),
 *   tokenId?: string (for token mode, useful for tracking)
 * }
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { token, keyId, wrappedDek, publicKey, mode, articleId } = body;

    // Validate public key (required for all modes)
    if (!publicKey || typeof publicKey !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid publicKey" },
        { status: 400 }
      );
    }

    // TOKEN MODE: Pre-signed share link unlock
    if (token) {
      if (!wrappedDek || typeof wrappedDek !== "string") {
        return NextResponse.json(
          { error: "Missing wrappedDek (required for token mode)" },
          { status: 400 }
        );
      }

      // Validate the token
      const validation = tokens.validate(token);
      if (!validation.valid) {
        console.log(`Token validation failed: ${validation.error} - ${validation.message}`);
        return NextResponse.json(
          { error: validation.message },
          { status: 401 }
        );
      }

      const payload = validation.payload;

      // Log the unlock for analytics
      console.log(`[UNLOCK] Token ${payload.tid} used for tier '${payload.tier}'`, {
        tokenId: payload.tid,
        tier: payload.tier,
        articleId: articleId || payload.articleId,
        userId: payload.userId,
        maxUses: payload.maxUses,
        ip: request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip"),
        timestamp: new Date().toISOString(),
      });

      // TODO: Check usage count if payload.maxUses is set
      // This would require a Redis/DB lookup to track usage

      // Unlock using the token
      const result = server.unlockWithToken(
        payload,
        wrappedDek,
        publicKey,
        articleId
      );

      return NextResponse.json({
        ...result,
        keyType: "dek",
        tokenId: payload.tid,
        bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
      });
    }

    // TIER/ARTICLE MODE: Requires keyId
    if (!keyId || typeof keyId !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid keyId (or provide a token)" },
        { status: 400 }
      );
    }

    // Determine if this is a tier key or article key
    const isArticleKey = keyId.startsWith("article:");
    const useTierMode =
      mode === "tier" || (!isArticleKey && mode !== "article");

    if (useTierMode && !isArticleKey) {
      // TIER KEY MODE: Return the key-wrapping key (KEK)
      // Parse tier:bucketId
      const colonIndex = keyId.lastIndexOf(":");
      if (colonIndex === -1) {
        return NextResponse.json(
          { error: "Invalid tier keyId format. Expected 'tier:bucketId'" },
          { status: 400 }
        );
      }

      const tier = keyId.substring(0, colonIndex);
      const bucketId = keyId.substring(colonIndex + 1);

      const result = server.getTierKeyForUser(tier, bucketId, publicKey);

      return NextResponse.json({
        ...result,
        keyType: "kek", // Key-encrypting key (can unwrap DEKs)
        bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
      });
    }

    // ARTICLE KEY MODE: Return the unwrapped DEK
    if (!wrappedDek || typeof wrappedDek !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid wrappedDek (required for article keys)" },
        { status: 400 }
      );
    }

    // Static key lookup for article keys - derive from same TOTP provider as CMS
    const staticKeyLookup = async (keyId: string): Promise<Buffer | null> => {
      if (keyId.startsWith("article:")) {
        const articleId = keyId.slice(8);
        const keyEntry = await totp.getArticleKey(articleId);
        return Buffer.isBuffer(keyEntry.key)
          ? keyEntry.key
          : Buffer.from(keyEntry.key, "base64");
      }
      return null;
    };

    const result = await server.unlockForUser(
      { keyId, wrappedDek },
      publicKey,
      staticKeyLookup
    );

    return NextResponse.json({
      ...result,
      keyType: "dek", // Data encryption key (decrypts content directly)
      bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
    });
  } catch (error) {
    console.error("Unlock error:", error);

    if (error instanceof Error) {
      if (
        error.message.includes("public key") ||
        error.message.includes("SPKI")
      ) {
        return NextResponse.json(
          { error: "Invalid public key format" },
          { status: 400 }
        );
      }
      if (
        error.message.includes("expired") ||
        error.message.includes("invalid")
      ) {
        return NextResponse.json({ error: error.message }, { status: 400 });
      }
    }

    return NextResponse.json(
      { error: "Failed to process unlock request" },
      { status: 500 }
    );
  }
}
