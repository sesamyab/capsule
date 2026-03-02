import { NextRequest, NextResponse } from "next/server";
import {
  createSubscriptionServer,
  createTokenManager,
} from "@sesamy/capsule-server";
import type { SubscriptionServer, TokenManager } from "@sesamy/capsule-server";
import {
  PERIOD_DURATION_SECONDS,
  getKeyProvider,
  getTokenSecret,
  getPeriodSecret,
} from "@/lib/capsule";

// ---------------------------------------------------------------------------
// Lazy singletons – avoid calling secret getters at module-init time so that
// `next build` can collect pages without the env vars being set.
// ---------------------------------------------------------------------------

let _server: SubscriptionServer | undefined;
function getServer() {
  if (!_server) {
    _server = createSubscriptionServer({
      periodSecret: getPeriodSecret(),
      periodDurationSeconds: PERIOD_DURATION_SECONDS,
    });
  }
  return _server;
}

let _tokens: TokenManager | undefined;
function getTokens() {
  if (!_tokens) {
    _tokens = createTokenManager({
      secret: getTokenSecret(),
      issuer: "capsule-demo",
      keyId: "demo-key-2026",
    });
  }
  return _tokens;
}

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
 * 2. SHARED KEY MODE (mode: "shared" or default for shared keys)
 *    Returns the key-wrapping key (KEK) for a content ID.
 *    Client can then unwrap any article's content key locally.
 *    → "Unlock once, access all premium content"
 *
 * 3. ARTICLE KEY MODE (for article:xxx keys)
 *    Returns the unwrapped content key for a specific article.
 *    → Single article access
 *
 * Request body:
 * {
 *   // For token mode:
 *   token?: string (pre-signed share token),
 *   wrappedContentKey: string (required for token mode),
 *   publicKey: string (Base64 SPKI format),
 *   resourceId?: string (optional, for content validation),
 *
 *   // For shared/article mode:
 *   keyId: string (e.g., "premium:123456" or "article:crypto-guide"),
 *   wrappedContentKey?: string (required for article keys, optional for shared keys),
 *   publicKey: string (Base64 SPKI format),
 *   mode?: "shared" | "article" (default: auto-detect from keyId)
 * }
 *
 * Response:
 * {
 *   encryptedContentKey: string (Base64 RSA-OAEP wrapped key),
 *   keyId: string,
 *   periodId?: string,
 *   expiresAt: string (ISO 8601),
 *   keyType: "kek" | "dek" (indicates what encryptedContentKey contains),
 *   tokenId?: string (for token mode, useful for tracking)
 * }
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { token, keyId, wrappedContentKey, publicKey, mode, resourceId } = body;

    // Validate public key (required for all modes)
    if (!publicKey || typeof publicKey !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid publicKey" },
        { status: 400 },
      );
    }

    // Validate optional resourceId if provided
    if (resourceId !== undefined && typeof resourceId !== "string") {
      return NextResponse.json(
        { error: "Invalid resourceId – must be a string when provided" },
        { status: 400 },
      );
    }

    // TOKEN MODE: Pre-signed share link unlock
    if (token) {
      if (!wrappedContentKey || typeof wrappedContentKey !== "string") {
        return NextResponse.json(
          { error: "Missing wrappedContentKey (required for token mode)" },
          { status: 400 },
        );
      }

      // Validate the token
      const validation = await getTokens().validate(token);
      if (!validation.valid) {
        console.log(
          `Token validation failed: ${validation.error} - ${validation.message}`,
        );
        return NextResponse.json(
          { error: validation.message },
          { status: 401 },
        );
      }

      const payload = validation.payload;

      // Log the unlock for analytics
      console.log(
        `[UNLOCK] Token ${payload.tid} used for contentId '${payload.contentId}'`,
        {
          tokenId: payload.tid,
          issuer: payload.iss,
          keyId: payload.kid,
          contentId: payload.contentId,
          userId: payload.userId,
          maxUses: payload.maxUses,
          ip:
            request.headers.get("x-forwarded-for") ||
            request.headers.get("x-real-ip"),
          timestamp: new Date().toISOString(),
        },
      );

      // TODO: Check usage count if payload.maxUses is set
      // This would require a Redis/DB lookup to track usage

      // Unlock using the token (validates contentId matches)
      const result = await getServer().unlockWithToken(
        payload,
        wrappedContentKey,
        publicKey,
        resourceId,
      );

      return NextResponse.json({
        ...result,
        keyType: "dek",
        tokenId: payload.tid,
        issuer: payload.iss,
        contentId: payload.contentId,
        periodDurationSeconds: PERIOD_DURATION_SECONDS,
      });
    }

    // SHARED/ARTICLE MODE: Requires keyId
    if (!keyId || typeof keyId !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid keyId (or provide a token)" },
        { status: 400 },
      );
    }

    // Determine if this is a shared key or article key
    const isArticleKey = keyId.startsWith("article:");
    const useSharedMode =
      mode === "shared" || (!isArticleKey && mode !== "article");

    // Early validation: article keyIds must have a non-empty slug
    if (isArticleKey) {
      const slug = keyId.slice(8);
      if (!slug || !slug.trim()) {
        return NextResponse.json(
          { error: "Invalid article keyId: slug must be non-empty. Expected 'article:<slug>'" },
          { status: 400 },
        );
      }
    }

    // Early validation: shared keyIds must contain exactly "contentId:periodId"
    if (useSharedMode && !isArticleKey) {
      if (!keyId.includes(":")) {
        return NextResponse.json(
          { error: "Invalid shared keyId format. Expected 'contentId:periodId'" },
          { status: 400 },
        );
      }

      // SHARED KEY MODE: Return the key-wrapping key (KEK)
      // Parse contentId:periodId
      const colonIndex = keyId.lastIndexOf(":");
      const contentId = keyId.substring(0, colonIndex);
      const periodId = keyId.substring(colonIndex + 1);

      if (!contentId || !contentId.trim() || !periodId || !periodId.trim()) {
        return NextResponse.json(
          { error: "Invalid shared keyId: both contentId and periodId must be non-empty. Expected 'contentId:periodId'" },
          { status: 400 },
        );
      }

      const result = await getServer().getSharedKeyForUser(contentId, periodId, publicKey);

      return NextResponse.json({
        ...result,
        keyType: "kek", // Key-encrypting key (can unwrap content keys)
        periodDurationSeconds: PERIOD_DURATION_SECONDS,
      });
    }

    // ARTICLE KEY MODE: Return the unwrapped content key
    if (!wrappedContentKey || typeof wrappedContentKey !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid wrappedContentKey (required for article keys)" },
        { status: 400 },
      );
    }

    // Static key lookup for article keys - derive from same period key provider as CMS
    const staticKeyLookup = async (keyId: string): Promise<Uint8Array | null> => {
      if (keyId.startsWith("article:")) {
        const contentId = keyId.slice(8);
        const keyEntry = await getKeyProvider().getArticleKey(contentId);
        if (keyEntry.key instanceof Uint8Array) {
          return keyEntry.key;
        }
        // Decode base64 string to Uint8Array
        const binaryString = atob(keyEntry.key);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
      }
      return null;
    };

    const result = await getServer().unlockForUser(
      { keyId, wrappedContentKey },
      publicKey,
      staticKeyLookup,
    );

    return NextResponse.json({
      ...result,
      keyType: "dek", // Data encryption key (decrypts content directly)
      periodDurationSeconds: PERIOD_DURATION_SECONDS,
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
          { status: 400 },
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
      { status: 500 },
    );
  }
}
