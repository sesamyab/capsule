import { NextRequest, NextResponse } from "next/server";
import { createTokenManager } from "@sesamy/capsule-server";
import { getTokenSecret } from "@/lib/capsule";

/**
 * Token manager for generating share tokens.
 * Lazily initialized to avoid calling getTokenSecret() at build time.
 */
let _tokens: ReturnType<typeof createTokenManager> | undefined;
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
 * POST /api/share
 *
 * Generate a pre-signed share token for content access.
 * Used by publishers to create shareable links.
 *
 * Request body:
 * {
 *   articleSlug: string (required, article identifier for URL routing),
 *   url?: string (optional, full URL for the content),
 *   expiresIn: string (e.g., "24h", "7d"),
 *   maxUses?: number (optional, limit total uses),
 *   userId?: string (optional, for attribution),
 *   meta?: object (optional, custom metadata)
 * }
 *
 * Response:
 * {
 *   token: string,
 *   tokenId: string,
 *   expiresAt: string (ISO 8601),
 *   shareUrl: string (full URL with token)
 * }
 *
 * Note: In production, this endpoint should be protected
 * and only accessible by authenticated publishers.
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { articleSlug, url, expiresIn, maxUses, userId, meta } = body;

    // Validate required fields
    if (!articleSlug || typeof articleSlug !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid articleSlug" },
        { status: 400 },
      );
    }

    if (!expiresIn || typeof expiresIn !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid expiresIn (e.g., '24h', '7d')" },
        { status: 400 },
      );
    }

    // Generate the token
    // In the demo, all articles use the "premium" content name for encryption.
    // The contentId in the token must match the content name used during encryption
    // so the server can derive the correct period key for unlocking.
    // The articleSlug is stored in meta so the token carries the full context.
    const token = await getTokens().generate({
      contentId: "premium",
      url,
      expiresIn,
      maxUses,
      userId,
      meta: { ...meta, articleSlug },
    });

    // Extract token info for response
    const payload = await getTokens().peek(token);
    if (!payload) {
      return NextResponse.json(
        { error: "Failed to generate token" },
        { status: 500 },
      );
    }

    // Derive all downstream values from the token payload (source of truth)
    // so the share URL and audit records can never diverge from the token scope.
    const tokenContentId = payload.contentId;
    const metaSlug = payload.meta?.articleSlug;
    const tokenArticleSlug = typeof metaSlug === "string" ? metaSlug : articleSlug;
    const tokenUrl = payload.url;

    // Build share URL
    const baseUrl = request.headers.get("origin") || request.nextUrl.origin;
    const path = `/article/${tokenArticleSlug}`;
    const defaultUrl = `${baseUrl}${path}`;
    const targetUrl = tokenUrl || defaultUrl;
    const separator = targetUrl.includes("?") ? "&" : "?";
    const shareUrl = `${targetUrl}${separator}token=${encodeURIComponent(token)}`;

    // Log token generation for audit
    console.log(`[SHARE] Token generated`, {
      tokenId: payload.tid,
      issuer: payload.iss,
      keyId: payload.kid,
      contentId: tokenContentId,
      articleSlug: tokenArticleSlug,
      expiresIn,
      maxUses,
      userId,
      expiresAt: new Date(payload.exp * 1000).toISOString(),
    });

    return NextResponse.json({
      token,
      tokenId: payload.tid,
      issuer: payload.iss,
      keyId: payload.kid,
      contentId: tokenContentId,
      articleSlug: tokenArticleSlug,
      expiresAt: new Date(payload.exp * 1000).toISOString(),
      shareUrl,
    });
  } catch (error) {
    console.error("Share token generation error:", error);

    if (error instanceof Error) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }

    return NextResponse.json(
      { error: "Failed to generate share token" },
      { status: 500 },
    );
  }
}
