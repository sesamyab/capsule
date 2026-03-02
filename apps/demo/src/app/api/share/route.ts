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
 *   contentId: string (required, publisher's content ID),
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
    const { contentId, url, expiresIn, maxUses, userId, meta } = body;

    // Validate required fields
    if (!contentId || typeof contentId !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid contentId" },
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
    // In the demo, all articles use the "premium" tier for encryption.
    // The contentId in the token must match the tier used during encryption
    // so the server can derive the correct period key for unlocking.
    const token = await getTokens().generate({
      tier: "premium",
      contentId: "premium",
      url,
      expiresIn,
      maxUses,
      userId,
      meta,
    });

    // Extract token info for response
    const payload = await getTokens().peek(token);
    if (!payload) {
      return NextResponse.json(
        { error: "Failed to generate token" },
        { status: 500 },
      );
    }

    // Build share URL
    const baseUrl = request.headers.get("origin") || request.nextUrl.origin;
    const path = `/article/${contentId}`;
    const defaultUrl = `${baseUrl}${path}`;
    const targetUrl = url || defaultUrl;
    const separator = targetUrl.includes("?") ? "&" : "?";
    const shareUrl = `${targetUrl}${separator}token=${encodeURIComponent(token)}`;

    // Log token generation for audit
    console.log(`[SHARE] Token generated`, {
      tokenId: payload.tid,
      issuer: payload.iss,
      keyId: payload.kid,
      contentId,
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
      contentId: payload.contentId,
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
