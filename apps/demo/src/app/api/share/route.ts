import { NextRequest, NextResponse } from "next/server";
import { createTokenManager } from "@sesamy/capsule-server";
import { TOKEN_SECRET } from "@/lib/capsule";

/**
 * Token manager for generating share tokens.
 */
const tokens = createTokenManager({
  secret: TOKEN_SECRET,
});

/**
 * POST /api/share
 *
 * Generate a pre-signed share token for content access.
 * Used by publishers to create shareable links.
 *
 * Request body:
 * {
 *   tier: string (e.g., "premium"),
 *   articleId?: string (optional, restrict to specific article),
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
    const { tier, articleId, expiresIn, maxUses, userId, meta } = body;

    // Validate required fields
    if (!tier || typeof tier !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid tier" },
        { status: 400 }
      );
    }

    if (!expiresIn || typeof expiresIn !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid expiresIn (e.g., '24h', '7d')" },
        { status: 400 }
      );
    }

    // Generate the token
    const token = tokens.generate({
      tier,
      articleId,
      expiresIn,
      maxUses,
      userId,
      meta,
    });

    // Extract token info for response
    const payload = tokens.peek(token);
    if (!payload) {
      return NextResponse.json(
        { error: "Failed to generate token" },
        { status: 500 }
      );
    }

    // Build share URL
    const baseUrl = request.headers.get("origin") || request.nextUrl.origin;
    const path = articleId ? `/article/${articleId}` : "/";
    const shareUrl = `${baseUrl}${path}?token=${encodeURIComponent(token)}`;

    // Log token generation for audit
    console.log(`[SHARE] Token generated`, {
      tokenId: payload.tid,
      tier,
      articleId,
      expiresIn,
      maxUses,
      userId,
      expiresAt: new Date(payload.exp * 1000).toISOString(),
    });

    return NextResponse.json({
      token,
      tokenId: payload.tid,
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
      { status: 500 }
    );
  }
}
