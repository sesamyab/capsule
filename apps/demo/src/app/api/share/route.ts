import { NextRequest, NextResponse } from "next/server";
import { getPublisher } from "@/lib/capsule";

/**
 * POST /api/share
 *
 * Generate a share link token for a DCA-protected resource.
 *
 * The publisher creates a signed JWT (ES256) that grants pre-authenticated
 * access to the specified content items. This token can be included in a
 * URL query parameter (e.g., ?share=<token>) and the client will send it
 * with the unlock request.
 *
 * DCA-compatible: the periodSecret never leaves the publisher.
 * The share token is purely an authorization grant — key material flows
 * through the normal DCA seal/unseal channel.
 *
 * Request body:
 *   - resourceId: string — which resource to share
 *   - contentNames: string[] — which content items to grant (e.g., ["TierA"])
 *   - expiresIn: number — token lifetime in seconds (default: 7 days)
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    const resourceId = body.resourceId;
    if (!resourceId || typeof resourceId !== "string") {
      return NextResponse.json(
        { error: "resourceId is required" },
        { status: 400 },
      );
    }

    const contentNames = body.contentNames ?? ["TierA"];
    const expiresIn = body.expiresIn ?? 7 * 24 * 3600; // 7 days

    const publisher = await getPublisher();

    const token = await publisher.createShareLinkToken({
      resourceId,
      contentNames,
      expiresIn,
      data: body.data,
    });

    // Build the share URL
    const origin = request.nextUrl.origin;
    const shareUrl = `${origin}/article/${encodeURIComponent(resourceId)}?share=${encodeURIComponent(token)}`;

    return NextResponse.json({
      token,
      shareUrl,
      expiresIn,
      resourceId,
      contentNames,
    });
  } catch (error) {
    console.error("Share link creation error:", error);
    return NextResponse.json(
      { error: "Failed to create share link" },
      { status: 500 },
    );
  }
}
