import { NextRequest, NextResponse } from "next/server";
import { getPublisher } from "@/lib/capsule";

// ---------------------------------------------------------------------------
// Auth – callers must present `Authorization: Bearer <SHARE_API_SECRET>`
// In development mode a hard-coded fallback is used when the env var is unset.
// ---------------------------------------------------------------------------

const DEV_FALLBACK_SHARE_SECRET = "demo-share-secret";

function getShareApiSecret(): string {
  const secret = process.env.SHARE_API_SECRET;
  if (secret) return secret;
  if (process.env.NODE_ENV === "development") {
    console.warn(
      "[share] SHARE_API_SECRET not set — using insecure demo fallback (dev only)",
    );
    return DEV_FALLBACK_SHARE_SECRET;
  }
  throw new Error("SHARE_API_SECRET environment variable is required in production");
}

function verifyBearer(request: NextRequest): NextResponse | null {
  const authHeader = request.headers.get("authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return NextResponse.json(
      { error: "Missing Authorization header. Expected: Bearer <SHARE_API_SECRET>" },
      { status: 401 },
    );
  }

  const token = authHeader.slice("Bearer ".length);
  const expected = getShareApiSecret();

  // Constant-time comparison to prevent timing attacks
  if (token.length !== expected.length) {
    return NextResponse.json({ error: "Invalid bearer token" }, { status: 403 });
  }
  let mismatch = 0;
  for (let i = 0; i < token.length; i++) {
    mismatch |= token.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  if (mismatch !== 0) {
    return NextResponse.json({ error: "Invalid bearer token" }, { status: 403 });
  }

  return null; // authorised
}

/**
 * POST /api/share
 *
 * Generate a share link token for a DCA-protected resource.
 *
 * **Requires** `Authorization: Bearer <SHARE_API_SECRET>`.
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
  // --- Authorization gate ---------------------------------------------------
  const authError = verifyBearer(request);
  if (authError) return authError;

  try {
    const body = await request.json();

    const resourceId = body.resourceId;
    if (!resourceId || typeof resourceId !== "string") {
      return NextResponse.json(
        { error: "resourceId is required" },
        { status: 400 },
      );
    }

    // --- Validate contentNames / keyNames ------------------------------------
    // Prefer keyNames if provided; fall back to contentNames for backwards compat
    const rawKeyNames: unknown = body.keyNames;
    const rawContentNames: unknown = body.contentNames;

    const isValidStringArray = (arr: unknown): arr is string[] =>
      Array.isArray(arr) &&
      arr.length > 0 &&
      arr.length <= 20 &&
      arr.every(
        (n: unknown) => typeof n === "string" && n.length > 0 && n.length <= 128,
      );

    const keyNames: string[] | undefined = rawKeyNames && isValidStringArray(rawKeyNames)
      ? rawKeyNames
      : undefined;
    const contentNames: string[] | undefined = rawContentNames && isValidStringArray(rawContentNames)
      ? rawContentNames
      : undefined;

    if (!keyNames && !contentNames) {
      return NextResponse.json(
        {
          error:
            "keyNames or contentNames must be an array of 1–20 non-empty strings (max 128 chars each)",
        },
        { status: 400 },
      );
    }

    // --- Validate expiresIn (seconds) ----------------------------------------
    const MAX_EXPIRES_IN = 30 * 24 * 3600; // 30 days
    const MIN_EXPIRES_IN = 60; // 1 minute
    const expiresIn: unknown = body.expiresIn ?? 7 * 24 * 3600; // default 7 days
    if (
      typeof expiresIn !== "number" ||
      !Number.isFinite(expiresIn) ||
      !Number.isInteger(expiresIn) ||
      expiresIn < MIN_EXPIRES_IN ||
      expiresIn > MAX_EXPIRES_IN
    ) {
      return NextResponse.json(
        {
          error: `expiresIn must be an integer between ${MIN_EXPIRES_IN} and ${MAX_EXPIRES_IN} seconds`,
        },
        { status: 400 },
      );
    }

    const publisher = await getPublisher();

    const token = await publisher.createShareLinkToken({
      resourceId,
      ...(keyNames ? { keyNames } : { contentNames: contentNames! }),
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
      ...(keyNames ? { keyNames } : { contentNames }),
    });
  } catch (error) {
    console.error("Share link creation error:", error);
    return NextResponse.json(
      { error: "Failed to create share link" },
      { status: 500 },
    );
  }
}
