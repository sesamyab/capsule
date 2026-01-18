import { NextRequest, NextResponse } from "next/server";
import { authenticateCmsRequest } from "@/lib/auth";
import { getCurrentBucketKeys, getConfig } from "@/lib/time-buckets";

/**
 * POST /api/cms/bucket-keys
 *
 * CMS endpoint to fetch current time-bucket keys for encryption.
 * Supports both API Key and JWT authentication.
 *
 * Note: In TOTP mode, CMS can derive keys locally and doesn't need this endpoint.
 * This endpoint is provided for API-mode or for CMS implementations that prefer
 * fetching keys rather than deriving them.
 *
 * Request:
 * - Headers: Authorization: Bearer <api-key or jwt>
 * - Body: { tier: string }
 *
 * Response:
 * {
 *   tier: string,
 *   method: "totp" | "api",
 *   bucketPeriodSeconds: number,
 *   current: {
 *     bucketId: string,
 *     key: string (base64),
 *     expiresAt: string (ISO 8601)
 *   },
 *   next: {
 *     bucketId: string,
 *     key: string (base64),
 *     expiresAt: string (ISO 8601)
 *   }
 * }
 */
export async function POST(request: NextRequest) {
  try {
    // Authenticate CMS request
    const authorization = request.headers.get("authorization") || undefined;
    const authResult = authenticateCmsRequest(authorization);

    if (!authResult.authenticated) {
      return NextResponse.json(
        { error: "Unauthorized - Invalid or missing authentication" },
        { status: 401 }
      );
    }

    // Parse request body
    const body = await request.json();
    const { tier } = body;

    if (!tier || typeof tier !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid tier" },
        { status: 400 }
      );
    }

    // Get current bucket keys
    const { current, next } = getCurrentBucketKeys(tier);
    const config = getConfig();

    // Return keys to CMS
    return NextResponse.json({
      tier,
      method: config.method,
      bucketPeriodSeconds: config.bucketPeriodSeconds,
      current: {
        bucketId: current.bucketId,
        key: current.key.toString("base64"),
        expiresAt: current.expiresAt.toISOString(),
      },
      next: {
        bucketId: next.bucketId,
        key: next.key.toString("base64"),
        expiresAt: next.expiresAt.toISOString(),
      },
      authenticatedWith: authResult.method,
      cmsId: authResult.cmsId,
    });
  } catch (error) {
    console.error("Bucket keys error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * GET /api/cms/bucket-keys
 *
 * Returns the current key exchange configuration (no auth required).
 * Useful for CMS to determine which method to use.
 */
export async function GET() {
  const config = getConfig();

  return NextResponse.json({
    method: config.method,
    bucketPeriodSeconds: config.bucketPeriodSeconds,
    description:
      config.method === "totp"
        ? "TOTP mode: CMS should derive keys locally using shared secret"
        : "API mode: CMS should fetch keys from this endpoint",
  });
}
