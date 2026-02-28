import { NextRequest, NextResponse } from "next/server";
import { authenticateCmsRequest } from "@/lib/auth";
import { getCurrentPeriodKeys, getConfig } from "@/lib/time-periods";

/**
 * POST /api/cms/period-keys
 *
 * CMS endpoint to fetch current time-period keys for encryption.
 * Supports both API Key and JWT authentication.
 *
 * Note: In period mode, CMS can derive keys locally and doesn't need this endpoint.
 * This endpoint is provided for API-mode or for CMS implementations that prefer
 * fetching keys rather than deriving them.
 *
 * Request:
 * - Headers: Authorization: Bearer <api-key or jwt>
 * - Body: { contentId: string }
 *
 * Response:
 * {
 *   contentId: string,
 *   method: "period" | "api",
 *   periodDurationSeconds: number,
 *   current: {
 *     periodId: string,
 *     key: string (base64),
 *     expiresAt: string (ISO 8601)
 *   },
 *   next: {
 *     periodId: string,
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
    const { contentId } = body;

    if (!contentId || typeof contentId !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid contentId" },
        { status: 400 }
      );
    }

    // Get current period keys
    const { current, next } = await getCurrentPeriodKeys(contentId);
    const config = getConfig();

    // Helper to convert Uint8Array to base64
    const toBase64 = (bytes: Uint8Array) => {
      let binary = '';
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    };

    // Return keys to CMS
    return NextResponse.json({
      contentId,
      method: config.method,
      periodDurationSeconds: config.periodDurationSeconds,
      current: {
        periodId: current.periodId,
        key: toBase64(current.key),
        expiresAt: current.expiresAt.toISOString(),
      },
      next: {
        periodId: next.periodId,
        key: toBase64(next.key),
        expiresAt: next.expiresAt.toISOString(),
      },
      authenticatedWith: authResult.method,
      cmsId: authResult.cmsId,
    });
  } catch (error) {
    console.error("Period keys error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * GET /api/cms/period-keys
 *
 * Returns the current key exchange configuration (no auth required).
 * Useful for CMS to determine which method to use.
 */
export async function GET() {
  const config = getConfig();

  return NextResponse.json({
    method: config.method,
    periodDurationSeconds: config.periodDurationSeconds,
    description:
      config.method === "period"
        ? "period mode: CMS should derive keys locally using shared secret"
        : "API mode: CMS should fetch keys from this endpoint",
  });
}
