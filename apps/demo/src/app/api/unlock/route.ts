import { NextRequest, NextResponse } from "next/server";
import { getIssuer } from "@/lib/capsule";
import type { DcaUnlockRequest } from "@sesamy/capsule-server";

/**
 * POST /api/unlock
 *
 * DCA unlock endpoint. The client sends a DCA unlock request containing:
 * - resource: unsigned resource metadata (for key lookup)
 * - resourceJWT: ES256-signed resource JWT
 * - issuerJWT: ES256-signed integrity proof for this issuer's sealed blobs
 * - sealed: sealed contentKeys and periodKeys for this issuer
 * - keyId: identifies which issuer private key to use
 * - issuerName: this issuer's canonical name
 * - clientPublicKey (optional): RSA-OAEP public key for client-bound transport
 * - shareToken (optional): Publisher-signed share link token for pre-authenticated access
 *
 * The issuer:
 * 1. Verifies the publisher's JWT signatures against the trusted-publisher allowlist
 * 2. Verifies issuerJWT integrity proofs (SHA-256 of sealed blobs)
 * 3. Makes an access decision:
 *    - If shareToken is present: validates the publisher-signed token and grants
 *      access to the content names specified in the token
 *    - Otherwise: makes a normal access decision (in demo: always grant)
 * 4. Unseals and returns contentKeys or periodKeys
 */
export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as DcaUnlockRequest;

    // Basic validation
    if (!body.resource || !body.resourceJWT || !body.issuerJWT || !body.sealed) {
      return NextResponse.json(
        { error: "Invalid DCA unlock request — missing required fields" },
        { status: 400 },
      );
    }

    const issuer = await getIssuer();

    // Share link token flow: the token IS the access decision
    if (body.shareToken) {
      const result = await issuer.unlockWithShareToken(body, {
        deliveryMode: "contentKey",
        onShareToken: (payload) => {
          // In production, you would check use counts, audit log, etc.
          console.log(
            `[share-link] Granting access via share token: resource=${payload.resourceId}, ` +
            `content=[${payload.contentNames.join(",")}], jti=${payload.jti ?? "none"}`,
          );
        },
      });

      return NextResponse.json(result);
    }

    // Normal unlock flow: choose delivery mode based on accessType
    const grantedContentNames = Object.keys(body.sealed);

    // accessType: "article" → contentKey (one-time, non-cacheable)
    //             "tier" or "subscription" → periodKey (cacheable for 1 hour)
    const accessType = (body as unknown as unknown as Record<string, unknown>).accessType as string | undefined;
    const deliveryMode = accessType === "article" ? "contentKey" : "periodKey";

    console.log(
      `[unlock] accessType=${accessType ?? "default"}, deliveryMode=${deliveryMode}, ` +
      `content=[${grantedContentNames.join(",")}]`,
    );

    const result = await issuer.unlock(body, {
      grantedContentNames,
      deliveryMode,
    });

    return NextResponse.json(result);
  } catch (error) {
    console.error("DCA unlock error:", error);

    if (error instanceof Error) {
      // Surface verification/auth errors as 4xx
      if (
        error.message.includes("not trusted") ||
        error.message.includes("signature") ||
        error.message.includes("verification failed") ||
        error.message.includes("integrity") ||
        error.message.includes("domain") ||
        error.message.includes("Share token") ||
        error.message.includes("expired")
      ) {
        return NextResponse.json(
          { error: error.message },
          { status: 403 },
        );
      }
      if (
        error.message.includes("missing") ||
        error.message.includes("invalid") ||
        error.message.includes("malformed")
      ) {
        return NextResponse.json(
          { error: error.message },
          { status: 400 },
        );
      }
    }

    return NextResponse.json(
      { error: "Failed to process DCA unlock request" },
      { status: 500 },
    );
  }
}
