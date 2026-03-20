import { NextRequest, NextResponse } from "next/server";
import { getIssuer } from "@/lib/capsule";
import type { DcaUnlockRequest } from "@sesamy/capsule-server";
import { articles } from "@/lib/articles";

/**
 * POST /api/unlock
 *
 * DCA unlock endpoint. Supports both v1 and v2 request formats:
 *
 * **v1 (current):** All fields present — resource, resourceJWT, issuerJWT,
 * sealed, keyId, issuerName, plus optional clientPublicKey and shareToken.
 *
 * **v2 (beta):** Only resourceJWT, sealed, and keyId are required.
 * The issuerJWT is dropped — AES-GCM provides sealed-blob integrity.
 * The service auto-detects the format.
 *
 * The issuer:
 * 1. Verifies the publisher's JWT signature against the trusted-publisher allowlist
 * 2. v1 only: Verifies issuerJWT integrity proofs (SHA-256 of sealed blobs)
 * 3. Makes an access decision:
 *    - If shareToken is present: validates the publisher-signed token and grants
 *      access to the content names specified in the token
 *    - Otherwise: makes a normal access decision (in demo: always grant)
 * 4. Unseals and returns contentKeys or periodKeys
 */
export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as DcaUnlockRequest;

    // Basic validation — v2 only requires resourceJWT, sealed, keyId
    if (!body.resourceJWT || !body.sealed) {
      return NextResponse.json(
        { error: "Invalid DCA unlock request — missing required fields (resourceJWT, sealed)" },
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
          const scope = payload.keyNames
            ? `keyNames=[${payload.keyNames.join(",")}]`
            : `content=[${(payload.contentNames ?? []).join(",")}]`;
          console.log(
            `[share-link] Granting access via share token: resource=${payload.resourceId}, ` +
            `${scope}, jti=${payload.jti ?? "none"}`,
          );
        },
      });

      return NextResponse.json(result);
    }

    // ── Access decision ────────────────────────────────────────────────
    // IMPORTANT: Derive scope from the *verified* resource (server-side),
    // NOT from untrusted client fields (body.sealed / body.contentKeyMap).
    // In v2 there is no issuerJWT integrity proof, so the client could
    // inflate contentKeyMap/sealed to widen the scope the issuer unseals.
    //
    // 1. Verify the request JWTs to get the trusted resource.
    // 2. Look up the article server-side to determine the entitled tier.
    // 3. Pass only the server-authorised scope to issuer.unlock().
    const { resource } = await issuer.verify(body);
    const article = articles[resource.resourceId];
    if (!article) {
      return NextResponse.json(
        { error: `Unknown resource: "${resource.resourceId}"` },
        { status: 404 },
      );
    }

    // The article's tier is the server-side source of truth for key scope.
    // In production this would come from a subscription/entitlement check.
    const grantedKeyNames = [article.tier];

    // accessType: "article" → contentKey (one-time, non-cacheable)
    //             "tier" or "subscription" → periodKey (cacheable for 1 hour)
    const accessType = (body as unknown as Record<string, unknown>).accessType as string | undefined;
    const deliveryMode = accessType === "article" ? "contentKey" : "periodKey";

    console.log(
      `[unlock] resource=${resource.resourceId}, tier=${article.tier}, ` +
      `deliveryMode=${deliveryMode}, grantedKeyNames=[${grantedKeyNames.join(",")}]`,
    );

    const result = await issuer.unlock(body, {
      grantedKeyNames,
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
