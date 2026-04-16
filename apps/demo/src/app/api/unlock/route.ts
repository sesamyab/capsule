import { NextRequest, NextResponse } from "next/server";
import { getIssuer } from "@/lib/capsule";
import type { DcaUnlockRequest } from "@sesamy/capsule-server";
import { articles } from "@/lib/articles";

/**
 * POST /api/unlock
 *
 * DCA unlock endpoint. Requires resourceJWT and keys.
 *
 * The issuer:
 * 1. Verifies the publisher's JWT signature against the trusted-publisher allowlist
 * 2. Makes an access decision:
 *    - If shareToken is present: validates the publisher-signed token and grants
 *      access to the content names specified in the token
 *    - Otherwise: makes a normal access decision (in demo: always grant)
 * 3. Unwraps and returns contentKeys or wrapKeys
 */
export async function POST(request: NextRequest) {
  try {
    const body = (await request.json()) as DcaUnlockRequest;

    if (
      !body.resourceJWT ||
      !Array.isArray(body.keys) ||
      body.keys.some(
        (k: unknown) =>
          typeof k !== "object" || k === null || typeof (k as Record<string, unknown>).contentKey !== "string",
      )
    ) {
      return NextResponse.json(
        { error: "Invalid DCA unlock request — missing required fields (resourceJWT, keys)" },
        { status: 400 },
      );
    }

    const issuer = await getIssuer();

    // Share link token flow: the token IS the access decision
    if (body.shareToken) {
      const result = await issuer.unlockWithShareToken(body, {
        deliveryMode: "direct",
        onShareToken: (payload) => {
          const scope = payload.scopes
            ? `scopes=[${payload.scopes.join(",")}]`
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
    // NOT from untrusted client fields. scope on each entry is AAD-bound
    // (tampering causes unwrap failure), but the issuer should still
    // determine the granted scope from its own data.
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
    const grantedScopes = [article.tier];

    // accessType: "article" → direct contentKey (one-time, non-cacheable)
    //             "tier" or "subscription" → wrapKey (cacheable for one rotation)
    const accessType = (body as unknown as Record<string, unknown>).accessType as string | undefined;
    const deliveryMode = accessType === "article" ? "direct" : "wrapKey";

    console.log(
      `[unlock] resource=${resource.resourceId}, tier=${article.tier}, ` +
      `deliveryMode=${deliveryMode}, grantedScopes=[${grantedScopes.join(",")}]`,
    );

    const result = await issuer.unlock(body, {
      grantedScopes,
      deliveryMode,
    });

    return NextResponse.json(result);
  } catch (error) {
    console.error("DCA unlock error:", error);

    if (error instanceof Error) {
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
