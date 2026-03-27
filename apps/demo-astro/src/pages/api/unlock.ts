/**
 * DCA Unlock API
 *
 * Receives a DCA unlock request, verifies the publisher JWT,
 * unseals period keys, and returns them to the client.
 *
 * Supports both v1 and v2 request formats:
 *
 * **v1 (current):** All fields present — resource, resourceJWT, issuerJWT,
 * sealed, keyId, issuerName, plus optional clientPublicKey and shareToken.
 *
 * **v2 (beta):** Only resourceJWT and contentKeys are required.
 * The issuerJWT, keyId, resource, and issuerName are dropped.
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

import type { APIRoute } from "astro";
import type { DcaUnlockRequest } from "@sesamy/capsule-server";
import { getIssuer } from "../../lib/encryption";
import { articles } from "../../lib/articles";

export const POST: APIRoute = async ({ request }) => {
  try {
    let body: DcaUnlockRequest;
    try {
      body = await request.json();
    } catch {
      return new Response(
        JSON.stringify({ error: "Invalid or missing JSON body" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // Basic validation — v2 requires resourceJWT + contentKeys; v1 sends sealed
    if (!body.resourceJWT || (!body.contentKeys && !body.sealed)) {
      return new Response(
        JSON.stringify({ error: "Invalid DCA unlock request — missing required fields (resourceJWT, contentKeys)" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    const issuer = await getIssuer();

    // Share link token flow: the token IS the access decision
    if (body.shareToken) {
      const result = await issuer.unlockWithShareToken(body, {
        deliveryMode: "contentKey",
        onShareToken: (payload) => {
          const scope = payload.keyNames
            ? `keyNames=[${payload.keyNames.join(",")}]`
            : `content=[${(payload.contentNames ?? []).join(",")}]`;
          console.log(
            `[share-link] Granting access via share token: resource=${payload.resourceId}, ` +
            `${scope}, jti=${payload.jti ?? "none"}`,
          );
        },
      });

      return new Response(JSON.stringify(result), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    // ── Access decision ────────────────────────────────────────────────
    // IMPORTANT: Derive scope from the *verified* resource (server-side),
    // NOT from untrusted client fields (body.contentKeys / body.contentKeyMap).
    // In v2 there is no issuerJWT integrity proof, so the client could
    // inflate contentKeyMap/contentKeys to widen the scope the issuer unseals.
    //
    // 1. Verify the request JWTs to get the trusted resource.
    // 2. Look up the article server-side to determine the entitled tier.
    // 3. Pass only the server-authorised scope to issuer.unlock().
    const { resource } = await issuer.verify(body);
    const article = articles[resource.resourceId];
    if (!article) {
      return new Response(
        JSON.stringify({ error: `Unknown resource: "${resource.resourceId}"` }),
        { status: 404, headers: { "Content-Type": "application/json" } },
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

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("[dca] Unlock error:", error);

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
        return new Response(
          JSON.stringify({ error: error.message }),
          { status: 403, headers: { "Content-Type": "application/json" } },
        );
      }
      if (
        error.message.includes("missing") ||
        error.message.includes("invalid") ||
        error.message.includes("malformed")
      ) {
        return new Response(
          JSON.stringify({ error: error.message }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      }
    }

    return new Response(
      JSON.stringify({ error: "Failed to process DCA unlock request" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
};
