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

import type { APIRoute } from "astro";
import type { DcaUnlockRequest } from "@sesamy/capsule-server";
import { getIssuer } from "../../lib/encryption";

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

    // Basic validation — v2 only requires resourceJWT, sealed, keyId
    if (!body.resourceJWT || !body.sealed) {
      return new Response(
        JSON.stringify({ error: "Invalid DCA unlock request — missing required fields (resourceJWT, sealed)" }),
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

    // Normal unlock flow: choose delivery mode based on accessType
    // accessType: "article" → contentKey (one-time, non-cacheable)
    //             "tier" or "subscription" → periodKey (cacheable for 1 hour)
    const accessType = (body as unknown as Record<string, unknown>).accessType as string | undefined;
    const deliveryMode = accessType === "article" ? "contentKey" : "periodKey";

    // Resolve access grant: if contentKeyMap is present (v2 keyName mode),
    // grant by keyName so the issuer resolves which content items to unseal.
    // Otherwise fall back to granting all sealed content names directly.
    const hasKeyNames = body.contentKeyMap && Object.keys(body.contentKeyMap).length > 0;
    const grantedKeyNames = hasKeyNames
      ? Array.from(new Set(Object.values(body.contentKeyMap!)))
      : undefined;
    const grantedContentNames = hasKeyNames ? undefined : Object.keys(body.sealed);

    console.log(
      `[unlock] accessType=${accessType ?? "default"}, deliveryMode=${deliveryMode}, ` +
      `${grantedKeyNames ? `keyNames=[${grantedKeyNames.join(",")}]` : `content=[${grantedContentNames!.join(",")}]`}`,
    );

    const result = await issuer.unlock(body, {
      grantedContentNames,
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
