/**
 * Capsule Unlock API
 *
 * Receives client's public key and wrapped content key, unwraps the content key,
 * re-wraps it with the client's public key, and returns it.
 *
 * Uses @sesamy/capsule-server for key management.
 */

import type { APIRoute } from "astro";
import type { UnlockResponse } from "@sesamy/capsule";
import { createSubscriptionServer } from "@sesamy/capsule-server";
import { PERIOD_DURATION_SECONDS, keyProvider } from "../../lib/encryption";

/** Period secret for key derivation */
function getPeriodSecret(): string {
  const secret = import.meta.env.CAPSULE_PERIOD_SECRET;
  if (secret) return secret;
  if (import.meta.env.DEV) {
    console.warn("[capsule] CAPSULE_PERIOD_SECRET not set — using insecure demo fallback (dev only)");
    return Buffer.from("demo-secret-do-not-use-in-production!!", "utf-8").toString("base64");
  }
  throw new Error("CAPSULE_PERIOD_SECRET environment variable is required in production");
}
const PERIOD_SECRET = getPeriodSecret();

/**
 * Subscription server instance for handling unlock requests.
 */
const server = createSubscriptionServer({
  periodSecret: PERIOD_SECRET,
  periodDurationSeconds: PERIOD_DURATION_SECONDS,
});

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    const { keyId, wrappedContentKey, publicKey } = body;

    if (!publicKey || !keyId || !wrappedContentKey) {
      return new Response(
        JSON.stringify({
          error: "Missing required fields: keyId, wrappedContentKey, publicKey",
        }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Use the subscription server to unlock
    // In production, you'd validate user subscription here first!

    // Static key lookup for article keys - derive from same period key provider as CMS
    const staticKeyLookup = async (id: string): Promise<Uint8Array | null> => {
      if (id.startsWith("article:")) {
        const contentId = id.slice(8);
        const keyEntry = await keyProvider.getArticleKey(contentId);
        if (keyEntry.key instanceof Uint8Array) {
          return keyEntry.key;
        }
        // Decode base64 string to Uint8Array
        const binaryString = atob(keyEntry.key);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
      }
      return null;
    };

    const result = await server.unlockForUser(
      { keyId, wrappedContentKey },
      publicKey,
      staticKeyLookup,
    );

    // Build response matching UnlockResponse interface
    const response: UnlockResponse = {
      encryptedContentKey: result.encryptedContentKey,
      expiresAt: result.expiresAt,
      periodId: result.periodId,
      periodDurationSeconds: PERIOD_DURATION_SECONDS,
    };

    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("Unlock error:", error);
    return new Response(
      JSON.stringify({ error: "Failed to process unlock request" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
};
