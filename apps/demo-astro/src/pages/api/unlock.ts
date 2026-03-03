/**
 * DCA Unlock API
 *
 * Receives a DCA unlock request, verifies the publisher JWT,
 * unseals period keys, and returns them to the client.
 */

import type { APIRoute } from "astro";
import { getIssuer } from "../../lib/encryption";

export const POST: APIRoute = async ({ request }) => {
  try {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return new Response(
        JSON.stringify({ error: "Invalid or missing JSON body" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    const issuer = await getIssuer();

    // Demo mode: grant access to all sealed content items
    const grantedContentNames = Object.keys(
      (body as Record<string, unknown>).sealed as Record<string, unknown> ?? {},
    );

    const result = await issuer.unlock(body as any, {
      grantedContentNames,
      deliveryMode: "periodKey",
    });

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("[dca] Unlock error:", error);
    const message = error instanceof Error ? error.message : "Internal server error";
    return new Response(
      JSON.stringify({ error: message }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
};
