/**
 * Capsule Unlock API
 *
 * Receives client's public key and wrapped DEK, unwraps the DEK,
 * re-wraps it with the client's public key, and returns it.
 * 
 * Uses @sesamy/capsule-server for key management.
 */

import type { APIRoute } from "astro";
import type { UnlockResponse } from "@sesamy/capsule";
import { createSubscriptionServer } from "@sesamy/capsule-server";
import { BUCKET_PERIOD_SECONDS } from "../../lib/encryption";

/** Master secret for key derivation */
const MASTER_SECRET = import.meta.env.CAPSULE_MASTER_SECRET || 
  Buffer.from("demo-secret-do-not-use-in-production!!", "utf-8").toString("base64");

/**
 * Subscription server instance for handling unlock requests.
 */
const server = createSubscriptionServer(MASTER_SECRET, BUCKET_PERIOD_SECONDS);

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    const { keyId, wrappedDek, publicKey } = body;

    if (!publicKey || !keyId || !wrappedDek) {
      return new Response(
        JSON.stringify({ error: "Missing required fields: keyId, wrappedDek, publicKey" }), 
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // Use the subscription server to unlock
    // In production, you'd validate user subscription here first!
    const result = await server.unlockForUser(
      { keyId, wrappedDek },
      publicKey
    );

    // Build response matching UnlockResponse interface
    const response: UnlockResponse = {
      encryptedDek: result.encryptedDek,
      expiresAt: result.expiresAt,
      bucketId: result.bucketId,
      bucketPeriodSeconds: BUCKET_PERIOD_SECONDS,
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
