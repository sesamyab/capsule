import { NextResponse } from "next/server";
import { getConfig, getCurrentBucket, getNextBucket, getBucketExpiration } from "@/lib/time-buckets";

/**
 * GET /api/config
 * 
 * Returns the current Capsule configuration.
 * Useful for debugging and for clients to understand the current setup.
 */
export async function GET() {
  const config = getConfig();
  const currentBucket = getCurrentBucket();
  const nextBucket = getNextBucket();
  
  return NextResponse.json({
    keyExchange: {
      method: config.method,
      bucketPeriodSeconds: config.bucketPeriodSeconds,
      description: config.method === "totp" 
        ? "TOTP mode: Keys derived locally using shared secret. Both CMS and subscription server must share the same secret."
        : "API mode: CMS fetches keys from subscription server. Server controls rotation period."
    },
    currentBucket: {
      id: currentBucket,
      counter: parseInt(currentBucket), // TOTP counter (Unix seconds / period)
      expiresAt: getBucketExpiration(currentBucket).toISOString(),
      expiresIn: Math.round((getBucketExpiration(currentBucket).getTime() - Date.now()) / 1000) + " seconds",
      info: "TOTP counter = floor(Unix time / period). Used as HKDF input to derive AES key."
    },
    nextBucket: {
      id: nextBucket,
      counter: parseInt(nextBucket),
      expiresAt: getBucketExpiration(nextBucket).toISOString()
    },
    environment: {
      hasCustomSecret: config.hasCustomSecret,
      envVars: {
        CAPSULE_KEY_METHOD: "Set to 'totp' or 'api' (default: totp)",
        CAPSULE_BUCKET_PERIOD: "Bucket period in seconds (default: 30)",
        CAPSULE_MASTER_SECRET: "Base64-encoded shared secret (auto-generated if not set)"
      }
    }
  });
}
