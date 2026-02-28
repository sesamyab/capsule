import { NextResponse } from "next/server";
import { getConfig, getCurrentPeriod, getNextPeriod, getPeriodExpiration } from "@/lib/time-periods";

/**
 * GET /api/config
 * 
 * Returns the current Capsule configuration.
 * Useful for debugging and for clients to understand the current setup.
 */
export async function GET() {
  const config = getConfig();
  const currentPeriod = getCurrentPeriod();
  const nextPeriod = getNextPeriod();

  return NextResponse.json({
    keyExchange: {
      method: config.method,
      periodDurationSeconds: config.periodDurationSeconds,
      description: config.method === "period"
        ? "period mode: Keys derived locally using shared secret. Both CMS and subscription server must share the same secret."
        : "API mode: CMS fetches keys from subscription server. Server controls rotation period."
    },
    currentPeriod: {
      id: currentPeriod,
      counter: parseInt(currentPeriod), // Period counter (Unix seconds / period)
      expiresAt: getPeriodExpiration(currentPeriod).toISOString(),
      expiresIn: Math.round((getPeriodExpiration(currentPeriod).getTime() - Date.now()) / 1000) + " seconds",
      info: "Period counter = floor(Unix time / period). Used as HKDF input to derive AES key."
    },
    nextPeriod: {
      id: nextPeriod,
      counter: parseInt(nextPeriod),
      expiresAt: getPeriodExpiration(nextPeriod).toISOString()
    },
    environment: {
      hasCustomSecret: config.hasCustomSecret,
      envVars: {
        CAPSULE_KEY_METHOD: "Set to 'period' or 'api' (default: period)",
        CAPSULE_BUCKET_PERIOD: "Period duration in seconds (default: 30)",
        PERIOD_SECRET: "Base64-encoded shared secret (auto-generated if not set)"
      }
    }
  });
}
