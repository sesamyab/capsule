/**
 * Time-period utilities for the demo app.
 * 
 * Re-exports from @sesamy/capsule-server with some demo-specific wrappers.
 */

import { timingSafeEqual } from "crypto";
import {
  derivePeriodKey as derivePeriodKeyBase,
  getCurrentPeriod as getCurrentPeriodBase,
  getNextPeriod as getNextPeriodBase,
  getPreviousPeriod as getPreviousPeriodBase,
  getPeriodExpiration as getPeriodExpirationBase,
  getPeriodId,
  isPeriodValid as isPeriodValidBase,
  DEFAULT_PERIOD_DURATION_SECONDS,
} from "@sesamy/capsule-server";

/**
 * Configuration from environment variables
 */
export type KeyDerivationMethod = "period" | "api";

/** Key exchange method: "period" (default) or "api" */
export const KEY_EXCHANGE_METHOD: KeyDerivationMethod =
  (process.env.CAPSULE_KEY_METHOD as KeyDerivationMethod) || "period";

/** Period duration in seconds (default: 30 seconds) */
export const PERIOD_DURATION_SECONDS = parseInt(
  process.env.CAPSULE_BUCKET_PERIOD || "30",
  10
);

/** Period duration in milliseconds */
export const PERIOD_DURATION_MS = PERIOD_DURATION_SECONDS * 1000;

/**
 * Period secret for deriving period keys.
 * In production, store this in KMS (AWS Secrets Manager, Google Secret Manager, etc.)
 */
export const PERIOD_SECRET = process.env.PERIOD_SECRET
  ? Buffer.from(process.env.PERIOD_SECRET, "base64")
  : (() => {
    const { randomBytes } = require("crypto");
    const secret = randomBytes(32);
    console.log("[Capsule] Generated demo secret:", secret.toString("base64"));
    console.log("[Capsule] Key method:", KEY_EXCHANGE_METHOD);
    console.log("[Capsule] Period duration:", PERIOD_DURATION_SECONDS, "seconds");
    return secret;
  })();

/** Export for client display */
export function getConfig() {
  return {
    method: KEY_EXCHANGE_METHOD,
    periodDurationSeconds: PERIOD_DURATION_SECONDS,
    hasCustomSecret: !!process.env.PERIOD_SECRET
  };
}

/**
 * Get the current time period ID.
 * Uses seconds-based calculation.
 */
export function getCurrentPeriod(): string {
  return getCurrentPeriodBase(PERIOD_DURATION_SECONDS);
}

/**
 * Get the next time period ID.
 */
export function getNextPeriod(): string {
  return getNextPeriodBase(PERIOD_DURATION_SECONDS);
}

/**
 * Get the previous time period ID.
 */
export function getPreviousPeriod(): string {
  return getPreviousPeriodBase(PERIOD_DURATION_SECONDS);
}

/**
 * Get when a period expires.
 */
export function getPeriodExpiration(periodId: string): Date {
  return getPeriodExpirationBase(periodId, PERIOD_DURATION_SECONDS);
}

/**
 * Check if a period is still valid (current, next, or previous for grace period).
 */
export function isPeriodValid(periodId: string): boolean {
  return isPeriodValidBase(periodId, PERIOD_DURATION_SECONDS);
}

/**
 * Derive a time-period key for a specific content ID and period.
 * 
 * @param contentId - Content ID (e.g., "premium", "basic")
 * @param periodId - Time period identifier
 * @returns 256-bit AES key material
 */
export async function derivePeriodKey(contentId: string, periodId: string): Promise<Uint8Array> {
  return derivePeriodKeyBase(PERIOD_SECRET, contentId, periodId);
}

/**
 * Get period keys for current and next time windows.
 */
export async function getCurrentPeriodKeys(contentId: string): Promise<{
  current: { periodId: string; key: Uint8Array; expiresAt: Date };
  next: { periodId: string; key: Uint8Array; expiresAt: Date };
}> {
  const currentPeriod = getCurrentPeriod();
  const nextPeriod = getNextPeriod();

  return {
    current: {
      periodId: currentPeriod,
      key: await derivePeriodKey(contentId, currentPeriod),
      expiresAt: getPeriodExpiration(currentPeriod)
    },
    next: {
      periodId: nextPeriod,
      key: await derivePeriodKey(contentId, nextPeriod),
      expiresAt: getPeriodExpiration(nextPeriod)
    }
  };
}

/**
 * Constant-time string comparison to prevent timing attacks.
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// Re-export defaults
export { DEFAULT_PERIOD_DURATION_SECONDS, getPeriodId };
