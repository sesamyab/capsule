/**
 * Time-period key derivation using HKDF.
 *
 * Derives deterministic AES-256 keys from a period secret and time period ID.
 * Keys rotate every `periodDurationSeconds` (default: 30 seconds).
 * Uses Web Crypto API for cross-platform compatibility.
 */

import {
  hkdf,
  getRandomBytes,
} from "./web-crypto";
import type { PeriodKey } from "./types";

/** Default period duration in seconds */
export const DEFAULT_PERIOD_DURATION_SECONDS = 30;

// Re-export HKDF for any consumers that need it
export { hkdf };

/**
 * Validate that periodDurationSeconds is a positive finite number.
 * @throws if the value is zero, negative, NaN, or Infinity.
 */
function validatePeriodDuration(periodDurationSeconds: number): void {
  if (
    !Number.isFinite(periodDurationSeconds) ||
    periodDurationSeconds <= 0
  ) {
    throw new RangeError(
      `periodDurationSeconds must be a positive finite number, got ${periodDurationSeconds}`,
    );
  }
}

/**
 * Get the period ID for a given timestamp.
 */
export function getPeriodId(
  timestampMs: number = Date.now(),
  periodDurationSeconds: number = DEFAULT_PERIOD_DURATION_SECONDS,
): string {
  validatePeriodDuration(periodDurationSeconds);
  const timestampSec = Math.floor(timestampMs / 1000);
  const periodNum = Math.floor(timestampSec / periodDurationSeconds);
  return periodNum.toString();
}

/**
 * Get the current period ID.
 */
export function getCurrentPeriod(
  periodDurationSeconds: number = DEFAULT_PERIOD_DURATION_SECONDS,
): string {
  return getPeriodId(Date.now(), periodDurationSeconds);
}

/**
 * Get the next period ID.
 */
export function getNextPeriod(
  periodDurationSeconds: number = DEFAULT_PERIOD_DURATION_SECONDS,
): string {
  return getPeriodId(Date.now() + periodDurationSeconds * 1000, periodDurationSeconds);
}

/**
 * Get the previous period ID.
 */
export function getPreviousPeriod(
  periodDurationSeconds: number = DEFAULT_PERIOD_DURATION_SECONDS,
): string {
  return getPeriodId(Date.now() - periodDurationSeconds * 1000, periodDurationSeconds);
}

/**
 * Get when a period expires.
 */
export function getPeriodExpiration(
  periodId: string,
  periodDurationSeconds: number = DEFAULT_PERIOD_DURATION_SECONDS,
): Date {
  validatePeriodDuration(periodDurationSeconds);
  if (!/^-?\d+$/.test(periodId)) {
    throw new Error(`Invalid periodId: "${periodId}"`);
  }
  const periodNum = Number(periodId);
  if (!Number.isSafeInteger(periodNum)) {
    throw new Error(`periodId out of safe integer range: "${periodId}"`);
  }
  const expiresAtMs = (periodNum + 1) * periodDurationSeconds * 1000;
  if (!Number.isFinite(expiresAtMs)) {
    throw new RangeError(
      `Computed expiration overflows for periodId "${periodId}" with periodDurationSeconds ${periodDurationSeconds}`,
    );
  }
  return new Date(expiresAtMs);
}

/**
 * Check if a period is currently valid (current, next, or previous for grace period).
 *
 * Uses a single timestamp snapshot to avoid period rollover races.
 */
export function isPeriodValid(
  periodId: string,
  periodDurationSeconds: number = DEFAULT_PERIOD_DURATION_SECONDS,
): boolean {
  const now = Date.now();
  const current = getPeriodId(now, periodDurationSeconds);
  const next = getPeriodId(now + periodDurationSeconds * 1000, periodDurationSeconds);
  const previous = getPeriodId(now - periodDurationSeconds * 1000, periodDurationSeconds);
  return periodId === current || periodId === next || periodId === previous;
}

/**
 * Derive a period key from period secret + period ID using HKDF.
 *
 * @param periodSecret - The period secret (256-bit)
 * @param keyId - The key identifier (e.g., content ID like "premium")
 * @param periodId - The period identifier
 * @returns 256-bit AES key
 */
export async function derivePeriodKey(
  periodSecret: Uint8Array,
  keyId: string,
  periodId: string,
): Promise<Uint8Array> {
  const info = `capsule-period-${keyId}`;
  return hkdf(periodSecret, periodId, info, 32);
}

/**
 * Get period key with metadata.
 */
export async function getPeriodKey(
  periodSecret: Uint8Array,
  keyId: string,
  periodId: string,
  periodDurationSeconds: number = DEFAULT_PERIOD_DURATION_SECONDS,
): Promise<PeriodKey> {
  return {
    periodId,
    key: await derivePeriodKey(periodSecret, keyId, periodId),
    expiresAt: getPeriodExpiration(periodId, periodDurationSeconds),
  };
}

/**
 * Get current and next period keys for a key ID.
 * Used by CMS to wrap content keys for both time windows.
 *
 * Uses a single timestamp snapshot to avoid period rollover races.
 */
export async function getPeriodKeys(
  periodSecret: Uint8Array,
  keyId: string,
  periodDurationSeconds: number = DEFAULT_PERIOD_DURATION_SECONDS,
): Promise<{ current: PeriodKey; next: PeriodKey }> {
  const now = Date.now();
  const currentPeriodId = getPeriodId(now, periodDurationSeconds);
  const nextPeriodId = getPeriodId(now + periodDurationSeconds * 1000, periodDurationSeconds);

  const [current, next] = await Promise.all([
    getPeriodKey(periodSecret, keyId, currentPeriodId, periodDurationSeconds),
    getPeriodKey(periodSecret, keyId, nextPeriodId, periodDurationSeconds),
  ]);

  return { current, next };
}

/**
 * Generate a new period secret (256-bit random).
 */
export function generatePeriodSecret(): Uint8Array {
  return getRandomBytes(32);
}
