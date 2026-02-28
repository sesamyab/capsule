/**
 * DCA Time Buckets — human-readable period labels and periodKey derivation.
 *
 * DCA uses YYMMDDTHH (hourly) or YYMMDDTHHMM (sub-hour) format for period labels.
 * These are bookkeeping only — the client and issuer never parse or validate them.
 *
 * periodKeys are derived via HKDF with contentName as salt, making them
 * content-specific by construction.
 */

import { hkdf, getRandomBytes, toBase64Url } from "./web-crypto";

/**
 * Format a Date into a DCA time bucket label.
 *
 * @param date - The date to format
 * @param subHour - If true, include minutes (YYMMDDTHHMM)
 * @returns Time bucket string, e.g., "251023T13" or "251023T1430"
 */
export function formatTimeBucket(date: Date, subHour = false): string {
  const yy = String(date.getUTCFullYear()).slice(2);
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(date.getUTCDate()).padStart(2, "0");
  const hh = String(date.getUTCHours()).padStart(2, "0");
  if (subHour) {
    const min = String(date.getUTCMinutes()).padStart(2, "0");
    return `${yy}${mm}${dd}T${hh}${min}`;
  }
  return `${yy}${mm}${dd}T${hh}`;
}

/**
 * Get the start of the current hour as a Date.
 */
function hourFloor(date: Date): Date {
  const d = new Date(date);
  d.setUTCMinutes(0, 0, 0);
  return d;
}

/**
 * Get the current and next time bucket labels.
 *
 * @param periodDurationHours - Period duration in hours (default: 1)
 * @param now - Current time (default: Date.now())
 * @returns Current and next bucket labels, plus their Date boundaries
 */
export function getCurrentTimeBuckets(
  periodDurationHours = 1,
  now: Date = new Date(),
): {
  current: { t: string; start: Date };
  next: { t: string; start: Date };
} {
  const currentStart = hourFloor(now);

  // Align to period boundary
  const hoursSinceEpoch = Math.floor(currentStart.getTime() / (3600_000));
  const periodHours = Math.max(1, Math.floor(periodDurationHours));
  const alignedHour = hoursSinceEpoch - (hoursSinceEpoch % periodHours);
  const alignedStart = new Date(alignedHour * 3600_000);
  const nextStart = new Date((alignedHour + periodHours) * 3600_000);

  return {
    current: { t: formatTimeBucket(alignedStart), start: alignedStart },
    next: { t: formatTimeBucket(nextStart), start: nextStart },
  };
}

/**
 * Derive a DCA periodKey using HKDF.
 *
 * HKDF parameters:
 *   IKM  = periodSecret
 *   salt = contentName (makes keys content-specific)
 *   info = "dca|" + timeBucket (e.g., "dca|251023T13")
 *   len  = 32 bytes (AES-256)
 *
 * @param periodSecret - Publisher's period secret
 * @param contentName - Content item name (HKDF salt)
 * @param timeBucket - Time bucket label (e.g., "251023T13")
 * @returns 32-byte AES-256 key
 */
export async function deriveDcaPeriodKey(
  periodSecret: Uint8Array,
  contentName: string,
  timeBucket: string,
): Promise<Uint8Array> {
  return hkdf(periodSecret, contentName, `dca|${timeBucket}`, 32);
}

/**
 * Generate a random renderId (base64url, minimum 11 characters / 8 bytes).
 */
export function generateRenderId(): string {
  return toBase64Url(getRandomBytes(16));
}
