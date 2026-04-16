/**
 * DCA Rotation — wrapKey identifiers (kid) and wrapKey derivation.
 *
 * Each wrapKey is identified by a `kid` string and derived deterministically
 * from `HKDF(rotationSecret, scope, kid)`. The publisher is stateless: given
 * the same inputs, it re-derives the same wrapKey.
 *
 * The kid has no required semantic meaning to the client or issuer — it's an
 * opaque identifier. The default kid generator uses a time-based label
 * (YYMMDDTHH) so rotation happens on a predictable cadence, but publishers
 * can adopt any rotation policy that produces distinct kids.
 */

import { hkdf, getRandomBytes, toBase64Url } from "./web-crypto";

/**
 * Format a Date into a time-based kid label (YYMMDDTHH or YYMMDDTHHMM).
 *
 * @param date - The date to format
 * @param subHour - If true, include minutes (YYMMDDTHHMM)
 * @returns kid string, e.g., "251023T13" or "251023T1430"
 */
export function formatTimeKid(date: Date, subHour = false): string {
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
 * Get the current and next kid labels for time-based rotation.
 *
 * @param rotationIntervalHours - Interval in hours (default: 1)
 * @param now - Current time (default: Date.now())
 * @returns Current and next kid labels, plus their Date boundaries
 */
export function getCurrentRotationVersions(
  rotationIntervalHours = 1,
  now: Date = new Date(),
): {
  current: { kid: string; start: Date };
  next: { kid: string; start: Date };
} {
  const currentStart = hourFloor(now);

  const hoursSinceEpoch = Math.floor(currentStart.getTime() / (3600_000));
  const intervalHours = Math.max(1, Math.floor(rotationIntervalHours));
  const alignedHour = hoursSinceEpoch - (hoursSinceEpoch % intervalHours);
  const alignedStart = new Date(alignedHour * 3600_000);
  const nextStart = new Date((alignedHour + intervalHours) * 3600_000);

  return {
    current: { kid: formatTimeKid(alignedStart), start: alignedStart },
    next: { kid: formatTimeKid(nextStart), start: nextStart },
  };
}

/**
 * Derive a DCA wrapKey using HKDF.
 *
 * HKDF parameters:
 *   IKM  = rotationSecret
 *   salt = scope (makes keys scope-specific — shared across content items in the same scope)
 *   info = "dca|" + kid (e.g., "dca|251023T13")
 *   len  = 32 bytes (AES-256)
 *
 * @param rotationSecret - Publisher's rotation secret
 * @param scope - Access scope (HKDF salt)
 * @param kid - Key identifier (rotation version)
 * @returns 32-byte AES-256 wrapKey
 */
export async function deriveWrapKey(
  rotationSecret: Uint8Array,
  scope: string,
  kid: string,
): Promise<Uint8Array> {
  return hkdf(rotationSecret, scope, `dca|${kid}`, 32);
}

/**
 * Generate a random renderId (base64url, 16 bytes → ~22 chars).
 */
export function generateRenderId(): string {
  return toBase64Url(getRandomBytes(16));
}
