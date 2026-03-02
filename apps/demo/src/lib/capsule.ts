/**
 * Shared CMS server instance for content encryption.
 * Uses the high-level @sesamy/capsule-server API.
 *
 * All secrets are resolved lazily so that `next build` can collect pages
 * without crashing when env vars are absent.  A missing secret surfaces
 * as an error on the first real request instead.
 */

import { createCmsServer, createPeriodKeyProvider } from "@sesamy/capsule-server";

/** Period duration in seconds (30s for demo, longer for production) */
export const PERIOD_DURATION_SECONDS = 30;

const DEV_FALLBACK_SECRET = Buffer.from(
  "demo-secret-do-not-use-in-production!!",
  "utf-8",
).toString("base64");

// ---------------------------------------------------------------------------
// Secret helpers – throw at runtime if missing outside dev
// ---------------------------------------------------------------------------

let _periodSecret: string | undefined;
let _tokenSecret: string | undefined;

/** @throws if PERIOD_SECRET is missing and NODE_ENV !== "development" */
export function getPeriodSecret(): string {
  if (_periodSecret) return _periodSecret;
  const secret = process.env.PERIOD_SECRET;
  if (secret) {
    _periodSecret = secret;
    return secret;
  }
  if (process.env.NODE_ENV === "development") {
    console.warn(
      "[capsule] PERIOD_SECRET not set — using insecure demo fallback (dev only)",
    );
    _periodSecret = DEV_FALLBACK_SECRET;
    return _periodSecret;
  }
  throw new Error(
    "PERIOD_SECRET environment variable is required in production",
  );
}

/** @throws if CAPSULE_TOKEN_SECRET is missing and NODE_ENV !== "development" */
export function getTokenSecret(): string {
  if (_tokenSecret) return _tokenSecret;
  const secret = process.env.CAPSULE_TOKEN_SECRET;
  if (secret) {
    _tokenSecret = secret;
    return secret;
  }
  if (process.env.NODE_ENV === "development") {
    console.warn(
      "[capsule] CAPSULE_TOKEN_SECRET not set — using insecure demo fallback (dev only)",
    );
    _tokenSecret = "demo-token-secret-do-not-use-in-production!!";
    return _tokenSecret;
  }
  throw new Error(
    "CAPSULE_TOKEN_SECRET environment variable is required in production",
  );
}

// ---------------------------------------------------------------------------
// Lazy singletons – created on first access
// ---------------------------------------------------------------------------

let _keyProvider: ReturnType<typeof createPeriodKeyProvider> | undefined;
let _cms: ReturnType<typeof createCmsServer> | undefined;

export function getKeyProvider() {
  if (!_keyProvider) {
    _keyProvider = createPeriodKeyProvider({
      periodSecret: getPeriodSecret(),
      periodDurationSeconds: PERIOD_DURATION_SECONDS,
    });
  }
  return _keyProvider;
}

export function getCms() {
  if (!_cms) {
    _cms = createCmsServer({
      getKeys: async (keyIds) => {
        const kp = getKeyProvider();
        const keys = await kp.getKeys(
          keyIds.filter((id) => !id.startsWith("article:")),
        );

        for (const id of keyIds.filter((id) => id.startsWith("article:"))) {
          const resourceId = id.slice(8);
          keys.push(await kp.getArticleKey(resourceId));
        }

        return keys;
      },
    });
  }
  return _cms;
}
