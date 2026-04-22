---
"@sesamy/capsule-server": minor
---

Add JWKS support for issuer public keys, plus a pluggable cache with 30-day stale-if-error semantics.

## What changed

**`DcaIssuerConfig.jwksUri`** — new alternative to `publicKeyPem`. When set, the publisher fetches an [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) JWKS, filters for active encryption keys (`kty=EC crv=P-256` or `kty=RSA`, `use=enc` or absent, not `status=retired`, `kid` required), and wraps content for every active key. Each `DcaIssuerKey` in the manifest is tagged with the issuing key's `kid` so the issuer can pick the one matching its private key during rotation overlap. `publicKeyPem` and `jwksUri` are mutually exclusive — throws at render time if both or neither are set. `keyId` stays required with `publicKeyPem`, ignored with `jwksUri`.

**Pluggable cache.** `DcaPublisherConfig` gains two new fields:

- `jwksCache?: DcaJwksCache` — backend for JWKS documents. Default: in-memory `Map` scoped to the module. Supply a persistent backend (Cloudflare KV, Redis, filesystem) for multi-process deployments.
- `jwksStaleWindowSeconds?: number` — stale-if-error window. Default: 30 days.

**Caching behavior.** Freshness follows the JWKS response's `Cache-Control: max-age` (1h fallback). When an entry is past freshness and the upstream refresh fails, the cached copy is served for up to `staleWindowSeconds` past freshness with a `console.warn`. After that, render throws with the URL in the error message. Cache read/write errors are swallowed with a warning so a broken cache doesn't break rendering when upstream is healthy.

**New exports:** `fetchJwks`, `refreshJwks`, `getActiveIssuerKeys`, `selectActiveKeys`, `clearJwksCache`, plus types `Jwk`, `JwksDocument`, `ResolvedIssuerKey`, `DcaJwksCache`, `DcaJwksCacheEntry`, `DcaJwksOptions`.

## Why

Issuer private-key rotation previously required a redeploy of every publisher (they each held the current PEM in an env var). With JWKS, the issuer adds the new key to the published set and publishers pick it up on their next refresh. During the overlap window the publisher wraps content for both keys, so clients hitting either the old or new issuer instance unlock successfully — rotation becomes a no-op for publishers.

The 30-day stale window is the "availability beats freshness" trade-off: if the issuer's JWKS host is down, we'd rather keep rendering with a recently-valid key set than fail every request. Issuer keys rotate rarely; 30 days is far longer than any realistic outage.

## Backwards compatibility

Fully additive. `publicKeyPem` + `keyId` continues to work unchanged. `DcaIssuerKey.kid` and `DcaIssuerEntry.keyId` are both optional on the wire. The issuer server picks the entry whose `kid` matches its configured `keyId`, falling back to the sole entry when no kid discrimination is needed (legacy manifests).
