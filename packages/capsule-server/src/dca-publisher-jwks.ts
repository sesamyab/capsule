/**
 * DCA publisher JWKS — builds the JWKS document a publisher serves at
 * `.well-known/dca-publishers.json` so JWKS-configured issuers can resolve
 * the publisher's ES256 signing key dynamically.
 *
 * This module exposes two helpers:
 *   - {@link buildPublisherJwk} — produce a single JWK from one public key PEM.
 *   - {@link buildPublisherJwksDocument} — wrap one or more JWKs in `{ keys: [...] }`.
 *
 * The library intentionally does not own the HTTP route; publishers serve
 * the returned document from whatever framework they already use.
 */

import {
    importEcdsaP256PublicKey,
    exportEcdsaP256PublicKeyAsJwk,
} from "./web-crypto";

import type { Jwk, JwksDocument } from "./dca-jwks";

/**
 * Describe one publisher signing key for JWKS publication.
 */
export interface PublisherJwkInput {
    /**
     * ES256 (ECDSA P-256) public key in SPKI PEM form — the public half of
     * the signing keypair the publisher uses for resourceJWT and share
     * link tokens.
     */
    publicKeyPem: string;
    /**
     * Stable identifier for this key. Must match the `kid` set on JWTs
     * signed with the corresponding private key.
     */
    kid: string;
    /**
     * Mark a key as retired so issuers ignore it for new verifications
     * while the JWKS still lists it for debugging/rotation overlap.
     * Non-standard but honored by {@link selectActivePublisherKeys}.
     */
    status?: "retired";
}

/**
 * Produce a single JWK for a publisher signing key.
 *
 * The returned JWK carries `kty: "EC"`, `crv: "P-256"`, `use: "sig"`,
 * `alg: "ES256"`, and `kid: <input.kid>`. Pass it into a JWKS document
 * either by hand or via {@link buildPublisherJwksDocument}.
 */
export async function buildPublisherJwk(input: PublisherJwkInput): Promise<Jwk> {
    if (!input.publicKeyPem || typeof input.publicKeyPem !== "string") {
        throw new Error("buildPublisherJwk: publicKeyPem must be a non-empty PEM string");
    }
    if (!input.kid || typeof input.kid !== "string") {
        throw new Error("buildPublisherJwk: kid must be a non-empty string");
    }

    const cryptoKey = await importEcdsaP256PublicKey(input.publicKeyPem);
    const raw = (await exportEcdsaP256PublicKeyAsJwk(cryptoKey)) as Record<string, unknown>;

    const jwk: Jwk = {
        kty: "EC",
        crv: "P-256",
        x: raw.x as string,
        y: raw.y as string,
        kid: input.kid,
        use: "sig",
        alg: "ES256",
    };
    if (input.status === "retired") {
        jwk.status = "retired";
    }
    return jwk;
}

/**
 * Build a JWKS document (RFC 7517) for one or more publisher signing keys.
 *
 * Typical usage — a publisher with a single active key:
 * ```ts
 * const doc = await buildPublisherJwksDocument([{
 *   publicKeyPem: process.env.PUBLISHER_PUBLIC_KEY!,
 *   kid: process.env.PUBLISHER_SIGNING_KEY_ID!,
 * }]);
 * app.get("/.well-known/dca-publishers.json", (_, res) =>
 *   res.set("Cache-Control", "max-age=3600").json(doc),
 * );
 * ```
 *
 * During rotation, include both the new key (active) and the previous key
 * (optionally `status: "retired"` if it should no longer verify new tokens).
 */
export async function buildPublisherJwksDocument(
    keys: PublisherJwkInput[],
): Promise<JwksDocument> {
    if (!Array.isArray(keys) || keys.length === 0) {
        throw new Error("buildPublisherJwksDocument: keys must be a non-empty array");
    }
    const kids = new Set<string>();
    for (const k of keys) {
        if (kids.has(k.kid)) {
            throw new Error(`buildPublisherJwksDocument: duplicate kid "${k.kid}"`);
        }
        kids.add(k.kid);
    }
    return { keys: await Promise.all(keys.map(buildPublisherJwk)) };
}
