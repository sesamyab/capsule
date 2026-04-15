/**
 * DCA (Delegated Content Access) - Type Definitions
 *
 * Wire format types for the DCA standard: what publishers produce and clients consume.
 * All binary values are base64url-encoded strings (RFC 4648 §5, no padding).
 */

// ============================================================================
// dca-manifest JSON structure (goes in <script class="dca-manifest">)
// ============================================================================

/**
 * Top-level DCA manifest.
 * One per page — embedded in `<script type="application/json" class="dca-manifest">`.
 */
export interface DcaManifest {
    /** Format version */
    version: "0.10";
    /** ES256 JWT signing the resource — authoritative for access decisions */
    resourceJWT: string;
    /** Per content item: MIME type, IV, AAD, ciphertext, and wrapped content key(s) */
    content: Record<string, DcaContentEntry>;
    /** Per issuer: wrapped-for-issuer key material + unlock URL */
    issuers: Record<string, DcaIssuerEntry>;
}

/**
 * Publisher resource metadata (human-readable form).
 * Used internally after JWT verification. The JWT payload uses standard
 * claim names — see {@link DcaResourceJwtPayload}.
 */
export interface DcaResource {
    /** Random base64url string (min 8 bytes), unique per render */
    renderId: string;
    /** Publisher domain (issuer uses for signing key lookup) */
    domain: string;
    /** Render timestamp (ISO 8601, debug metadata) */
    issuedAt: string;
    /** Publisher's article/resource identifier */
    resourceId: string;
    /**
     * Required access scopes for this resource.
     * Declares which scopes (tiers/roles) are needed to unlock the content.
     */
    scopes: string[];
    /** Publisher-defined metadata for access decisions */
    data: Record<string, unknown>;
}

/**
 * JWT payload for `resourceJWT` — uses standard JWT claim names (RFC 7519).
 *
 * Mapping from DcaResource:
 *   - `domain`     → `iss` (JWT Issuer — the publisher that signed the token)
 *   - `resourceId` → `sub` (JWT Subject — the resource being accessed)
 *   - `issuedAt`   → `iat` (JWT Issued At — Unix timestamp in seconds)
 *   - `renderId`   → `jti` (JWT ID — unique per-render token identifier)
 *   - `scopes`     → `scopes` (custom claim — required access scopes)
 *   - `data`       → `data` (custom claim — publisher-defined metadata)
 */
export interface DcaResourceJwtPayload {
    /** Publisher domain (maps to DcaResource.domain) */
    iss: string;
    /** Resource identifier (maps to DcaResource.resourceId) */
    sub: string;
    /** Render timestamp as Unix seconds (maps to DcaResource.issuedAt) */
    iat: number;
    /** Render ID (maps to DcaResource.renderId) */
    jti: string;
    /**
     * Required access scopes for this resource.
     * Declares which scopes (tiers/roles) are needed to unlock the content.
     * The issuer can compare against the user's entitlements without a
     * separate server-side lookup.
     */
    scopes?: string[];
    /** Publisher-defined metadata for access decisions */
    data: Record<string, unknown>;
}

/**
 * Per-content-item entry in the manifest.
 *
 * Contains everything needed to decrypt one content item:
 *   - AEAD parameters for the body (iv, aad, contentType)
 *   - The encrypted body (ciphertext)
 *   - The contentKey wrapped under the rotation-versioned wrapKey (wrappedContentKey)
 */
export interface DcaContentEntry {
    /** MIME type of the content (e.g., "text/html", "application/json") */
    contentType: string;
    /** base64url-encoded 12-byte AES-GCM IV for content decryption */
    iv: string;
    /** Opaque AAD string — pass as-is to AES-GCM via TextEncoder.encode() */
    aad: string;
    /** base64url-encoded AES-GCM ciphertext (content body + auth tag) */
    ciphertext: string;
    /**
     * The contentKey wrapped under one or more wrapKeys (typically current +
     * next rotation). Each entry is keyed by `kid` so the client can match
     * whichever wrapKey the issuer returns.
     */
    wrappedContentKey: DcaWrappedContentKeyEntry[];
}

/**
 * A contentKey wrapped under a wrapKey (AES-256-GCM symmetric wrap).
 */
export interface DcaWrappedContentKeyEntry {
    /** Key identifier — rotation version (e.g., "251023T13"). Bookkeeping only. */
    kid: string;
    /** base64url-encoded 12-byte IV for unwrapping */
    iv: string;
    /** base64url-encoded wrapped contentKey (AES-GCM ciphertext + tag) */
    ciphertext: string;
}

/**
 * Per-issuer entry in `issuers`.
 */
export interface DcaIssuerEntry {
    /** Issuer's unlock endpoint URL */
    unlockUrl: string;
    /** Identifies which issuer private key to use */
    keyId: string;
    /**
     * Wrapped-for-issuer key material (one entry per content item).
     * The contentKey and each wrapKey are encrypted to the issuer's public
     * key (ECDH-P256 or RSA-OAEP). Only the issuer can unwrap them.
     */
    keys: DcaIssuerKey[];
}

/**
 * Per-content-item key material wrapped for one issuer.
 *
 * Both the contentKey (per-item, unique) and the wrapKeys (per-scope,
 * per-rotation — shared across items sharing a scope) are included, letting
 * the issuer choose `deliveryMode: "direct" | "wrapKey"` at unlock time.
 */
export interface DcaIssuerKey {
    /** Content item name. Defaults to "default" when omitted. */
    contentName?: string;
    /**
     * Access scope for this entry. Wrapped values are AAD-bound to this
     * scope — tampering with the scope causes unwrap to fail.
     */
    scope: string;
    /** base64url-encoded contentKey wrapped for the issuer's public key */
    contentKey: string;
    /** WrapKeys (per rotation) wrapped for the issuer's public key */
    wrapKeys: DcaWrappedIssuerWrapKey[];
}

/**
 * A wrapKey wrapped for one issuer's public key.
 */
export interface DcaWrappedIssuerWrapKey {
    /** Key identifier — rotation version (e.g., "251023T13") */
    kid: string;
    /** base64url-encoded wrapKey wrapped for the issuer */
    key: string;
}

// ============================================================================
// Unlock response types
// ============================================================================

/**
 * Direct-key delivery — issuer returns the contentKey for immediate
 * decryption. No client-side caching is possible in this mode.
 */
export interface DcaDirectKey {
    /** Content item name. Defaults to "default" when omitted. */
    contentName?: string;
    /** Access scope (echoed from the request). */
    scope?: string;
    /** base64url-encoded contentKey (plaintext or wrapped for client) */
    contentKey: string;
    wrapKeys?: never;
}

/**
 * WrapKey delivery — issuer returns wrapKeys so the client can unwrap
 * contentKeys locally and cache wrapKeys for cross-item / cross-page reuse.
 */
export interface DcaWrapKeyDelivery {
    /** Content item name. Defaults to "default" when omitted. */
    contentName?: string;
    /** Access scope (echoed from the request). */
    scope?: string;
    /** One entry per rotation version */
    wrapKeys: DcaUnlockedWrapKey[];
    contentKey?: never;
}

/**
 * Key material in an unlock response.
 *
 * Issuer returns exactly one of:
 *   - {@link DcaDirectKey}: raw contentKey (no caching)
 *   - {@link DcaWrapKeyDelivery}: wrapKeys (cacheable, cross-item reuse)
 */
export type DcaUnlockedKey = DcaDirectKey | DcaWrapKeyDelivery;

/**
 * An unwrapped (or client-wrapped) wrapKey entry in an unlock response.
 */
export interface DcaUnlockedWrapKey {
    /** Key identifier — rotation version (e.g., "251023T13") */
    kid: string;
    /** base64url-encoded wrapKey (plaintext or client-wrapped) */
    key: string;
}

// ============================================================================
// JSON API variant
// ============================================================================

/**
 * JSON API response — the manifest is already self-contained (ciphertext
 * lives inside `content.{name}.ciphertext`), so this is just `DcaManifest`.
 * Kept as an explicit alias for the JSON-oriented flow.
 */
export type DcaJsonApiResponse = DcaManifest;

// ============================================================================
// HTML embedding
// ============================================================================

/**
 * The manifest is embedded inside:
 *   <script type="application/json" class="dca-manifest">…</script>
 *
 * Target elements for decrypted content use `data-dca-content-name`:
 *   <div data-dca-content-name="bodytext"></div>
 */

// ============================================================================
// Publisher configuration types
// ============================================================================

/**
 * Configuration for creating a DCA publisher.
 */
export interface DcaPublisherConfig {
    /** Publisher domain (e.g., "www.news-site.com") */
    domain: string;
    /** ES256 (ECDSA P-256) private key PEM — for signing resourceJWT */
    signingKeyPem: string;
    /** Rotation secret for wrapKey derivation (base64 string or raw bytes) */
    rotationSecret: Uint8Array | string;
    /**
     * Rotation interval in hours (default: 1). Determines the granularity
     * of the kid (key id / rotation version). Rotation is purely an
     * identifier for wrapKey derivation — it is not tied to client caching
     * cadence beyond "how often a new wrapKey is minted".
     */
    rotationIntervalHours?: number;
}

/**
 * A content item to encrypt.
 */
export interface DcaContentItem {
    /** Publisher-defined name, e.g., "bodytext". ASCII: [a-zA-Z][a-zA-Z0-9-]* */
    contentName: string;
    /**
     * Access scope for wrapKey derivation (HKDF salt).
     * Defaults to `contentName` when omitted.
     *
     * Content items sharing a scope share the same wrapKey, enabling:
     *   - Role-based access: scope "premium" covers multiple content items
     *   - Efficient caching: one cached wrapKey unlocks all items in the scope
     *   - Clean separation: contentName identifies the item, scope controls access
     */
    scope?: string;
    /** Plaintext content to encrypt */
    content: string;
    /** MIME type (default: "text/html") */
    contentType?: string;
}

/**
 * Issuer configuration for rendering.
 */
export interface DcaIssuerConfig {
    /** Canonical issuer identifier (stable ASCII token) */
    issuerName: string;
    /** Issuer's public key PEM (ECDH P-256 or RSA-OAEP) */
    publicKeyPem: string;
    /** Algorithm: "ECDH-P256" or "RSA-OAEP" (auto-detected from key if omitted) */
    algorithm?: "ECDH-P256" | "RSA-OAEP";
    /** Identifies which issuer private key matches */
    keyId: string;
    /** Issuer's unlock endpoint URL */
    unlockUrl: string;
    /** Which content items this issuer gets wrapped keys for (by contentName) */
    contentNames?: string[];
    /**
     * Which scopes this issuer gets wrapped keys for.
     * All content items whose effective scope is in this list are wrapped
     * for this issuer. Alternative to `contentNames` for role-based access.
     *
     * When both `contentNames` and `scopes` are provided, `scopes` takes
     * precedence.
     */
    scopes?: string[];
}

/**
 * Options for a single render (page generation).
 */
export interface DcaRenderOptions {
    /** Publisher's unique resource identifier */
    resourceId: string;
    /** Content items to encrypt */
    contentItems: DcaContentItem[];
    /** Issuers to wrap keys for */
    issuers: DcaIssuerConfig[];
    /** Publisher-defined metadata for access decisions (goes in resource.data) */
    resourceData?: Record<string, unknown>;
}

/**
 * Result of a render operation.
 */
export interface DcaRenderResult {
    /** The complete manifest */
    manifest: DcaManifest;
    /** Pre-built HTML string for embedding the manifest */
    html: {
        /** `<script type="application/json" class="dca-manifest">…</script>` */
        manifestScript: string;
    };
    /** JSON API variant (same as {@link manifest}) */
    json: DcaJsonApiResponse;
}

// ============================================================================
// Issuer-side types
// ============================================================================

/**
 * Per-publisher trust configuration.
 *
 * Allows fine-grained control over what each publisher is permitted to claim
 * in unlock requests. Every publisher MUST be explicitly listed — there is no
 * fallback / wildcard lookup.
 */
export interface DcaTrustedPublisher {
    /** ES256 public key PEM for JWT verification */
    signingKeyPem: string;
    /**
     * Optional allowlist of resourceId patterns this publisher may claim.
     *
     * - Exact strings are matched with `===`.
     * - RegExp instances are tested with `.test(resourceId)`.
     *
     * When **omitted or empty**, the publisher may claim any resourceId
     * (i.e. the constraint is not applied).
     */
    allowedResourceIds?: (string | RegExp)[];
}

/**
 * Configuration for creating a DCA issuer.
 */
export interface DcaIssuerServerConfig {
    /** This issuer's canonical name */
    issuerName: string;
    /** Private key PEM (ECDH P-256 or RSA-OAEP) for unwrapping */
    privateKeyPem: string;
    /** Key ID that matches the publisher's keyId for this issuer */
    keyId: string;
    /**
     * Trusted-publisher allowlist.
     *
     * Maps **normalized** publisher domains to trust configuration.
     * Domains are lowercased and trailing dots are stripped at construction
     * time; requests from domains not in this map are rejected outright.
     *
     * Accepts two forms per entry:
     *   - **Simple** (plain PEM string): trusts all resources from the domain.
     *   - **Extended** (`DcaTrustedPublisher`): adds per-publisher constraints
     *     such as `allowedResourceIds`.
     *
     * @example
     * ```ts
     * trustedPublisherKeys: {
     *   "news.example.com": process.env.NEWS_ES256_PUB!,
     *   "blog.example.com": {
     *     signingKeyPem: process.env.BLOG_ES256_PUB!,
     *     allowedResourceIds: ["article-1", /^premium-/],
     *   },
     * }
     * ```
     */
    trustedPublisherKeys: Record<string, string | DcaTrustedPublisher>;
}

/**
 * Unlock request — what the client sends to the issuer.
 *
 * Carries `resourceJWT` + `keys` (wrapped-for-issuer key material for one
 * issuer's `keys` array from the manifest). Wrapped values are AAD-bound to
 * their scope, preventing cross-scope key substitution.
 */
export interface DcaUnlockRequest {
    /**
     * Signed resource JWT (publisher-signed, ES256).
     * Optional — the issuer no longer needs it for AAD reconstruction
     * (AAD is bound to scope on each entry). Issuers that want publisher
     * trust verification can still require it.
     */
    resourceJWT?: string;
    /** Wrapped-for-issuer keys (copied verbatim from manifest `issuers.{name}.keys`) */
    keys: DcaIssuerKey[];
    /**
     * Client's RSA-OAEP public key (base64url-encoded SPKI).
     * When present, the issuer wraps returned keys with this key
     * so no readable key material is sent over the network.
     * This enables client-bound transport mode.
     */
    clientPublicKey?: string;
    /**
     * Share link token (ES256 JWT signed by the publisher).
     * When present, the issuer uses this token as the access decision
     * instead of requiring a subscription check.
     */
    shareToken?: string;
}

/**
 * Unlock response — what the issuer returns to the client.
 * Contains either direct contentKeys or wrapKeys (issuer's choice per request).
 */
export interface DcaUnlockResponse {
    /** Unwrapped key material for granted content items */
    keys: DcaUnlockedKey[];
    /**
     * Transport mode used for key delivery:
     *   - "direct": keys are plaintext base64url strings (default)
     *   - "client-bound": keys are RSA-OAEP wrapped with the client's public key
     */
    transport?: "direct" | "client-bound";
}

// ============================================================================
// Share Link Tokens
// ============================================================================

/**
 * Share Link Token payload — a publisher-signed JWT that grants
 * pre-authenticated access to specific content.
 *
 * DCA-compatible: the rotationSecret never leaves the publisher.
 * The token is purely an authorization grant — key material flows
 * through the normal DCA wrap/unwrap channel.
 *
 * Flow:
 *   1. Publisher creates a share link token (ES256 JWT) granting access
 *   2. User clicks the share link, loads the page with DCA-wrapped content
 *   3. Client includes the share link token in the unlock request
 *   4. Issuer verifies the token signature (publisher-signed, trusted)
 *   5. Issuer grants access based on the token's claims (no subscription check)
 *   6. Issuer unwraps keys from the normal DCA wrapped data and returns them
 */
export interface DcaShareLinkTokenPayload {
    /** Token type discriminator */
    type: "dca-share";
    /** Publisher domain (must match the resource domain) */
    domain: string;
    /** Resource ID this token grants access to */
    resourceId: string;
    /** Content items this token grants access to (by contentName) */
    contentNames: string[];
    /**
     * Scopes this token grants access to.
     * When present, the issuer resolves scopes → contentNames
     * using the `scope` field on each key entry.
     * Takes precedence over `contentNames` when present.
     */
    scopes?: string[];
    /** Token issued-at (Unix timestamp, seconds) */
    iat: number;
    /** Token expiry (Unix timestamp, seconds) */
    exp: number;
    /** Optional: maximum number of uses (advisory — enforced by issuer) */
    maxUses?: number;
    /** Unique token ID for revocation or use-count tracking by issuer (auto-generated by publisher if not explicitly set) */
    jti: string;
    /** Optional: publisher-defined metadata (e.g., sharer identity, campaign) */
    data?: Record<string, unknown>;
}

/**
 * Options for creating a share link token.
 */
export interface DcaShareLinkOptions {
    /** Resource ID this token grants access to */
    resourceId: string;
    /** Content items to grant access to (by contentName) */
    contentNames?: string[];
    /**
     * Scopes to grant access to.
     * When present, the token grants access to all content items
     * whose scope is in this list.
     */
    scopes?: string[];
    /** Token lifetime in seconds (default: 7 days = 604800) */
    expiresIn?: number;
    /** Maximum number of uses (optional, advisory) */
    maxUses?: number;
    /** Unique token ID (auto-generated if omitted) */
    jti?: string;
    /** Publisher-defined metadata */
    data?: Record<string, unknown>;
}
