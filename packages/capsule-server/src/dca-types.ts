/**
 * DCA (Delegated Content Access) - Type Definitions
 *
 * Wire format types for the DCA standard: what publishers produce and clients consume.
 * All binary values are base64url-encoded strings (RFC 4648 §5, no padding).
 */

// ============================================================================
// dca-data JSON structure (goes in <script class="dca-data">)
// ============================================================================

/**
 * Top-level DCA data structure.
 * One per page — embedded in `<script type="application/json" class="dca-data">`.
 */
export interface DcaData {
    /** Format version */
    version: "1";
    /** Publisher metadata (unsigned copy for pre-verification key lookup) */
    resource: DcaResource;
    /** ES256 JWT signing the `resource` object — authoritative for access decisions */
    resourceJWT: string;
    /** Map of issuerName → ES256 JWT (integrity proofs for that issuer's sealed blobs) */
    issuerJWT: Record<string, string>;
    /** Per content item: MIME type, nonce, and AAD for decryption */
    contentSealData: Record<string, DcaContentSealData>;
    /** Per content item: array of contentKeys sealed with periodKeys */
    sealedContentKeys: Record<string, DcaSealedContentKey[]>;
    /** Per issuer: sealed keys, unlock URL, and key ID */
    issuerData: Record<string, DcaIssuerEntry>;
    /**
     * Maps contentName → keyName when any content item's keyName differs
     * from its contentName. Omitted when every keyName equals its contentName
     * (backward compatibility — v1 behaviour).
     *
     * The keyName determines which periodKey domain a content item belongs to.
     * Content items sharing a keyName share the same periodKey, enabling
     * role-based access: e.g. keyName "premium" covers both "bodytext" and
     * "sidebar", and a single subscription grants access to all of them.
     */
    contentKeyMap?: Record<string, string>;
}

/**
 * Publisher resource metadata (human-readable form).
 * Used in DcaData.resource (the page's unsigned copy) and internally
 * after JWT verification. The JWT payload uses standard claim names
 * — see {@link DcaResourceJwtPayload}.
 */
export interface DcaResource {
    /** Random base64url string (min 8 bytes), binds resourceJWT and issuerJWT */
    renderId: string;
    /** Publisher domain (issuer uses for signing key lookup) */
    domain: string;
    /** Render timestamp (ISO 8601, debug metadata) */
    issuedAt: string;
    /** Publisher's article/resource identifier */
    resourceId: string;
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
    /** Publisher-defined metadata for access decisions */
    data: Record<string, unknown>;
}

/**
 * Per-content-item decryption parameters.
 */
export interface DcaContentSealData {
    /** MIME type of the content (e.g., "text/html", "application/json") */
    contentType: string;
    /** base64url-encoded 12-byte AES-GCM IV for content decryption */
    nonce: string;
    /** Opaque AAD string — pass as-is to AES-GCM via TextEncoder.encode() */
    aad: string;
}

/**
 * A contentKey sealed (wrapped) with a periodKey.
 */
export interface DcaSealedContentKey {
    /** Period bucket label (e.g., "251023T13"). Bookkeeping — not validated. */
    t: string;
    /** base64url-encoded 12-byte nonce for unwrapping */
    nonce: string;
    /** base64url-encoded wrapped contentKey (AES-GCM ciphertext + tag, 48 bytes → 64 chars) */
    key: string;
}

/**
 * Per-issuer entry in `issuerData`.
 */
export interface DcaIssuerEntry {
    /** Map of contentName → sealed keys for this issuer */
    sealed: Record<string, DcaIssuerSealed>;
    /** Issuer's unlock endpoint URL */
    unlockUrl: string;
    /** Identifies which issuer private key to use */
    keyId: string;
}

/**
 * Sealed keys for one content item, for one issuer.
 * Both contentKey and periodKeys are sealed with the issuer's public key.
 */
export interface DcaIssuerSealed {
    /** contentKey sealed with issuer public key (base64url opaque blob) */
    contentKey: string;
    /** Map of period bucket "t" → periodKey sealed with issuer public key */
    periodKeys: Record<string, string>;
}

// ============================================================================
// issuerJWT payload
// ============================================================================

/**
 * Payload of an issuerJWT — integrity proofs for one issuer's sealed blobs.
 */
export interface DcaIssuerJwtPayload {
    /** Must match resource.renderId */
    renderId: string;
    /** The issuer this JWT is for */
    issuerName: string;
    /** SHA-256 hashes of sealed blobs, mirroring the structure of issuerData.*.sealed */
    proof: Record<string, DcaIssuerProof>;
    /**
     * Key ID for the issuer's private key (v2).
     * When present in the issuerJWT, the client does not need to send `keyId`
     * as a separate request field.
     */
    keyId?: string;
}

/**
 * Integrity proof for one content item's sealed keys.
 * Each hash = base64url(SHA-256(base64url_string_as_utf8_bytes)).
 */
export interface DcaIssuerProof {
    /** Hash of the sealed contentKey blob */
    contentKey: string;
    /** Map of period bucket "t" → hash of sealed periodKey blob */
    periodKeys: Record<string, string>;
}

// ============================================================================
// JSON API variant
// ============================================================================

/**
 * JSON API response — combines dca-data and sealed content in one object.
 * For headless CMS, mobile apps, SPAs.
 */
export interface DcaJsonApiResponse extends DcaData {
    /** Map of contentName → base64url ciphertext */
    sealedContent: Record<string, string>;
}

// ============================================================================
// sealed content in HTML
// ============================================================================

/**
 * Sealed content is placed in:
 *   <template class="dca-sealed-content">
 *     <div data-dca-content-name="bodytext">base64url_ciphertext...</div>
 *   </template>
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
    /** ES256 (ECDSA P-256) private key PEM — for signing resourceJWT and issuerJWT */
    signingKeyPem: string;
    /** Period secret for periodKey derivation (base64 string or raw bytes) */
    periodSecret: Uint8Array | string;
    /** Period duration in hours (default: 1). Determines the time bucket granularity */
    periodDurationHours?: number;
}

/**
 * A content item to encrypt.
 */
export interface DcaContentItem {
    /** Publisher-defined name, e.g., "bodytext". ASCII: [a-zA-Z][a-zA-Z0-9-]* */
    contentName: string;
    /**
     * Key domain for periodKey derivation (HKDF salt).
     * Defaults to `contentName` when omitted.
     *
     * Content items sharing a keyName share the same periodKey, enabling:
     *   - Role-based access: keyName "premium" covers multiple content items
     *   - Efficient caching: one cached periodKey unlocks all items in the domain
     *   - Clean separation: contentName identifies the item, keyName controls access
     */
    keyName?: string;
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
    /** Which content items this issuer gets sealed keys for (by contentName) */
    contentNames?: string[];
    /**
     * Which key domains this issuer gets sealed keys for.
     * All content items whose effective keyName is in this list are sealed
     * for this issuer. Alternative to `contentNames` for role-based access.
     *
     * When both `contentNames` and `keyNames` are provided, `keyNames` takes
     * precedence.
     */
    keyNames?: string[];
}

/**
 * Options for a single render (page generation).
 */
export interface DcaRenderOptions {
    /** Publisher's unique resource identifier */
    resourceId: string;
    /** Content items to encrypt */
    contentItems: DcaContentItem[];
    /** Issuers to seal keys for */
    issuers: DcaIssuerConfig[];
    /** Publisher-defined metadata for access decisions (goes in resource.data) */
    resourceData?: Record<string, unknown>;
}

/**
 * Result of a render operation.
 */
export interface DcaRenderResult {
    /** The complete dca-data JSON object */
    dcaData: DcaData;
    /** Sealed content: contentName → base64url ciphertext */
    sealedContent: Record<string, string>;
    /** Pre-built HTML strings for embedding */
    html: {
        /** `<script type="application/json" class="dca-data">...</script>` */
        dcaDataScript: string;
        /** `<template class="dca-sealed-content">...</template>` */
        sealedContentTemplate: string;
    };
    /** JSON API variant (dca-data + sealedContent combined) */
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
    /** Private key PEM (ECDH P-256 or RSA-OAEP) for unsealing */
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
     *   // Simple: any resourceId from this domain is accepted
     *   "news.example.com": process.env.NEWS_ES256_PUB!,
     *   // Extended: only specific resourceIds are allowed
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
 * Unlock request — what the client sends to the subscription service.
 *
 * **v1 (current):** All fields present — resource, resourceJWT, issuerJWT,
 * sealed, keyId, issuerName.
 *
 * **v2 (beta):** Only `resourceJWT`, `sealed`, and `keyId` are required.
 * The issuerJWT is dropped entirely — AES-GCM authenticated encryption
 * provides sealed-blob integrity, and the resourceJWT already authenticates
 * the publisher. The `keyId` comes from the page's `issuerData`.
 *
 * The service auto-detects which format is used and handles both.
 * v2 is **not** backwards compatible with v1-only services.
 */
export interface DcaUnlockRequest {
    /**
     * Unsigned resource (for domain-based key lookup before JWT verification).
     * **v1:** Required. **v2:** Omitted (decoded from resourceJWT).
     */
    resource?: DcaResource;
    /** Signed resource JWT (publisher-signed, ES256) */
    resourceJWT: string;
    /**
     * Integrity-proof JWT for sealed blobs.
     * **v1:** Required. **v2:** Omitted — AES-GCM provides integrity.
     */
    issuerJWT?: string;
    /** This issuer's sealed keys */
    sealed: Record<string, DcaIssuerSealed>;
    /**
     * Key ID for the issuer key to use.
     * **v1:** Required. **v2:** Required (from page's issuerData).
     */
    keyId?: string;
    /**
     * Issuer name (for context binding).
     * **v1:** Required. **v2:** Omitted (service knows its own name).
     */
    issuerName?: string;
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
    /**
     * Maps contentName → keyName (v2, for keyName-based access decisions).
     * Included by the client when the page's DcaData contains a contentKeyMap.
     * The issuer uses this to resolve `grantedKeyNames` → contentNames.
     */
    contentKeyMap?: Record<string, string>;
}

/**
 * Unlock response — what the issuer returns to the client.
 * Contains either contentKeys or periodKeys (issuer's choice per request).
 */
export interface DcaUnlockResponse {
    /** Map of contentName → key material for granted content items */
    keys: Record<string, DcaUnlockedKeys>;
    /**
     * Transport mode used for key delivery:
     *   - "direct": keys are plaintext base64url strings (default)
     *   - "client-bound": keys are RSA-OAEP wrapped with the client's public key
     */
    transport?: "direct" | "client-bound";
}

/**
 * Unlocked keys for one content item.
 * The issuer returns either contentKey or periodKeys (or both, though unusual).
 *
 * In direct transport: values are base64url-encoded raw key bytes.
 * In client-bound transport: values are base64url-encoded RSA-OAEP ciphertext
 * that only the client's non-extractable private key can decrypt.
 */
export interface DcaUnlockedKeys {
    /** base64url-encoded contentKey (raw in direct mode, RSA-OAEP wrapped in client-bound mode) */
    contentKey?: string;
    /** Map of period bucket "t" → base64url-encoded periodKey (raw or RSA-OAEP wrapped) */
    periodKeys?: Record<string, string>;
}

// ============================================================================
// Share Link Tokens
// ============================================================================

/**
 * Share Link Token payload — a publisher-signed JWT that grants
 * pre-authenticated access to specific content.
 *
 * DCA-compatible: the periodSecret never leaves the publisher.
 * The token is purely an authorization grant — key material flows
 * through the normal DCA seal/unseal channel.
 *
 * Flow:
 *   1. Publisher creates a share link token (ES256 JWT) granting access
 *   2. User clicks the share link, loads the page with DCA-sealed content
 *   3. Client includes the share link token in the unlock request
 *   4. Issuer verifies the token signature (publisher-signed, trusted)
 *   5. Issuer grants access based on the token's claims (no subscription check)
 *   6. Issuer unseals keys from the normal DCA sealed data and returns them
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
     * Key domains this token grants access to (v2 keyName-based).
     * When present, the issuer resolves keyNames → contentNames
     * via the request's contentKeyMap and grants all matching items.
     * Takes precedence over `contentNames` when present.
     */
    keyNames?: string[];
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
     * Key domains to grant access to (v2 keyName-based).
     * When present, the token grants access to all content items
     * whose keyName is in this list.
     */
    keyNames?: string[];
    /** Token lifetime in seconds (default: 7 days = 604800) */
    expiresIn?: number;
    /** Maximum number of uses (optional, advisory) */
    maxUses?: number;
    /** Unique token ID (auto-generated if omitted) */
    jti?: string;
    /** Publisher-defined metadata */
    data?: Record<string, unknown>;
}
