/**
 * Client-side token utilities for share links.
 *
 * The client can decode, inspect, and validate tokens:
 * - Parse tokens without validation (for routing/display)
 * - Validate signatures with trusted keys (full verification)
 * - Whitelist known issuers/keys for security
 * - Check expiry before making network requests
 *
 * @example Basic parsing (no signature validation):
 * ```ts
 * const result = parseShareToken(token);
 * if (result.valid && !result.expired) {
 *   console.log(`Content: ${result.payload.contentId}`);
 * }
 * ```
 *
 * @example Full validation with trusted keys:
 * ```ts
 * const validator = new TokenValidator({
 *   trustedKeys: {
 *     'my-publisher:key-2026': 'shared-secret-here',
 *   }
 * });
 * const result = await validator.validate(token);
 * if (result.valid) {
 *   console.log(`Verified by ${result.payload.iss}`);
 * }
 * ```
 */

/** Decoded token payload from a share link */
export interface ShareTokenPayload {
  /** Token version */
  v: 1;
  /** Unique token ID */
  tid: string;
  /** Issuer identifier */
  iss: string;
  /** Key ID used for signing */
  kid: string;
  /** Tier this token grants access to */
  tier: string;
  /** Publisher's content ID */
  contentId: string;
  /** Full URL for the content (optional) */
  url?: string;
  /** User/purchaser ID for attribution (optional) */
  userId?: string;
  /** Maximum number of uses (optional) */
  maxUses?: number;
  /** Token creation timestamp (Unix seconds) */
  iat: number;
  /** Token expiration timestamp (Unix seconds) */
  exp: number;
  /** Custom metadata (optional) */
  meta?: Record<string, string | number | boolean>;
}

/** Result of parsing a share token */
export interface ParsedToken {
  /** Whether the token format is valid */
  valid: boolean;
  /** Whether the token has expired (client-side check) */
  expired: boolean;
  /** Time until expiry in seconds (negative if expired) */
  expiresIn: number;
  /** The decoded payload */
  payload: ShareTokenPayload;
}

/** Error when token cannot be parsed */
export interface TokenParseError {
  valid: false;
  error: "malformed" | "invalid_format";
  message: string;
}

/**
 * Parse a share token without validating its signature.
 *
 * This extracts the token payload for client-side inspection.
 * The signature can only be validated server-side with the secret.
 *
 * @example
 * ```ts
 * const token = new URL(window.location.href).searchParams.get('token');
 * if (token) {
 *   const result = parseShareToken(token);
 *   if (result.valid) {
 *     if (result.expired) {
 *       showError('This share link has expired');
 *     } else if (result.payload.contentId !== currentArticleId) {
 *       // Redirect to correct content
 *       window.location.href = result.payload.url || `/article/${result.payload.contentId}`;
 *     } else {
 *       // Proceed with unlock
 *       console.log(`Shared by ${result.payload.iss}, expires in ${result.expiresIn}s`);
 *     }
 *   }
 * }
 * ```
 */
export function parseShareToken(token: string): ParsedToken | TokenParseError {
  try {
    // Token format: base64url(payload).base64url(signature)
    const dotIndex = token.lastIndexOf(".");
    if (dotIndex === -1) {
      return {
        valid: false,
        error: "invalid_format",
        message: "Token must contain payload and signature separated by '.'",
      };
    }

    const payloadB64 = token.substring(0, dotIndex);

    // Decode payload
    const payloadJson = atob(base64UrlToBase64(payloadB64));
    const payload = JSON.parse(payloadJson) as ShareTokenPayload;

    // Validate required fields
    if (
      typeof payload.v !== "number" ||
      typeof payload.iss !== "string" ||
      typeof payload.kid !== "string" ||
      typeof payload.tier !== "string" ||
      typeof payload.contentId !== "string" ||
      typeof payload.exp !== "number"
    ) {
      return {
        valid: false,
        error: "malformed",
        message: "Token missing required fields",
      };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = payload.exp - now;
    const expired = expiresIn < 0;

    return {
      valid: true,
      expired,
      expiresIn,
      payload,
    };
  } catch {
    return {
      valid: false,
      error: "malformed",
      message: "Failed to decode token",
    };
  }
}

/**
 * Check if current URL contains a share token and extract it.
 *
 * @example
 * ```ts
 * const tokenInfo = getShareTokenFromUrl();
 * if (tokenInfo?.valid && !tokenInfo.expired) {
 *   // Auto-unlock with token
 *   await capsule.unlockWithToken(tokenInfo.payload.contentId, tokenInfo.token);
 * }
 * ```
 */
export function getShareTokenFromUrl():
  | (ParsedToken & { token: string })
  | TokenParseError
  | null {
  if (typeof window === "undefined") return null;

  const params = new URLSearchParams(window.location.search);
  const token = params.get("token");

  if (!token) return null;

  const result = parseShareToken(token);
  if (!result.valid) return result as TokenParseError;

  return { ...result, token };
}

/**
 * Validate that a token matches the expected content.
 *
 * @example
 * ```ts
 * const tokenInfo = parseShareToken(token);
 * if (tokenInfo.valid) {
 *   const validation = validateTokenForContent(tokenInfo, 'my-article-id');
 *   if (!validation.valid) {
 *     console.error(validation.reason);
 *   }
 * }
 * ```
 */
export function validateTokenForContent(
  tokenResult: ParsedToken,
  contentId: string,
): { valid: true } | { valid: false; reason: string } {
  if (tokenResult.expired) {
    return { valid: false, reason: "Token has expired" };
  }

  if (tokenResult.payload.contentId !== contentId) {
    return {
      valid: false,
      reason: `Token is for content "${tokenResult.payload.contentId}", not "${contentId}"`,
    };
  }

  return { valid: true };
}

// ============================================================================
// Token Validator - Full signature validation with trusted keys
// ============================================================================

/** Map of trusted keys: "issuer:keyId" -> secret */
export type TrustedKeys = Record<string, string>;

/** Options for TokenValidator */
export interface TokenValidatorOptions {
  /**
   * Map of trusted signing keys.
   * Key format: "issuer:keyId" (e.g., "my-publisher:key-2026-01")
   * Value: The shared secret used for signing
   *
   * If empty or not provided, all tokens with valid signatures are accepted
   * (requires passing secret to validate()).
   */
  trustedKeys?: TrustedKeys;

  /**
   * Whether to require tokens to be from a trusted issuer.
   * If true, tokens from unknown issuers will be rejected.
   * If false (default), unknown issuers are accepted if a secret is provided.
   */
  requireTrustedIssuer?: boolean;
}

/** Result of successful token validation */
export interface TokenValidationSuccess {
  valid: true;
  /** Whether the issuer is in the trusted keys list */
  trusted: boolean;
  /** Whether the token has expired */
  expired: boolean;
  /** Time until expiry in seconds (negative if expired) */
  expiresIn: number;
  /** The verified payload */
  payload: ShareTokenPayload;
}

/** Result of failed token validation */
export interface TokenValidationFailure {
  valid: false;
  error:
    | "malformed"
    | "invalid_format"
    | "invalid_signature"
    | "untrusted_issuer"
    | "no_secret"
    | "expired";
  message: string;
  /** Payload is available even on failure (for debugging) */
  payload?: ShareTokenPayload;
}

export type TokenValidationResult =
  | TokenValidationSuccess
  | TokenValidationFailure;

/**
 * Compute HMAC-SHA256 signature using Web Crypto API.
 */
async function computeHmacSignature(
  data: string,
  secret: string,
): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(data);

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  return crypto.subtle.sign("HMAC", key, messageData);
}

/**
 * Convert ArrayBuffer to base64url string.
 */
function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Convert base64url to standard base64 with proper padding.
 *
 * RFC 4648 base64url commonly omits '=' padding; restore it to a multiple of 4
 * before decoding with atob() to prevent runtime errors in strict environments.
 */
function base64UrlToBase64(base64url: string): string {
  // Replace base64url characters with standard base64
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed (base64 length must be multiple of 4)
  const pad = base64.length % 4;
  if (pad) {
    base64 += "=".repeat(4 - pad);
  }
  return base64;
}

/**
 * Timing-safe comparison for signatures.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Token Validator for full signature verification.
 *
 * Use this when you need to cryptographically verify tokens on the client.
 * This is useful for:
 * - Trusted first-party tokens (you control the signing key)
 * - Offline validation without server round-trip
 * - Whitelisting known publishers
 *
 * @example Accept any token with provided secret:
 * ```ts
 * const validator = new TokenValidator();
 * const result = await validator.validate(token, { secret: mySecret });
 * ```
 *
 * @example Whitelist trusted publishers:
 * ```ts
 * const validator = new TokenValidator({
 *   trustedKeys: {
 *     'acme-corp:key-2026': process.env.ACME_SECRET,
 *     'partner:key-v1': process.env.PARTNER_SECRET,
 *   },
 *   requireTrustedIssuer: true, // Reject unknown issuers
 * });
 *
 * const result = await validator.validate(token);
 * if (result.valid && result.trusted) {
 *   // Token is from a known, trusted publisher
 * }
 * ```
 *
 * @example Extract info from URL and validate:
 * ```ts
 * const validator = new TokenValidator({ trustedKeys: myKeys });
 * const tokenInfo = getShareTokenFromUrl();
 *
 * if (tokenInfo?.valid) {
 *   const result = await validator.validate(tokenInfo.token);
 *   if (result.valid && !result.expired) {
 *     // Proceed with unlock
 *     await capsule.unlockWithToken(result.payload.contentId, tokenInfo.token);
 *   }
 * }
 * ```
 */
export class TokenValidator {
  private trustedKeys: TrustedKeys;
  private requireTrustedIssuer: boolean;

  constructor(options: TokenValidatorOptions = {}) {
    this.trustedKeys = options.trustedKeys || {};
    this.requireTrustedIssuer = options.requireTrustedIssuer ?? false;
  }

  /**
   * Get the key identifier for looking up secrets.
   */
  private getKeyId(payload: ShareTokenPayload): string {
    return `${payload.iss}:${payload.kid}`;
  }

  /**
   * Check if an issuer/key combination is trusted.
   */
  isTrusted(issuer: string, keyId: string): boolean {
    return `${issuer}:${keyId}` in this.trustedKeys;
  }

  /**
   * Add a trusted key at runtime.
   */
  addTrustedKey(issuer: string, keyId: string, secret: string): void {
    this.trustedKeys[`${issuer}:${keyId}`] = secret;
  }

  /**
   * Remove a trusted key.
   */
  removeTrustedKey(issuer: string, keyId: string): void {
    delete this.trustedKeys[`${issuer}:${keyId}`];
  }

  /**
   * Validate a token's signature and payload.
   *
   * @param token - The token string to validate
   * @param options - Optional validation options
   * @param options.secret - Secret to use if token is not from a trusted issuer
   * @param options.contentId - If provided, validates the token is for this content
   * @returns Validation result with payload if successful
   */
  async validate(
    token: string,
    options: { secret?: string; contentId?: string } = {},
  ): Promise<TokenValidationResult> {
    // Parse token structure
    const dotIndex = token.lastIndexOf(".");
    if (dotIndex === -1) {
      return {
        valid: false,
        error: "invalid_format",
        message: "Token must contain payload and signature separated by '.'",
      };
    }

    const payloadB64 = token.substring(0, dotIndex);
    const signatureB64 = token.substring(dotIndex + 1);

    // Decode payload
    let payload: ShareTokenPayload;
    try {
      const payloadJson = atob(base64UrlToBase64(payloadB64));
      payload = JSON.parse(payloadJson);
    } catch {
      return {
        valid: false,
        error: "malformed",
        message: "Failed to decode token payload",
      };
    }

    // Validate required fields
    if (
      typeof payload.v !== "number" ||
      typeof payload.iss !== "string" ||
      typeof payload.kid !== "string" ||
      typeof payload.tier !== "string" ||
      typeof payload.contentId !== "string" ||
      typeof payload.exp !== "number"
    ) {
      return {
        valid: false,
        error: "malformed",
        message: "Token missing required fields",
        payload,
      };
    }

    // Find the secret to use
    const keyId = this.getKeyId(payload);
    const trusted = keyId in this.trustedKeys;
    const secret = this.trustedKeys[keyId] || options.secret;

    if (!secret) {
      if (this.requireTrustedIssuer) {
        return {
          valid: false,
          error: "untrusted_issuer",
          message: `Token issuer "${payload.iss}" with key "${payload.kid}" is not trusted`,
          payload,
        };
      }
      return {
        valid: false,
        error: "no_secret",
        message: "No secret provided for token validation",
        payload,
      };
    }

    // Verify signature
    const expectedSig = await computeHmacSignature(payloadB64, secret);
    const expectedSigB64 = arrayBufferToBase64Url(expectedSig);

    // Normalize incoming signature by stripping padding (base64url encoders may keep trailing =)
    const normalizedSigB64 = signatureB64.replace(/=+$/, "");

    if (!timingSafeEqual(expectedSigB64, normalizedSigB64)) {
      return {
        valid: false,
        error: "invalid_signature",
        message: "Token signature is invalid",
        payload,
      };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = payload.exp - now;
    const expired = expiresIn < 0;

    // Check content ID if provided
    if (options.contentId && payload.contentId !== options.contentId) {
      return {
        valid: false,
        error: "malformed",
        message: `Token is for content "${payload.contentId}", not "${options.contentId}"`,
        payload,
      };
    }

    return {
      valid: true,
      trusted,
      expired,
      expiresIn,
      payload,
    };
  }

  /**
   * Validate a token from the current URL.
   *
   * @param options - Validation options
   * @returns Validation result or null if no token in URL
   */
  async validateFromUrl(
    options: { secret?: string; contentId?: string } = {},
  ): Promise<(TokenValidationResult & { token: string }) | null> {
    if (typeof window === "undefined") return null;

    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");

    if (!token) return null;

    const result = await this.validate(token, options);
    return { ...result, token };
  }
}

/**
 * Create a token validator with trusted keys.
 *
 * @example
 * ```ts
 * const validator = createTokenValidator({
 *   trustedKeys: {
 *     'my-publisher:key-2026': 'secret-here',
 *   }
 * });
 *
 * const result = await validator.validate(token);
 * ```
 */
export function createTokenValidator(
  options: TokenValidatorOptions = {},
): TokenValidator {
  return new TokenValidator(options);
}

// ============================================================================
// JWKS-Based Token Validator - Ed25519 signature validation with key discovery
// ============================================================================

/** A JWK key from the JWKS endpoint */
export interface JwkKey {
  kty: "OKP";
  crv: "Ed25519";
  kid: string;
  x: string;
  use: "sig";
  alg: "EdDSA";
}

/** JWKS response structure */
export interface Jwks {
  keys: JwkKey[];
}

/** Cached issuer with fetched keys */
interface CachedIssuer {
  keys: Map<string, CryptoKey>;
  fetchedAt: number;
}

/** Options for JwksTokenValidator */
export interface JwksTokenValidatorOptions {
  /**
   * List of trusted issuer URLs.
   * Tokens from issuers not in this list will be rejected.
   *
   * @example ['https://api.sesamy.com', 'https://partner.example.com']
   */
  trustedIssuers: string[];

  /**
   * How long to cache JWKS keys (in milliseconds).
   * Default: 1 hour
   */
  cacheTimeMs?: number;

  /**
   * Custom fetch function for testing or special environments.
   */
  fetch?: typeof fetch;
}

/** Result of JWKS token validation */
export interface JwksValidationSuccess {
  valid: true;
  /** Issuer URL */
  issuer: string;
  /** Key ID used to sign */
  keyId: string;
  /** Whether token has expired */
  expired: boolean;
  /** Seconds until expiry (negative if expired) */
  expiresIn: number;
  /** Verified payload */
  payload: ShareTokenPayload & { alg?: string };
}

export interface JwksValidationFailure {
  valid: false;
  error:
    | "malformed"
    | "invalid_format"
    | "invalid_signature"
    | "untrusted_issuer"
    | "unknown_key"
    | "jwks_fetch_failed"
    | "unsupported_algorithm";
  message: string;
  payload?: ShareTokenPayload & { alg?: string };
}

export type JwksValidationResult =
  | JwksValidationSuccess
  | JwksValidationFailure;

/**
 * Import an Ed25519 public key from JWK format for Web Crypto API.
 */
async function importEd25519PublicKey(jwk: JwkKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
    },
    { name: "Ed25519" },
    false,
    ["verify"],
  );
}

/**
 * Verify Ed25519 signature using Web Crypto API.
 */
async function verifyEd25519Signature(
  publicKey: CryptoKey,
  data: string,
  signature: string,
): Promise<boolean> {
  try {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    // Decode base64url signature (atob throws InvalidCharacterError on malformed input)
    const sigBinary = atob(base64UrlToBase64(signature));
    const sigBuffer = new Uint8Array(sigBinary.length);
    for (let i = 0; i < sigBinary.length; i++) {
      sigBuffer[i] = sigBinary.charCodeAt(i);
    }

    return await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      sigBuffer,
      dataBuffer,
    );
  } catch {
    return false;
  }
}

/**
 * JWKS-based Token Validator for Ed25519 signed tokens.
 *
 * This validator fetches public keys from the issuer's `/.well-known/jwks.json`
 * endpoint and verifies signatures locally. Only tokens from whitelisted
 * issuers are accepted.
 *
 * @example
 * ```ts
 * const validator = new JwksTokenValidator({
 *   trustedIssuers: [
 *     'https://api.sesamy.com',
 *     'https://partner.example.com',
 *   ],
 * });
 *
 * const result = await validator.validate(token);
 * if (result.valid && !result.expired) {
 *   console.log(`Verified token from ${result.issuer}`);
 * }
 * ```
 */
export class JwksTokenValidator {
  private trustedIssuers: Set<string>;
  private cache: Map<string, CachedIssuer> = new Map();
  private cacheTimeMs: number;
  private fetchFn: typeof fetch;

  constructor(options: JwksTokenValidatorOptions) {
    this.trustedIssuers = new Set(
      options.trustedIssuers.map((url) => url.replace(/\/$/, "")), // Remove trailing slash
    );
    this.cacheTimeMs = options.cacheTimeMs ?? 60 * 60 * 1000; // 1 hour default
    this.fetchFn = options.fetch ?? fetch.bind(globalThis);
  }

  /**
   * Add a trusted issuer at runtime.
   */
  addTrustedIssuer(issuerUrl: string): void {
    this.trustedIssuers.add(issuerUrl.replace(/\/$/, ""));
  }

  /**
   * Remove a trusted issuer.
   */
  removeTrustedIssuer(issuerUrl: string): void {
    const normalized = issuerUrl.replace(/\/$/, "");
    this.trustedIssuers.delete(normalized);
    this.cache.delete(normalized);
  }

  /**
   * Check if an issuer is trusted.
   */
  isTrustedIssuer(issuerUrl: string): boolean {
    return this.trustedIssuers.has(issuerUrl.replace(/\/$/, ""));
  }

  /**
   * Clear the JWKS cache for all or a specific issuer.
   */
  clearCache(issuerUrl?: string): void {
    if (issuerUrl) {
      this.cache.delete(issuerUrl.replace(/\/$/, ""));
    } else {
      this.cache.clear();
    }
  }

  /**
   * Fetch and cache JWKS from an issuer.
   */
  private async fetchJwks(
    issuerUrl: string,
  ): Promise<Map<string, CryptoKey> | null> {
    const normalized = issuerUrl.replace(/\/$/, "");

    // Check cache
    const cached = this.cache.get(normalized);
    if (cached && Date.now() - cached.fetchedAt < this.cacheTimeMs) {
      return cached.keys;
    }

    // Fetch JWKS
    try {
      const response = await this.fetchFn(
        `${normalized}/.well-known/jwks.json`,
      );
      if (!response.ok) {
        return null;
      }

      const jwks: Jwks = await response.json();
      const keys = new Map<string, CryptoKey>();

      for (const jwk of jwks.keys) {
        if (jwk.kty === "OKP" && jwk.crv === "Ed25519" && jwk.alg === "EdDSA") {
          try {
            const cryptoKey = await importEd25519PublicKey(jwk);
            keys.set(jwk.kid, cryptoKey);
          } catch {
            // Skip invalid keys
          }
        }
      }

      this.cache.set(normalized, { keys, fetchedAt: Date.now() });
      return keys;
    } catch {
      return null;
    }
  }

  /**
   * Validate a token using JWKS.
   */
  async validate(
    token: string,
    options: { contentId?: string } = {},
  ): Promise<JwksValidationResult> {
    // Parse token
    const dotIndex = token.lastIndexOf(".");
    if (dotIndex === -1) {
      return {
        valid: false,
        error: "invalid_format",
        message: "Token must contain payload and signature separated by '.'",
      };
    }

    const payloadB64 = token.substring(0, dotIndex);
    const signatureB64 = token.substring(dotIndex + 1);

    // Decode payload
    let payload: ShareTokenPayload & { alg?: string };
    try {
      const payloadJson = atob(base64UrlToBase64(payloadB64));
      payload = JSON.parse(payloadJson);
    } catch {
      return {
        valid: false,
        error: "malformed",
        message: "Failed to decode token payload",
      };
    }

    // Validate required fields
    if (
      typeof payload.iss !== "string" ||
      typeof payload.kid !== "string" ||
      typeof payload.tier !== "string" ||
      typeof payload.contentId !== "string" ||
      typeof payload.exp !== "number"
    ) {
      return {
        valid: false,
        error: "malformed",
        message: "Token missing required fields",
        payload,
      };
    }

    // Check algorithm
    if (payload.alg && payload.alg !== "EdDSA") {
      return {
        valid: false,
        error: "unsupported_algorithm",
        message: `Unsupported algorithm: ${payload.alg}. Expected EdDSA.`,
        payload,
      };
    }

    // Check if issuer is trusted
    const normalizedIssuer = payload.iss.replace(/\/$/, "");
    if (!this.trustedIssuers.has(normalizedIssuer)) {
      return {
        valid: false,
        error: "untrusted_issuer",
        message: `Issuer "${payload.iss}" is not in the trusted issuers list`,
        payload,
      };
    }

    // Fetch JWKS
    const keys = await this.fetchJwks(normalizedIssuer);
    if (!keys) {
      return {
        valid: false,
        error: "jwks_fetch_failed",
        message: `Failed to fetch JWKS from ${normalizedIssuer}/.well-known/jwks.json`,
        payload,
      };
    }

    // Get the public key
    const publicKey = keys.get(payload.kid);
    if (!publicKey) {
      return {
        valid: false,
        error: "unknown_key",
        message: `Key "${payload.kid}" not found in issuer's JWKS`,
        payload,
      };
    }

    // Verify signature
    const isValid = await verifyEd25519Signature(
      publicKey,
      payloadB64,
      signatureB64,
    );
    if (!isValid) {
      return {
        valid: false,
        error: "invalid_signature",
        message: "Token signature is invalid",
        payload,
      };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = payload.exp - now;
    const expired = expiresIn < 0;

    // Check content ID if provided
    if (options.contentId && payload.contentId !== options.contentId) {
      return {
        valid: false,
        error: "malformed",
        message: `Token is for content "${payload.contentId}", not "${options.contentId}"`,
        payload,
      };
    }

    return {
      valid: true,
      issuer: payload.iss,
      keyId: payload.kid,
      expired,
      expiresIn,
      payload,
    };
  }

  /**
   * Validate a token from the current URL.
   */
  async validateFromUrl(
    options: { contentId?: string } = {},
  ): Promise<(JwksValidationResult & { token: string }) | null> {
    if (typeof window === "undefined") return null;

    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");

    if (!token) return null;

    const result = await this.validate(token, options);
    return { ...result, token };
  }
}

/**
 * Create a JWKS-based token validator with trusted issuers.
 *
 * @example
 * ```ts
 * const validator = createJwksTokenValidator({
 *   trustedIssuers: ['https://api.sesamy.com'],
 * });
 *
 * const result = await validator.validate(token);
 * ```
 */
export function createJwksTokenValidator(
  options: JwksTokenValidatorOptions,
): JwksTokenValidator {
  return new JwksTokenValidator(options);
}
