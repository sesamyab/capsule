/**
 * Token utilities for pre-signed unlock links.
 *
 * Enables publishers to generate shareable links that grant access to content
 * without requiring user authentication. Tokens are signed JWTs that can be:
 * - Shared on social media
 * - Sent via email after purchase
 * - Used for "gift this article" features
 * - Time-limited promotional access
 *
 * @example
 * ```typescript
 * import { createTokenManager } from '@sesamy/capsule-server';
 *
 * const tokens = createTokenManager({
 *   secret: process.env.TOKEN_SECRET,
 * });
 *
 * // Generate a share token for social media
 * const token = tokens.generate({
 *   tier: 'premium',
 *   maxUses: 1000,
 *   expiresIn: '7d',
 * });
 *
 * // Validate token from incoming request
 * const payload = tokens.validate(token);
 * if (payload) {
 *   // Token is valid, proceed with unlock
 * }
 * ```
 */

import { createHmac, randomBytes, timingSafeEqual } from "crypto";

/** Token payload - what's encoded in the token */
export interface UnlockTokenPayload {
  /** Token version for future compatibility */
  v: 1;
  /** Unique token ID for tracking/revocation */
  tid: string;
  /** Issuer identifier (e.g., "sesamy", "publisher-name") */
  iss: string;
  /** Key ID used for signing (enables key rotation) */
  kid: string;
  /** Tier this token grants access to (e.g., "premium") */
  tier: string;
  /** Publisher's content ID (required for content binding) */
  contentId: string;
  /** Optional: full URL for the content */
  url?: string;
  /** Optional: user/purchaser ID for attribution */
  userId?: string;
  /** Optional: maximum number of uses (undefined = unlimited) */
  maxUses?: number;
  /** Token creation timestamp (Unix seconds) */
  iat: number;
  /** Token expiration timestamp (Unix seconds) */
  exp: number;
  /** Optional: custom metadata */
  meta?: Record<string, string | number | boolean>;
}

/** Options for generating a token */
export interface GenerateTokenOptions {
  /** Tier this token grants access to */
  tier: string;
  /** Publisher's content ID (required) */
  contentId: string;
  /** Optional: full URL for the content */
  url?: string;
  /** Optional: user/purchaser ID */
  userId?: string;
  /** Optional: maximum uses */
  maxUses?: number;
  /**
   * Token validity duration.
   * Examples: "1h", "24h", "7d", "30d"
   * Or a number of seconds.
   */
  expiresIn: string | number;
  /** Optional: custom metadata */
  meta?: Record<string, string | number | boolean>;
}

/** Result of token validation */
export interface TokenValidationResult {
  valid: true;
  payload: UnlockTokenPayload;
}

/** Token validation error */
export interface TokenValidationError {
  valid: false;
  error: "invalid" | "expired" | "malformed";
  message: string;
}

/** Token manager options */
export interface TokenManagerOptions {
  /** Secret key for signing tokens (min 32 bytes recommended) */
  secret: string | Buffer;
  /** Issuer identifier (e.g., "sesamy", "my-publisher") */
  issuer: string;
  /** Key ID for this secret (enables key rotation, e.g., "key-2026-01") */
  keyId: string;
}

/** Callback for tracking token usage */
export type UsageTracker = (
  tokenId: string,
  payload: UnlockTokenPayload,
  context: { articleId?: string; ip?: string }
) => Promise<{ allowed: boolean; currentUses?: number }>;

/**
 * Parse duration string to seconds.
 * Supports: "1h", "24h", "7d", "30d", etc.
 */
function parseDuration(duration: string | number): number {
  if (typeof duration === "number") {
    return duration;
  }

  const match = duration.match(/^(\d+)(s|m|h|d)$/);
  if (!match) {
    throw new Error(
      `Invalid duration format: ${duration}. Use "1h", "24h", "7d", etc.`
    );
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case "s":
      return value;
    case "m":
      return value * 60;
    case "h":
      return value * 60 * 60;
    case "d":
      return value * 60 * 60 * 24;
    default:
      throw new Error(`Unknown duration unit: ${unit}`);
  }
}

/**
 * Token Manager for generating and validating unlock tokens.
 *
 * Tokens are URL-safe Base64-encoded JSON with HMAC-SHA256 signature.
 * Format: base64url(payload).base64url(signature)
 */
export class TokenManager {
  private secret: Buffer;
  private issuer: string;
  private keyId: string;

  constructor(options: TokenManagerOptions) {
    this.secret = Buffer.isBuffer(options.secret)
      ? options.secret
      : Buffer.from(options.secret, "utf-8");
    this.issuer = options.issuer;
    this.keyId = options.keyId;

    if (this.secret.length < 32) {
      console.warn(
        "TokenManager: secret should be at least 32 bytes for security"
      );
    }
  }

  /**
   * Generate a signed unlock token.
   */
  generate(options: GenerateTokenOptions): string {
    const now = Math.floor(Date.now() / 1000);
    const expiresInSeconds = parseDuration(options.expiresIn);

    const payload: UnlockTokenPayload = {
      v: 1,
      tid: randomBytes(12).toString("base64url"),
      iss: this.issuer,
      kid: this.keyId,
      tier: options.tier,
      contentId: options.contentId,
      iat: now,
      exp: now + expiresInSeconds,
    };

    if (options.url) payload.url = options.url;
    if (options.userId) payload.userId = options.userId;
    if (options.maxUses !== undefined) payload.maxUses = options.maxUses;
    if (options.meta) payload.meta = options.meta;

    return this.sign(payload);
  }

  /**
   * Validate a token and return its payload.
   */
  validate(token: string): TokenValidationResult | TokenValidationError {
    // Parse token
    const dotIndex = token.lastIndexOf(".");
    if (dotIndex === -1) {
      return {
        valid: false,
        error: "malformed",
        message: "Invalid token format",
      };
    }

    const payloadB64 = token.substring(0, dotIndex);
    const signatureB64 = token.substring(dotIndex + 1);

    // Verify signature
    const expectedSig = this.computeSignature(payloadB64);
    const providedSig = Buffer.from(signatureB64, "base64url");

    if (
      expectedSig.length !== providedSig.length ||
      !timingSafeEqual(expectedSig, providedSig)
    ) {
      return { valid: false, error: "invalid", message: "Invalid signature" };
    }

    // Decode payload
    let payload: UnlockTokenPayload;
    try {
      const payloadJson = Buffer.from(payloadB64, "base64url").toString(
        "utf-8"
      );
      payload = JSON.parse(payloadJson);
    } catch {
      return {
        valid: false,
        error: "malformed",
        message: "Invalid payload encoding",
      };
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return { valid: false, error: "expired", message: "Token has expired" };
    }

    return { valid: true, payload };
  }

  /**
   * Extract payload without verifying signature.
   * Useful for getting token ID for logging before validation.
   */
  peek(token: string): UnlockTokenPayload | null {
    try {
      const dotIndex = token.lastIndexOf(".");
      if (dotIndex === -1) return null;

      const payloadB64 = token.substring(0, dotIndex);
      const payloadJson = Buffer.from(payloadB64, "base64url").toString(
        "utf-8"
      );
      return JSON.parse(payloadJson);
    } catch {
      return null;
    }
  }

  /**
   * Sign a payload and return the complete token.
   */
  private sign(payload: UnlockTokenPayload): string {
    const payloadJson = JSON.stringify(payload);
    const payloadB64 = Buffer.from(payloadJson).toString("base64url");
    const signature = this.computeSignature(payloadB64);
    return `${payloadB64}.${signature.toString("base64url")}`;
  }

  /**
   * Compute HMAC-SHA256 signature.
   */
  private computeSignature(data: string): Buffer {
    return createHmac("sha256", this.secret).update(data).digest();
  }
}

/**
 * Create a token manager for generating and validating unlock tokens.
 *
 * @example
 * ```typescript
 * const tokens = createTokenManager({
 *   secret: process.env.TOKEN_SECRET,
 * });
 *
 * // Generate share link token
 * const token = tokens.generate({
 *   tier: 'premium',
 *   maxUses: 1000,
 *   expiresIn: '7d',
 * });
 *
 * const shareUrl = `https://example.com/article/my-article?token=${token}`;
 * ```
 */
export function createTokenManager(
  options: TokenManagerOptions
): TokenManager {
  return new TokenManager(options);
}
