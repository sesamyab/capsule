/**
 * Authentication utilities for CMS <-> Subscription Server communication.
 * 
 * Supports:
 * - Option 1: API Key authentication (simple shared secret)
 * - Option 2: JWT with asymmetric keys (EdDSA/Ed25519)
 */

import { createHash, generateKeyPairSync, sign, verify } from "crypto";
import { constantTimeCompare } from "./time-buckets";

/**
 * API Key for CMS authentication (Option 1).
 * In production, store in environment variable.
 */
const VALID_CMS_API_KEY = process.env.CMS_API_KEY || "demo-cms-api-key-change-in-production";

/**
 * Registered CMS public keys for JWT verification (Option 2).
 * In production, store in database.
 */
const cmsPublicKeys = new Map<string, string>();

/**
 * Initialize with a demo CMS public key for testing.
 */
export function initializeDemoCmsKey() {
  const { publicKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  
  cmsPublicKeys.set("demo-cms", publicKey);
  return publicKey;
}

/**
 * Verify API Key authentication (Option 1).
 */
export function verifyApiKey(apiKey: string | undefined): boolean {
  if (!apiKey) {
    return false;
  }
  
  // Remove "Bearer " prefix if present
  const key = apiKey.replace(/^Bearer\s+/i, "");
  
  return constantTimeCompare(key, VALID_CMS_API_KEY);
}

/**
 * Simple JWT implementation for demo purposes.
 * In production, use a library like jsonwebtoken or jose.
 */

interface JwtPayload {
  iss: string;  // Issuer (CMS identifier)
  aud: string;  // Audience (subscription server)
  sub?: string; // Subject (what the token is for)
  iat: number;  // Issued at (Unix timestamp)
  exp: number;  // Expires at (Unix timestamp)
}

/**
 * Decode JWT without verification (to get issuer).
 */
export function decodeJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }
    
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64url").toString("utf8")
    );
    
    return payload as JwtPayload;
  } catch {
    return null;
  }
}

/**
 * Verify JWT signature using Ed25519 (Option 2).
 */
export function verifyJwt(token: string, expectedAudience: string): JwtPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }
    
    // Decode payload to get issuer
    const payload = decodeJwt(token);
    if (!payload) {
      return null;
    }
    
    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return null; // Token expired
    }
    
    // Check audience
    if (payload.aud !== expectedAudience) {
      return null;
    }
    
    // Get public key for this issuer
    const publicKey = cmsPublicKeys.get(payload.iss);
    if (!publicKey) {
      return null; // Unknown CMS
    }
    
    // Verify signature
    const message = `${parts[0]}.${parts[1]}`;
    const signature = Buffer.from(parts[2], "base64url");
    
    const isValid = verify(
      null, // Ed25519 doesn't use a digest algorithm
      Buffer.from(message, "utf8"),
      { key: publicKey, format: "pem" },
      signature
    );
    
    if (!isValid) {
      return null;
    }
    
    return payload;
  } catch (error) {
    console.error("JWT verification error:", error);
    return null;
  }
}

/**
 * Register a CMS public key for JWT verification.
 */
export function registerCmsPublicKey(cmsId: string, publicKey: string): void {
  cmsPublicKeys.set(cmsId, publicKey);
}

/**
 * Get registered CMS public key.
 */
export function getCmsPublicKey(cmsId: string): string | undefined {
  return cmsPublicKeys.get(cmsId);
}

/**
 * List all registered CMS IDs.
 */
export function listRegisteredCms(): string[] {
  return Array.from(cmsPublicKeys.keys());
}

/**
 * Create a JWT token (for CMS to use).
 * This is a helper for testing - real CMS would generate its own tokens.
 */
export function createJwt(
  privateKey: string,
  issuer: string,
  audience: string,
  expiresInSeconds: number = 300
): string {
  const now = Math.floor(Date.now() / 1000);
  
  const payload: JwtPayload = {
    iss: issuer,
    aud: audience,
    sub: "bucket-keys",
    iat: now,
    exp: now + expiresInSeconds
  };
  
  const header = { alg: "EdDSA", typ: "JWT" };
  
  const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  
  const message = `${headerB64}.${payloadB64}`;
  
  const signature = sign(
    null,
    Buffer.from(message, "utf8"),
    { key: privateKey, format: "pem" }
  );
  
  const signatureB64 = signature.toString("base64url");
  
  return `${message}.${signatureB64}`;
}

/**
 * Authenticate CMS request (supports both API Key and JWT).
 */
export function authenticateCmsRequest(
  authorization: string | undefined,
  audience: string = "subscription.example.com"
): { authenticated: boolean; method?: "api-key" | "jwt"; cmsId?: string } {
  if (!authorization) {
    return { authenticated: false };
  }
  
  const token = authorization.replace(/^Bearer\s+/i, "");
  
  // Try JWT first (contains dots)
  if (token.includes(".")) {
    const payload = verifyJwt(token, audience);
    if (payload) {
      return { authenticated: true, method: "jwt", cmsId: payload.iss };
    }
  }
  
  // Fall back to API key
  if (verifyApiKey(authorization)) {
    return { authenticated: true, method: "api-key", cmsId: "api-key-cms" };
  }
  
  return { authenticated: false };
}
