import { NextRequest, NextResponse } from "next/server";
import { registerCmsPublicKey, listRegisteredCms } from "@/lib/auth";

/**
 * POST /api/cms/register
 * 
 * Register a CMS public key for JWT authentication.
 * In production, this would require admin authentication.
 * 
 * Request:
 * {
 *   cmsId: string,
 *   publicKey: string (PEM format)
 * }
 * 
 * Response:
 * {
 *   success: boolean,
 *   cmsId: string
 * }
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { cmsId, publicKey } = body;
    
    if (!cmsId || typeof cmsId !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid cmsId" },
        { status: 400 }
      );
    }
    
    if (!publicKey || typeof publicKey !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid publicKey" },
        { status: 400 }
      );
    }
    
    // Validate public key format
    if (!publicKey.includes("BEGIN PUBLIC KEY")) {
      return NextResponse.json(
        { error: "Invalid public key format - must be PEM" },
        { status: 400 }
      );
    }
    
    // Register the public key
    registerCmsPublicKey(cmsId, publicKey);
    
    return NextResponse.json({
      success: true,
      cmsId,
      message: `Public key registered for ${cmsId}`
    });
  } catch (error) {
    console.error("Registration error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * GET /api/cms/register
 * 
 * List all registered CMS instances.
 */
export async function GET() {
  try {
    const registered = listRegisteredCms();
    
    return NextResponse.json({
      registered,
      count: registered.length
    });
  } catch (error) {
    console.error("List error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
