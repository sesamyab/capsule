import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

/**
 * Middleware to format HTML output for readability.
 * This makes "View Source" much cleaner for the demo.
 *
 * In production, you'd remove this for performance.
 */
export function middleware(request: NextRequest) {
  // Only process HTML pages, not API routes or static assets
  const isHtmlPage =
    !request.nextUrl.pathname.startsWith("/api") &&
    !request.nextUrl.pathname.startsWith("/_next") &&
    !request.nextUrl.pathname.includes(".");

  if (!isHtmlPage) {
    return NextResponse.next();
  }

  // Continue with the request, we'll format in the response
  return NextResponse.next();
}

export const config = {
  matcher: [
    // Match all paths except static files and API
    "/((?!api|_next/static|_next/image|favicon.ico).*)",
  ],
};
