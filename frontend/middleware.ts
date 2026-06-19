import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const AUTH_COOKIE = "aether_session";
const PUBLIC_PATHS = ["/auth", "/api/auth"];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
  }

  if (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon") ||
    pathname.match(/\.(ico|png|jpg|jpeg|svg|css|js|woff|woff2)$/)
  ) {
    return NextResponse.next();
  }

  const sessionToken = request.cookies.get(AUTH_COOKIE)?.value;
  const expectedToken = process.env.AUTH_CODE;

  if (!expectedToken) {
    return NextResponse.redirect(new URL("/auth", request.url));
  }

  if (!sessionToken || sessionToken !== expectedToken) {
    const loginUrl = new URL("/auth", request.url);
    loginUrl.searchParams.set("redirect", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|robots.txt).*)"],
};
