import { NextRequest, NextResponse } from "next/server";

const AUTH_COOKIE = "aether_session";

export async function GET(request: NextRequest) {
  const cookie = request.cookies.get(AUTH_COOKIE)?.value;
  const expectedCode = process.env.AUTH_CODE;

  if (!cookie || !expectedCode || cookie !== expectedCode) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  return NextResponse.json({ success: true });
}

export async function POST(request: NextRequest) {
  try {
    const { code } = await request.json();
    const expectedCode = process.env.AUTH_CODE;

    if (!expectedCode) {
      return NextResponse.json(
        { error: "Authentication not configured" },
        { status: 500 },
      );
    }

    if (typeof code !== "string" || code.length === 0) {
      return NextResponse.json({ error: "Invalid request" }, { status: 400 });
    }

    if (
      code.length !== expectedCode.length ||
      !secureCompare(code, expectedCode)
    ) {
      return NextResponse.json(
        { error: "Invalid access code" },
        { status: 401 },
      );
    }

    const response = NextResponse.json({ success: true });
    response.cookies.set(AUTH_COOKIE, code, {
      httpOnly: true,
      secure: request.nextUrl.protocol === "https:",
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 30,
    });

    return response;
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
}

export async function DELETE(request: NextRequest) {
  const response = NextResponse.json({ success: true });
  response.cookies.set(AUTH_COOKIE, "", {
    httpOnly: true,
    secure: request.nextUrl.protocol === "https:",
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  return response;
}

function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
