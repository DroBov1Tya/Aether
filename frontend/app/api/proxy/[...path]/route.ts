import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.BACKEND_URL || "http://backend:8080";
const API_KEY = process.env.API_KEY || "";

let initialized = false;

function logInit() {
  if (!initialized) {
    console.log("=".repeat(50));
    console.log("[Proxy] INITIALIZATION");
    console.log("[Proxy] BACKEND_URL:", BACKEND_URL);
    console.log(
      "[Proxy] API_KEY present:",
      API_KEY
        ? `YES (${API_KEY.length} chars)`
        : "❌ NO - will send requests WITHOUT auth!",
    );
    console.log(
      "[Proxy] All env keys:",
      Object.keys(process.env)
        .filter(
          (k) =>
            k.includes("BACKEND") || k.includes("API") || k.includes("KEY"),
        )
        .join(", "),
    );
    console.log("=".repeat(50));
    initialized = true;
  }
}

logInit();

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  const { path } = await params;
  const apiPath = "/" + path.join("/");
  const searchParams = request.nextUrl.searchParams.toString();
  const targetUrl = `${BACKEND_URL}${apiPath}${searchParams ? "?" + searchParams : ""}`;

  return proxyRequest(targetUrl, { method: "GET" });
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
) {
  const { path } = await params;
  const apiPath = "/" + path.join("/");
  const targetUrl = `${BACKEND_URL}${apiPath}`;
  const body = await request.text();

  return proxyRequest(targetUrl, { method: "POST", body });
}

async function proxyRequest(
  targetUrl: string,
  init: RequestInit,
): Promise<NextResponse> {
  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (API_KEY && API_KEY.length > 0) {
      headers["X-API-KEY"] = API_KEY;
    } else {
      console.warn(
        "[Proxy] ⚠️  API_KEY is empty! Request will be sent without auth.",
      );
    }

    console.log(
      `[Proxy] ${init.method} ${targetUrl} | API_KEY: ${API_KEY ? "present" : "MISSING"}`,
    );

    const res = await fetch(targetUrl, {
      ...init,
      headers,
      cache: "no-store",
    });

    const data = await res.arrayBuffer();

    return new NextResponse(data, {
      status: res.status,
      headers: {
        "Content-Type": res.headers.get("Content-Type") || "application/json",
      },
    });
  } catch (e: any) {
    console.error(`[Proxy] ERROR to ${targetUrl}:`, e.message);
    return NextResponse.json(
      { error: "Backend unavailable", details: e.message },
      { status: 502 },
    );
  }
}
