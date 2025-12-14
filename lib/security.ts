import { NextRequest } from "next/server";

export function requireApiKey(req: NextRequest) {
  const key = req.headers.get("x-api-key");
  if (!key || key !== process.env.API_KEY) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
  }
  return null;
}
