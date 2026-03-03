import { NextRequest } from "next/server";

const BEARER_PREFIX_REGEX = /^Bearer\s+/i;

function trim(value: string | null | undefined): string {
  return (value ?? "").trim();
}

export function expectedApiKey(): string {
  const preferred = trim(process.env.CASA_APP_API_KEY);
  if (preferred.length > 0) return preferred;
  return trim(process.env.API_KEY);
}

export function extractApiKeyFromHeaders(headers: Headers): string {
  const explicit = trim(headers.get("x-api-key"));
  if (explicit.length > 0) return explicit;

  const auth = trim(headers.get("authorization"));
  if (auth.length === 0) return "";
  return auth.replace(BEARER_PREFIX_REGEX, "").trim();
}

export function isApiKeyAuthorized(headers: Headers): boolean {
  const expected = expectedApiKey();
  if (expected.length === 0) return false;

  const got = extractApiKeyFromHeaders(headers);
  return got.length > 0 && got === expected;
}

export function unauthorizedResponse() {
  return new Response(JSON.stringify({ error: "Unauthorized" }), {
    status: 401,
    headers: { "content-type": "application/json" },
  });
}

export function requireApiKey(req: NextRequest | Request) {
  if (!isApiKeyAuthorized(req.headers)) {
    return unauthorizedResponse();
  }
  return null;
}
