const env = (process.env.SQUARE_ENV ?? "production").toLowerCase();

export const SQUARE_BASE =
  env === "sandbox"
    ? "https://connect.squareupsandbox.com"
    : "https://connect.squareup.com";

export function squareHeaders() {
  const token = process.env.SQUARE_ACCESS_TOKEN;
  const version = process.env.SQUARE_VERSION;

  if (!token) throw new Error("Missing SQUARE_ACCESS_TOKEN");
  if (!version) throw new Error("Missing SQUARE_VERSION");

  return {
    Authorization: `Bearer ${token}`,
    "Square-Version": version,
    "Content-Type": "application/json",
  };
}

// Square responses are dynamic JSON objects; callers validate fields before use.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type JsonObject = Record<string, any>;

function asJsonObject(value: unknown): JsonObject | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as JsonObject;
}

export async function squareFetch(path: string, init?: RequestInit) {
  const res = await fetch(`${SQUARE_BASE}${path}`, {
    ...init,
    headers: {
      ...squareHeaders(),
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });

  const text = await res.text();
  let parsed: unknown = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }

  const json = asJsonObject(parsed) ?? {};

  if (!res.ok) {
    return { ok: false as const, status: res.status, error: json };
  }
  return { ok: true as const, status: res.status, data: json };
}
