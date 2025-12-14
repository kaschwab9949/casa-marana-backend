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
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }

  if (!res.ok) {
    return { ok: false as const, status: res.status, error: json };
  }
  return { ok: true as const, status: res.status, data: json };
}
