export const runtime = "nodejs";

import { Pool } from "pg";
import { requireApiKey } from "@/lib/auth";
import { squareFetch } from "@/lib/square";

const E164_REGEX = /^\+[1-9]\d{7,14}$/;

let pool: Pool | null = null;

type PgLikeError = {
  code?: string;
  message?: string;
};

type LoyaltyAccount = {
  id?: string;
};

type LoyaltySearchResponse = {
  loyalty_accounts?: LoyaltyAccount[];
};

function asPgLikeError(error: unknown): PgLikeError {
  if (typeof error !== "object" || error === null) return {};
  const cast = error as Record<string, unknown>;
  return {
    code: typeof cast.code === "string" ? cast.code : undefined,
    message: typeof cast.message === "string" ? cast.message : undefined,
  };
}

function asLoyaltySearchResponse(value: unknown): LoyaltySearchResponse {
  if (typeof value !== "object" || value === null) return {};
  return value as LoyaltySearchResponse;
}

function getPool(): Pool | null {
  const conn = process.env.SUPABASE_DATABASE_URL;
  if (!conn) return null;
  if (!pool) {
    pool = new Pool({
      connectionString: conn,
      ssl: { rejectUnauthorized: false },
    });
  }
  return pool;
}

function trim(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.trim();
}

async function cleanupLocalData(phone: string) {
  const db = getPool();
  if (!db) {
    return {
      snakeScoresDeleted: 0,
      locationSamplesDeleted: 0,
      warnings: ["SUPABASE_DATABASE_URL missing; skipped local cleanup."],
    };
  }

  const warnings: string[] = [];
  let snakeScoresDeleted = 0;
  let locationSamplesDeleted = 0;

  const client = await db.connect();
  try {
    try {
      const result = await client.query(
        "DELETE FROM snake_scores WHERE phone_e164 = $1",
        [phone]
      );
      snakeScoresDeleted = result.rowCount ?? 0;
    } catch (error: unknown) {
      const pgError = asPgLikeError(error);
      if (pgError.code !== "42P01") {
        warnings.push(
          `snake_scores cleanup failed: ${String(pgError.message ?? error)}`
        );
      } else {
        warnings.push("snake_scores table not found; skipped.");
      }
    }

    try {
      const result = await client.query(
        "DELETE FROM location_samples WHERE phone_e164 = $1",
        [phone]
      );
      locationSamplesDeleted = result.rowCount ?? 0;
    } catch (error: unknown) {
      const pgError = asPgLikeError(error);
      if (pgError.code !== "42P01") {
        warnings.push(
          `location_samples cleanup failed: ${String(pgError.message ?? error)}`
        );
      } else {
        warnings.push("location_samples table not found; skipped.");
      }
    }
  } finally {
    client.release();
  }

  return {
    snakeScoresDeleted,
    locationSamplesDeleted,
    warnings,
  };
}

async function cleanupSquareLoyalty(phone: string) {
  const warnings: string[] = [];

  const search = await squareFetch("/v2/loyalty/accounts/search", {
    method: "POST",
    body: JSON.stringify({
      query: { mappings: [{ phone_number: phone }] },
      limit: 30,
    }),
  });

  if (!search.ok) {
    warnings.push(`Square loyalty search failed: ${JSON.stringify(search.error ?? {})}`);
    return {
      accountsFound: 0,
      accountsDeleted: 0,
      warnings,
    };
  }

  const data = asLoyaltySearchResponse(search.data);
  const accounts = Array.isArray(data.loyalty_accounts) ? data.loyalty_accounts : [];

  let accountsDeleted = 0;
  for (const account of accounts) {
    const accountId = trim(account?.id);
    if (!accountId) continue;

    const deleted = await squareFetch(`/v2/loyalty/accounts/${accountId}`, {
      method: "DELETE",
    });

    if (deleted.ok) {
      accountsDeleted += 1;
    } else {
      warnings.push(
        `Square delete failed for account ${accountId}: ${JSON.stringify(deleted.error ?? {})}`
      );
    }
  }

  return {
    accountsFound: accounts.length,
    accountsDeleted,
    warnings,
  };
}

export async function handleAccountDelete(
  req: Request,
  sourcePath = "/api/account/delete",
  deprecated = false
) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  const body = await req.json().catch(() => ({}));
  const phone = trim(body?.phone ?? body?.phone_number);

  if (!phone) {
    return Response.json({ error: "Missing phone" }, { status: 400 });
  }

  if (!E164_REGEX.test(phone)) {
    return Response.json(
      { error: "INVALID_PHONE_NUMBER. Use E.164 format, for example +16295551234." },
      { status: 400 }
    );
  }

  const localCleanup = await cleanupLocalData(phone);
  const squareCleanup = await cleanupSquareLoyalty(phone);

  return Response.json(
    {
      ok: true,
      phone,
      sourcePath,
      canonicalPath: "/api/account/delete",
      deprecatedEndpoint: deprecated,
      local: {
        snakeScoresDeleted: localCleanup.snakeScoresDeleted,
        locationSamplesDeleted: localCleanup.locationSamplesDeleted,
      },
      square: {
        accountsFound: squareCleanup.accountsFound,
        accountsDeleted: squareCleanup.accountsDeleted,
      },
      warnings: [...localCleanup.warnings, ...squareCleanup.warnings],
    },
    { status: 200 }
  );
}

export async function POST(req: Request) {
  return handleAccountDelete(req);
}
