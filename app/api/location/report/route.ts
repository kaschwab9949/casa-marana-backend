export const runtime = "nodejs";

import { Pool } from "pg";
import { requireApiKey } from "@/lib/auth";

const pool = new Pool({
  connectionString: process.env.SUPABASE_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

function parseLimit(raw: string | null): number {
  const parsed = Number(raw ?? "100");
  if (!Number.isFinite(parsed)) return 100;
  return Math.max(1, Math.min(500, Math.floor(parsed)));
}

function parseBigIntString(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

export async function GET(req: Request) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  if (!process.env.SUPABASE_DATABASE_URL) {
    return Response.json(
      { error: "Missing SUPABASE_DATABASE_URL" },
      { status: 500 }
    );
  }

  const url = new URL(req.url);
  const phone = String(url.searchParams.get("phone") ?? "").trim();
  const limit = parseLimit(url.searchParams.get("limit"));

  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS maintenance_runs (
        job_name text PRIMARY KEY,
        last_ran_at timestamptz NOT NULL,
        last_deleted_count bigint NOT NULL DEFAULT 0
      );
    `);

    const summaryRes = await client.query(`
      SELECT
        count(*)::bigint AS total_rows,
        count(*) FILTER (
          WHERE customer_birthday IS NOT NULL
            AND btrim(customer_birthday) <> ''
        )::bigint AS rows_with_birthday,
        min(sampled_at) AS first_sampled_at,
        max(sampled_at) AS last_sampled_at,
        count(*) FILTER (
          WHERE sampled_at < now() - interval '365 days'
        )::bigint AS rows_older_than_365_days
      FROM location_samples
    `);

    const samplesRes = phone
      ? await client.query(
          `
          SELECT
            id,
            phone_e164,
            sampled_at,
            received_at,
            lat,
            lon,
            accuracy_m,
            customer_birthday
          FROM location_samples
          WHERE phone_e164 = $1
          ORDER BY sampled_at DESC
          LIMIT $2
          `,
          [phone, limit]
        )
      : await client.query(
          `
          SELECT
            id,
            phone_e164,
            sampled_at,
            received_at,
            lat,
            lon,
            accuracy_m,
            customer_birthday
          FROM location_samples
          ORDER BY sampled_at DESC
          LIMIT $1
          `,
          [limit]
        );

    const maintenanceRes = await client.query(
      `
      SELECT last_ran_at, last_deleted_count
      FROM maintenance_runs
      WHERE job_name = $1
      `,
      ["location_samples_retention_365d"]
    );

    const summary = summaryRes.rows[0] ?? {};
    const maintenance = maintenanceRes.rows[0] ?? null;

    return Response.json({
      ok: true,
      retentionDays: 365,
      filters: {
        phone: phone || null,
        limit,
      },
      summary: {
        totalRows: parseBigIntString(summary.total_rows),
        rowsWithBirthday: parseBigIntString(summary.rows_with_birthday),
        rowsWithoutBirthday:
          parseBigIntString(summary.total_rows) -
          parseBigIntString(summary.rows_with_birthday),
        oldestSampledAt: summary.first_sampled_at ?? null,
        newestSampledAt: summary.last_sampled_at ?? null,
        rowsOlderThan365Days: parseBigIntString(summary.rows_older_than_365_days),
      },
      maintenance: maintenance
        ? {
            lastRanAt: maintenance.last_ran_at ?? null,
            lastDeletedCount: parseBigIntString(maintenance.last_deleted_count),
          }
        : null,
      samples: samplesRes.rows.map((row) => ({
        id: row.id,
        phone: row.phone_e164,
        sampledAt: row.sampled_at,
        receivedAt: row.received_at,
        lat: row.lat,
        lon: row.lon,
        accuracyM: row.accuracy_m,
        customerBirthday: row.customer_birthday,
      })),
      reportedAt: new Date().toISOString(),
    });
  } catch (err: unknown) {
    const maybeCode = (err as { code?: string } | null)?.code;
    if (maybeCode === "42P01") {
      return Response.json(
        {
          error:
            "location_samples table not found. Send a Smart Check-In sample first or run schema setup.",
        },
        { status: 404 }
      );
    }

    return Response.json(
      { error: "Server error", detail: errorMessage(err) },
      { status: 500 }
    );
  } finally {
    client.release();
  }
}
