export const runtime = "nodejs";

import { NextRequest } from "next/server";
import { Pool } from "pg";
import { requireApiKey } from "@/lib/security";

const pool = new Pool({
  connectionString: process.env.SUPABASE_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

let schemaReady = false;

async function ensureSchema() {
  if (schemaReady) return;

  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS snake_scores (
        phone_e164 text PRIMARY KEY,
        display_name text NOT NULL,
        high_score integer NOT NULL DEFAULT 0 CHECK (high_score >= 0),
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS snake_scores_high_score_idx
      ON snake_scores (high_score DESC, updated_at ASC);
    `);

    schemaReady = true;
  } finally {
    client.release();
  }
}

export async function GET(req: NextRequest) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  if (!process.env.SUPABASE_DATABASE_URL) {
    return Response.json({ error: "Missing SUPABASE_DATABASE_URL" }, { status: 500 });
  }

  const rawLimit = Number(req.nextUrl.searchParams.get("limit") ?? 25);
  const limit = Number.isFinite(rawLimit)
    ? Math.max(1, Math.min(100, Math.floor(rawLimit)))
    : 25;

  const viewerPhone = String(req.nextUrl.searchParams.get("phone") ?? "").trim();

  try {
    await ensureSchema();

    const result = await pool.query(
      `
      SELECT phone_e164, display_name, high_score
      FROM snake_scores
      ORDER BY high_score DESC, updated_at ASC
      LIMIT $1
      `,
      [limit]
    );

    const entries = result.rows.map((row: any, index: number) => ({
      rank: index + 1,
      displayName: String(row.display_name ?? "Member"),
      score: Number(row.high_score ?? 0),
      isCurrentUser: viewerPhone.length > 0 && viewerPhone === String(row.phone_e164 ?? ""),
    }));

    return Response.json({
      entries,
      count: entries.length,
    });
  } catch (err: any) {
    return Response.json(
      { error: "Server error", detail: String(err?.message ?? err) },
      { status: 500 }
    );
  }
}
