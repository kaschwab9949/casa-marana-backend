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

function fallbackNameFromPhone(phoneE164: string): string {
  const digitsOnly = phoneE164.replace(/\D/g, "");
  const suffix = digitsOnly.slice(-4);
  return suffix.length === 0 ? "Member" : `Member ${suffix}`;
}

export async function POST(req: NextRequest) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  if (!process.env.SUPABASE_DATABASE_URL) {
    return Response.json({ error: "Missing SUPABASE_DATABASE_URL" }, { status: 500 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const phone = String(body?.phone ?? "").trim();
  const displayNameRaw = String(body?.displayName ?? "").trim();
  const score = Number(body?.score);

  if (!phone) return Response.json({ error: "Missing phone" }, { status: 400 });
  if (!Number.isFinite(score) || score < 0) {
    return Response.json({ error: "Invalid score" }, { status: 400 });
  }

  const submittedScore = Math.floor(score);
  const safeName =
    displayNameRaw.length > 0
      ? displayNameRaw.slice(0, 60)
      : fallbackNameFromPhone(phone);

  try {
    await ensureSchema();

    const result = await pool.query(
      `
      INSERT INTO snake_scores (phone_e164, display_name, high_score)
      VALUES ($1, $2, $3)
      ON CONFLICT (phone_e164)
      DO UPDATE SET
        display_name = EXCLUDED.display_name,
        high_score = GREATEST(snake_scores.high_score, EXCLUDED.high_score),
        updated_at = now()
      RETURNING high_score
      `,
      [phone, safeName, submittedScore]
    );

    return Response.json({
      ok: true,
      submittedScore,
      highScore: Number(result.rows[0]?.high_score ?? submittedScore),
    });
  } catch (err: any) {
    return Response.json(
      { error: "Server error", detail: String(err?.message ?? err) },
      { status: 500 }
    );
  }
}
