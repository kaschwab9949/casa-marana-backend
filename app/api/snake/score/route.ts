export const runtime = "nodejs";

import { NextRequest } from "next/server";
import { Pool } from "pg";
import { requireApiKey } from "@/lib/security";
import { squareFetch } from "@/lib/square";

const pool = new Pool({
  connectionString: process.env.SUPABASE_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

let schemaReady = false;

type ScoreRequestBody = {
  phone?: string;
  displayName?: string;
  score?: number;
};

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

async function ensureSchema() {
  if (schemaReady) return;

  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS snake_scores (
        phone_e164 text PRIMARY KEY,
        display_name text NOT NULL,
        high_score integer NOT NULL DEFAULT 0 CHECK (high_score >= 0),
        loyalty_member boolean NOT NULL DEFAULT false,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
    `);

    await client.query(`
      ALTER TABLE snake_scores
      ADD COLUMN IF NOT EXISTS loyalty_member boolean NOT NULL DEFAULT false;
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS snake_scores_high_score_idx
      ON snake_scores (high_score DESC, updated_at ASC);
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS snake_scores_loyalty_member_high_score_idx
      ON snake_scores (high_score DESC, updated_at ASC)
      WHERE loyalty_member = true;
    `);

    schemaReady = true;
  } finally {
    client.release();
  }
}

async function isLoyaltyMember(phoneE164: string): Promise<{ ok: boolean; enrolled: boolean }> {
  const search = await squareFetch("/v2/loyalty/accounts/search", {
    method: "POST",
    body: JSON.stringify({
      query: { mappings: [{ phone_number: phoneE164 }] },
      limit: 1,
    }),
  });

  if (!search.ok) {
    return { ok: false, enrolled: false };
  }

  const accounts = Array.isArray(search.data?.loyalty_accounts) ? search.data.loyalty_accounts : [];
  return { ok: true, enrolled: accounts.length > 0 };
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

  let body: ScoreRequestBody;
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

    const membership = await isLoyaltyMember(phone);
    if (!membership.ok) {
      return Response.json(
        { error: "Could not verify Square loyalty membership right now." },
        { status: 502 }
      );
    }
    if (!membership.enrolled) {
      return Response.json(
        { error: "Loyalty enrollment required to submit leaderboard scores." },
        { status: 403 }
      );
    }

    const result = await pool.query(
      `
      INSERT INTO snake_scores (phone_e164, display_name, high_score, loyalty_member)
      VALUES ($1, $2, $3, true)
      ON CONFLICT (phone_e164)
      DO UPDATE SET
        display_name = EXCLUDED.display_name,
        high_score = GREATEST(snake_scores.high_score, EXCLUDED.high_score),
        loyalty_member = true,
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
  } catch (err: unknown) {
    return Response.json(
      { error: "Server error", detail: errorMessage(err) },
      { status: 500 }
    );
  }
}
