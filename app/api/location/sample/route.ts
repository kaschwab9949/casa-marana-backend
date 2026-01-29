export const runtime = "nodejs";
import { Pool } from "pg";

const pool = new Pool({
  connectionString: process.env.SUPABASE_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function runDailyRetention(client: any) {
  const jobName = "location_samples_retention_365d";

  await client.query(`
    CREATE TABLE IF NOT EXISTS maintenance_runs (
      job_name text PRIMARY KEY,
      last_ran_at timestamptz NOT NULL
    );
  `);

  const res = await client.query(
    `SELECT last_ran_at FROM maintenance_runs WHERE job_name = $1`,
    [jobName]
  );

  const now = Date.now();
  const last = res.rows[0]?.last_ran_at
    ? new Date(res.rows[0].last_ran_at).getTime()
    : 0;

  if (last && now - last < 24 * 60 * 60 * 1000) return;

  await client.query(`
    DELETE FROM location_samples
    WHERE received_at < now() - interval '365 days'
  `);

  await client.query(
    `
    INSERT INTO maintenance_runs (job_name, last_ran_at)
    VALUES ($1, now())
    ON CONFLICT (job_name)
    DO UPDATE SET last_ran_at = EXCLUDED.last_ran_at
    `,
    [jobName]
  );
}

export async function POST(req: Request) {
  try {
    const body = await req.json();

    const phone = String(body.phone || "").trim();
    const lat = Number(body.lat);
    const lon = Number(body.lon);
    const accuracy =
      body.accuracy === undefined || body.accuracy === null
        ? null
        : Number(body.accuracy);
    const timestamp = Number(body.timestamp);

    if (!process.env.SUPABASE_DATABASE_URL) {
      return Response.json(
        { error: "Missing SUPABASE_DATABASE_URL" },
        { status: 500 }
      );
    }

    if (!phone) return Response.json({ error: "Missing phone" }, { status: 400 });
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
      return Response.json({ error: "Invalid lat/lon" }, { status: 400 });
    }
    if (!Number.isFinite(timestamp)) {
      return Response.json({ error: "Invalid timestamp" }, { status: 400 });
    }

    const client = await pool.connect();
    try {
      await runDailyRetention(client);

      await client.query(
        `INSERT INTO location_samples (phone_e164, sampled_at, lat, lon, accuracy_m)
         VALUES ($1, to_timestamp($2), $3, $4, $5)`,
        [phone, timestamp, lat, lon, accuracy]
      );
    } finally {
      client.release();
    }

    return Response.json({ ok: true });
  } catch (err: any) {
    return Response.json(
      { error: "Server error", detail: String(err?.message ?? err) },
      { status: 500 }
    );
  }
}
