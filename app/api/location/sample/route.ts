export const runtime = "nodejs";
import { Pool, PoolClient } from "pg";
import { requireApiKey } from "@/lib/auth";

const pool = new Pool({
  connectionString: process.env.SUPABASE_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

let schemaReady = false;

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

function fullYearFromTwoDigit(year: number, referenceDate: Date = new Date()): number {
  const clamped = Math.max(0, Math.min(99, year));
  const currentYear = referenceDate.getUTCFullYear();
  const currentCentury = Math.floor(currentYear / 100) * 100;
  const currentTwoDigit = currentYear % 100;

  if (clamped <= currentTwoDigit) return currentCentury + clamped;
  return currentCentury - 100 + clamped;
}

function normalizeBirthday(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  if (!trimmed) return null;

  const cleaned = trimmed.replace(/[-.]/g, "/");
  const parts = cleaned.split("/");
  if (parts.length !== 3) return null;

  const first = Number(parts[0]);
  const second = Number(parts[1]);
  const third = Number(parts[2]);
  if (!Number.isInteger(first) || !Number.isInteger(second) || !Number.isInteger(third)) {
    return null;
  }

  let month: number;
  let day: number;
  let year: number;

  if (parts[0].length === 4) {
    // Backward compatibility for YYYY-MM-DD values.
    year = first;
    month = second;
    day = third;
  } else {
    month = first;
    day = second;
    if (parts[2].length === 4) {
      year = third;
    } else if (parts[2].length <= 2) {
      year = fullYearFromTwoDigit(third);
    } else {
      return null;
    }
  }

  if (month < 1 || month > 12) return null;
  if (day < 1 || day > 31) return null;
  if (year < 1 || year > 9999) return null;

  const candidate = new Date(Date.UTC(year, month - 1, day));
  if (
    candidate.getUTCFullYear() !== year ||
    candidate.getUTCMonth() !== month - 1 ||
    candidate.getUTCDate() !== day
  ) {
    return null;
  }

  return `${String(month).padStart(2, "0")}/${String(day).padStart(2, "0")}/${String(
    year % 100
  ).padStart(2, "0")}`;
}

async function ensureSchema(client: PoolClient) {
  if (schemaReady) return;

  await client.query(`
    CREATE TABLE IF NOT EXISTS location_samples (
      id bigserial PRIMARY KEY,
      phone_e164 text NOT NULL,
      sampled_at timestamptz NOT NULL,
      lat double precision NOT NULL,
      lon double precision NOT NULL,
      accuracy_m double precision,
      customer_birthday text,
      received_at timestamptz NOT NULL DEFAULT now()
    );
  `);

  await client.query(`
    ALTER TABLE location_samples
    ADD COLUMN IF NOT EXISTS customer_birthday text;
  `);

  await client.query(`
    ALTER TABLE location_samples
    ADD COLUMN IF NOT EXISTS received_at timestamptz NOT NULL DEFAULT now();
  `);

  await client.query(`
    CREATE INDEX IF NOT EXISTS location_samples_phone_sampled_idx
    ON location_samples (phone_e164, sampled_at DESC);
  `);

  await client.query(`
    CREATE INDEX IF NOT EXISTS location_samples_received_idx
    ON location_samples (received_at DESC);
  `);

  schemaReady = true;
}

async function runDailyRetention(client: PoolClient) {
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
    WHERE sampled_at < now() - interval '365 days'
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

export async function handleLocationSample(
  req: Request,
  sourcePath = "/api/location/sample"
) {
  const gate = requireApiKey(req);
  if (gate) return gate;

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
    const rawBirthday =
      body.customerBirthday ?? body.customer_birthday ?? body.birthday;
    const hasBirthdayField = rawBirthday !== undefined && rawBirthday !== null;
    const hasBirthdayValue =
      typeof rawBirthday === "string" && rawBirthday.trim().length > 0;
    const customerBirthday = normalizeBirthday(rawBirthday);

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
    if (hasBirthdayField && typeof rawBirthday !== "string") {
      return Response.json(
        { error: "Invalid customerBirthday format. Use MM/DD/YY." },
        { status: 400 }
      );
    }
    if (hasBirthdayValue && !customerBirthday) {
      return Response.json(
        { error: "Invalid customerBirthday format. Use MM/DD/YY." },
        { status: 400 }
      );
    }

    const client = await pool.connect();
    try {
      await ensureSchema(client);
      await runDailyRetention(client);

      await client.query(
        `INSERT INTO location_samples (phone_e164, sampled_at, lat, lon, accuracy_m, customer_birthday)
         VALUES ($1, to_timestamp($2), $3, $4, $5, $6)`,
        [phone, timestamp, lat, lon, accuracy, customerBirthday]
      );
    } finally {
      client.release();
    }

    return Response.json({ ok: true, sourcePath, canonicalPath: "/api/location/sample" });
  } catch (err: unknown) {
    return Response.json(
      { error: "Server error", detail: errorMessage(err) },
      { status: 500 }
    );
  }
}

export async function POST(req: Request) {
  return handleLocationSample(req);
}
