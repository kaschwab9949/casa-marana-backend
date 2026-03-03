export const runtime = "nodejs";
import { Pool, PoolClient } from "pg";
import { requireApiKey } from "@/lib/auth";
import { squareFetch } from "@/lib/square";

const pool = new Pool({
  connectionString: process.env.SUPABASE_DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

let schemaReady = false;
const VENUE_LAT = 32.3568946;
const VENUE_LON = -111.0952091;
const VENUE_RADIUS_M = 150;
const SMART_CHECKIN_COOLDOWN_MS = 4 * 60 * 60 * 1000;
const SMART_CHECKIN_POINTS = 5;

type SmartCheckInResult = {
  visitQualified: boolean;
  awardedPoints: number;
  awardReason:
    | "outside_venue"
    | "cooldown_active"
    | "loyalty_lookup_failed"
    | "loyalty_enrollment_required"
    | "loyalty_adjust_failed"
    | "awarded";
  distanceM: number;
  loyaltyAccountId: string | null;
};

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
    CREATE TABLE IF NOT EXISTS smart_check_in_awards (
      id bigserial PRIMARY KEY,
      phone_e164 text NOT NULL,
      loyalty_account_id text NOT NULL,
      awarded_points integer NOT NULL,
      sampled_at timestamptz NOT NULL,
      awarded_at timestamptz NOT NULL DEFAULT now(),
      distance_m double precision,
      idempotency_key text NOT NULL,
      customer_birthday text,
      source_path text NOT NULL DEFAULT '/api/location/sample'
    );
  `);

  await client.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS smart_check_in_awards_phone_idempotency_idx
    ON smart_check_in_awards (phone_e164, idempotency_key);
  `);

  await client.query(`
    CREATE INDEX IF NOT EXISTS smart_check_in_awards_phone_awarded_idx
    ON smart_check_in_awards (phone_e164, awarded_at DESC);
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
      last_ran_at timestamptz NOT NULL,
      last_deleted_count bigint NOT NULL DEFAULT 0
    );
  `);

  await client.query(`
    ALTER TABLE maintenance_runs
    ADD COLUMN IF NOT EXISTS last_deleted_count bigint NOT NULL DEFAULT 0;
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

  const deleteRes = await client.query(`
    DELETE FROM location_samples
    WHERE sampled_at < now() - interval '365 days'
  `);
  const deletedCount = Number(deleteRes.rowCount ?? 0);

  await client.query(
    `
    INSERT INTO maintenance_runs (job_name, last_ran_at, last_deleted_count)
    VALUES ($1, now(), $2)
    ON CONFLICT (job_name)
    DO UPDATE SET
      last_ran_at = EXCLUDED.last_ran_at,
      last_deleted_count = EXCLUDED.last_deleted_count
    `,
    [jobName, deletedCount]
  );
}

function haversineDistanceMeters(
  latA: number,
  lonA: number,
  latB: number,
  lonB: number
): number {
  const toRadians = (value: number) => (value * Math.PI) / 180;
  const earthRadiusMeters = 6371000;
  const dLat = toRadians(latB - latA);
  const dLon = toRadians(lonB - lonA);
  const radA = toRadians(latA);
  const radB = toRadians(latB);
  const sinLat = Math.sin(dLat / 2);
  const sinLon = Math.sin(dLon / 2);
  const aa =
    sinLat * sinLat +
    Math.cos(radA) * Math.cos(radB) * sinLon * sinLon;
  const c = 2 * Math.atan2(Math.sqrt(aa), Math.sqrt(1 - aa));
  return earthRadiusMeters * c;
}

function idempotencyKeyForWindow(phone: string, referenceDate: Date): string {
  const bucket = Math.floor(referenceDate.getTime() / SMART_CHECKIN_COOLDOWN_MS);
  return `smart-checkin:${phone}:${bucket}`;
}

function asSquareErrorCodes(error: unknown): string[] {
  if (!error || typeof error !== "object") return [];
  const asRecord = error as Record<string, unknown>;
  const errors = Array.isArray(asRecord.errors) ? asRecord.errors : [];
  return errors
    .map((entry) => {
      if (!entry || typeof entry !== "object") return "";
      const code = (entry as Record<string, unknown>).code;
      return typeof code === "string" ? code.trim().toUpperCase() : "";
    })
    .filter((code) => code.length > 0);
}

async function awardSmartCheckInIfQualified(
  client: PoolClient,
  params: {
    phone: string;
    lat: number;
    lon: number;
    sampledAt: Date;
    customerBirthday: string | null;
    sourcePath: string;
  }
): Promise<SmartCheckInResult> {
  const { phone, lat, lon, sampledAt, customerBirthday, sourcePath } = params;

  const distanceM = haversineDistanceMeters(lat, lon, VENUE_LAT, VENUE_LON);
  if (distanceM > VENUE_RADIUS_M) {
    return {
      visitQualified: false,
      awardedPoints: 0,
      awardReason: "outside_venue",
      distanceM,
      loyaltyAccountId: null,
    };
  }

  const latestAwardRes = await client.query<{ awarded_at: Date }>(
    `
    SELECT awarded_at
    FROM smart_check_in_awards
    WHERE phone_e164 = $1
    ORDER BY awarded_at DESC
    LIMIT 1
    `,
    [phone]
  );
  const latestAwardedAt = latestAwardRes.rows[0]?.awarded_at;
  const now = Date.now();
  if (
    latestAwardedAt &&
    now - new Date(latestAwardedAt).getTime() < SMART_CHECKIN_COOLDOWN_MS
  ) {
    return {
      visitQualified: false,
      awardedPoints: 0,
      awardReason: "cooldown_active",
      distanceM,
      loyaltyAccountId: null,
    };
  }

  const lookup = await squareFetch("/v2/loyalty/accounts/search", {
    method: "POST",
    body: JSON.stringify({
      query: { mappings: [{ phone_number: phone }] },
      limit: 1,
    }),
  });
  if (!lookup.ok) {
    return {
      visitQualified: true,
      awardedPoints: 0,
      awardReason: "loyalty_lookup_failed",
      distanceM,
      loyaltyAccountId: null,
    };
  }

  const accounts = Array.isArray(lookup.data?.loyalty_accounts)
    ? lookup.data.loyalty_accounts
    : [];
  const loyaltyAccountID = String(accounts[0]?.id ?? "").trim();
  if (!loyaltyAccountID) {
    return {
      visitQualified: true,
      awardedPoints: 0,
      awardReason: "loyalty_enrollment_required",
      distanceM,
      loyaltyAccountId: null,
    };
  }

  const idempotencyKey = idempotencyKeyForWindow(phone, new Date(now));
  const adjust = await squareFetch(
    `/v2/loyalty/accounts/${encodeURIComponent(loyaltyAccountID)}/adjust`,
    {
      method: "POST",
      body: JSON.stringify({
        idempotency_key: idempotencyKey,
        adjust_points: {
          points: SMART_CHECKIN_POINTS,
          reason: "Smart Check-In visit bonus",
        },
      }),
    }
  );

  if (!adjust.ok) {
    const errorCodes = asSquareErrorCodes(adjust.error);
    if (errorCodes.includes("IDEMPOTENCY_KEY_REUSED")) {
      await client.query(
        `
        INSERT INTO smart_check_in_awards (
          phone_e164,
          loyalty_account_id,
          awarded_points,
          sampled_at,
          distance_m,
          idempotency_key,
          customer_birthday,
          source_path
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (phone_e164, idempotency_key) DO NOTHING
        `,
        [
          phone,
          loyaltyAccountID,
          SMART_CHECKIN_POINTS,
          sampledAt,
          distanceM,
          idempotencyKey,
          customerBirthday,
          sourcePath,
        ]
      );

      return {
        visitQualified: true,
        awardedPoints: SMART_CHECKIN_POINTS,
        awardReason: "awarded",
        distanceM,
        loyaltyAccountId: loyaltyAccountID,
      };
    }

    return {
      visitQualified: true,
      awardedPoints: 0,
      awardReason: "loyalty_adjust_failed",
      distanceM,
      loyaltyAccountId: loyaltyAccountID,
    };
  }

  await client.query(
    `
    INSERT INTO smart_check_in_awards (
      phone_e164,
      loyalty_account_id,
      awarded_points,
      sampled_at,
      distance_m,
      idempotency_key,
      customer_birthday,
      source_path
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    ON CONFLICT (phone_e164, idempotency_key) DO NOTHING
    `,
    [
      phone,
      loyaltyAccountID,
      SMART_CHECKIN_POINTS,
      sampledAt,
      distanceM,
      idempotencyKey,
      customerBirthday,
      sourcePath,
    ]
  );

  return {
    visitQualified: true,
    awardedPoints: SMART_CHECKIN_POINTS,
    awardReason: "awarded",
    distanceM,
    loyaltyAccountId: loyaltyAccountID,
  };
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
    const sampledAt = new Date(timestamp * 1000);

    const client = await pool.connect();
    let smartCheckIn: SmartCheckInResult = {
      visitQualified: false,
      awardedPoints: 0,
      awardReason: "outside_venue",
      distanceM: haversineDistanceMeters(lat, lon, VENUE_LAT, VENUE_LON),
      loyaltyAccountId: null,
    };
    try {
      await ensureSchema(client);
      await runDailyRetention(client);

      await client.query(
        `INSERT INTO location_samples (phone_e164, sampled_at, lat, lon, accuracy_m, customer_birthday)
         VALUES ($1, to_timestamp($2), $3, $4, $5, $6)`,
        [phone, timestamp, lat, lon, accuracy, customerBirthday]
      );

      smartCheckIn = await awardSmartCheckInIfQualified(client, {
        phone,
        lat,
        lon,
        sampledAt,
        customerBirthday,
        sourcePath,
      });
    } finally {
      client.release();
    }

    return Response.json({
      ok: true,
      sourcePath,
      canonicalPath: "/api/location/sample",
      visitQualified: smartCheckIn.visitQualified,
      awardedPoints: smartCheckIn.awardedPoints,
      awardReason: smartCheckIn.awardReason,
      distanceM: smartCheckIn.distanceM,
      loyaltyAccountId: smartCheckIn.loyaltyAccountId,
    });
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
