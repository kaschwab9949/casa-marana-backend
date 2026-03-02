import { NextRequest } from "next/server";
import { requireApiKey } from "@/lib/security";
import { squareFetch } from "@/lib/square";

const E164_PHONE_REGEX = /^\+[1-9]\d{7,14}$/;
type JsonRecord = Record<string, unknown>;

function asTrimmedString(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const trimmed = input.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function asCustomerIdList(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return input
    .map(asTrimmedString)
    .filter((value): value is string => value !== null)
    .slice(0, 30);
}

function normalizeLimit(input: unknown): number {
  const parsed =
    typeof input === "number"
      ? input
      : typeof input === "string"
      ? Number.parseInt(input, 10)
      : Number.NaN;
  if (!Number.isFinite(parsed)) return 10;
  return Math.max(1, Math.min(50, parsed));
}

function asRecord(input: unknown): JsonRecord {
  if (typeof input === "object" && input !== null) {
    return input as JsonRecord;
  }
  return {};
}

function toNumber(input: unknown, fallback = 0): number {
  const parsed = typeof input === "number" ? input : Number(input);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeAccount(rawInput: unknown) {
  const raw = asRecord(rawInput);
  const mapping = asRecord(raw.mapping);
  return {
    id: typeof raw.id === "string" ? raw.id : "",
    phone_number: asTrimmedString(mapping.phone_number),
    customer_id: asTrimmedString(raw.customer_id),
    program_id: asTrimmedString(raw.program_id),
    balance: toNumber(raw.balance),
    lifetime_points: toNumber(raw.lifetime_points),
    created_at: asTrimmedString(raw.created_at),
    updated_at: asTrimmedString(raw.updated_at),
    enrolled_at: asTrimmedString(raw.enrolled_at),
  };
}

export async function POST(req: NextRequest) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  const body = await req.json().catch(() => ({}));
  const customerIds = asCustomerIdList(body?.customer_ids ?? body?.customerIds);
  const phone = asTrimmedString(body?.phone ?? body?.phone_number);
  const limit = normalizeLimit(body?.limit);

  let query: Record<string, unknown> = {};

  if (customerIds.length > 0) {
    query = { customer_ids: customerIds };
  } else if (phone) {
    if (!E164_PHONE_REGEX.test(phone)) {
      return Response.json(
        { error: "INVALID_PHONE_NUMBER. Use E.164 format, for example +16295551234." },
        { status: 400 }
      );
    }
    query = { mappings: [{ phone_number: phone }] };
  } else if (body?.query && typeof body.query === "object") {
    query = body.query;
  }

  const search = await squareFetch("/v2/loyalty/accounts/search", {
    method: "POST",
    body: JSON.stringify({ query, limit }),
  });

  if (!search.ok) {
    return Response.json(
      { error: "Square search failed", details: search.error },
      { status: 502 }
    );
  }

  const accounts = Array.isArray(search.data?.loyalty_accounts)
    ? search.data.loyalty_accounts.map(normalizeAccount)
    : [];

  return Response.json({
    accounts,
    cursor: asTrimmedString(search.data?.cursor),
  });
}
