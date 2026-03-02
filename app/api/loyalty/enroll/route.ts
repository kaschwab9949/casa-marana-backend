import { NextRequest } from "next/server";
import { requireApiKey } from "@/lib/security";
import { squareFetch } from "@/lib/square";

const E164_PHONE_REGEX = /^\+[1-9]\d{7,14}$/;

function normalizePhone(input: unknown): string {
  return typeof input === "string" ? input.trim() : "";
}

function normalizeCustomerId(input: unknown): string | undefined {
  if (typeof input !== "string") return undefined;
  const trimmed = input.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

async function getMainProgramId() {
  const program = await squareFetch("/v2/loyalty/programs/main", { method: "GET" });
  if (!program.ok) {
    return { ok: false as const, error: program.error };
  }

  const programId = program.data?.program?.id;
  if (!programId || typeof programId !== "string") {
    return { ok: false as const, error: "Missing loyalty program ID from Square response." };
  }

  return { ok: true as const, programId };
}

async function searchAccountByPhone(phone: string) {
  return squareFetch("/v2/loyalty/accounts/search", {
    method: "POST",
    body: JSON.stringify({
      query: { mappings: [{ phone_number: phone }] },
      limit: 1,
    }),
  });
}

export async function POST(req: NextRequest) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  const body = await req.json().catch(() => null);
  const phone = normalizePhone(body?.phone ?? body?.phone_number ?? body?.mapping?.phone_number);
  const customerId = normalizeCustomerId(body?.customer_id ?? body?.customerId);
  const providedIdempotency = normalizeCustomerId(body?.idempotency_key ?? body?.idempotencyKey);

  if (!phone) {
    return Response.json({ error: "Missing phone_number in E.164 format." }, { status: 400 });
  }

  if (!E164_PHONE_REGEX.test(phone)) {
    return Response.json(
      { error: "INVALID_PHONE_NUMBER. Use E.164 format, for example +16295551234." },
      { status: 400 }
    );
  }

  const existing = await searchAccountByPhone(phone);
  if (!existing.ok) {
    return Response.json(
      { error: "Square search failed", details: existing.error },
      { status: 502 }
    );
  }

  const existingAccount = existing.data?.loyalty_accounts?.[0] ?? null;
  if (existingAccount) {
    return Response.json({ enrolled: true, created: false, account: existingAccount }, { status: 200 });
  }

  const program = await getMainProgramId();
  if (!program.ok) {
    return Response.json(
      { error: "Square program failed", details: program.error },
      { status: 502 }
    );
  }

  const created = await squareFetch("/v2/loyalty/accounts", {
    method: "POST",
    body: JSON.stringify({
      loyalty_account: {
        mapping: { phone_number: phone },
        program_id: program.programId,
        ...(customerId ? { customer_id: customerId } : {}),
      },
      idempotency_key: providedIdempotency ?? crypto.randomUUID(),
    }),
  });

  if (!created.ok) {
    const serialized = JSON.stringify(created.error ?? "").toLowerCase();
    const isAlreadyMapped =
      serialized.includes("mapping_already_exists") ||
      serialized.includes("already exists") ||
      serialized.includes("duplicate");

    if (isAlreadyMapped) {
      const retry = await searchAccountByPhone(phone);
      if (retry.ok) {
        const retryAccount = retry.data?.loyalty_accounts?.[0] ?? null;
        if (retryAccount) {
          return Response.json({ enrolled: true, created: false, account: retryAccount }, { status: 200 });
        }
      }
    }

    return Response.json(
      { error: "Square create failed", details: created.error },
      { status: 502 }
    );
  }

  return Response.json(
    {
      enrolled: true,
      created: true,
      account: created.data?.loyalty_account ?? null,
    },
    { status: 200 }
  );
}
