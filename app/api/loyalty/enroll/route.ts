import { NextRequest } from "next/server";
import { requireApiKey } from "@/lib/security";
import { squareFetch } from "@/lib/square";

export async function POST(req: NextRequest) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  const body = await req.json().catch(() => null);
  const phone = body?.phone;
  if (!phone) return Response.json({ error: "Missing phone" }, { status: 400 });

  const created = await squareFetch("/v2/loyalty/accounts", {
    method: "POST",
    body: JSON.stringify({ mapping: { phone_number: String(phone).trim() } }),
  });

  if (!created.ok) {
    return Response.json(
      { error: "Square create failed", details: created.error },
      { status: 502 }
    );
  }

  return Response.json({ enrolled: true, account: created.data?.loyalty_account });
}
