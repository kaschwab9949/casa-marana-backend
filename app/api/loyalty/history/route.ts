import { NextRequest } from "next/server";
import { requireApiKey } from "@/lib/security";
import { squareFetch } from "@/lib/square";

export async function GET(req: NextRequest) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  const phone = req.nextUrl.searchParams.get("phone");
  if (!phone) return Response.json({ error: "Missing phone" }, { status: 400 });

  const search = await squareFetch("/v2/loyalty/accounts/search", {
    method: "POST",
    body: JSON.stringify({
      query: { mappings: [{ phone_number: phone.trim() }] },
    }),
  });

  if (!search.ok) {
    return Response.json(
      { error: "Square search failed", details: search.error },
      { status: 502 }
    );
  }

  const accounts = search.data?.loyalty_accounts ?? [];
  if (accounts.length === 0) return Response.json({ enrolled: false, events: [] }, { status: 200 });

  const accountId = accounts[0].id;

  const events = await squareFetch("/v2/loyalty/events/search", {
    method: "POST",
    body: JSON.stringify({ query: { loyalty_account_id: accountId }, limit: 50 }),
  });

  if (!events.ok) {
    return Response.json(
      { error: "Square events failed", details: events.error },
      { status: 502 }
    );
  }

  return Response.json({
    enrolled: true,
    accountId,
    events: (events.data?.events ?? []).map((e: any) => ({
      id: e.id,
      type: e.type,
      createdAt: e.created_at,
      points: e.points,
    })),
  });
}
