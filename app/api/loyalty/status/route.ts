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
  if (accounts.length === 0) return Response.json({ enrolled: false }, { status: 200 });

  const accountId = accounts[0].id;

  const acct = await squareFetch(`/v2/loyalty/accounts/${accountId}`, { method: "GET" });
  if (!acct.ok) {
    return Response.json(
      { error: "Square retrieve failed", details: acct.error },
      { status: 502 }
    );
  }

  const program = await squareFetch("/v2/loyalty/programs/main", { method: "GET" });
  if (!program.ok) {
    return Response.json(
      { error: "Square program failed", details: program.error },
      { status: 502 }
    );
  }

  const points = acct.data?.loyalty_account?.balance ?? 0;
  const rewardTiers = program.data?.program?.reward_tiers ?? [];

  return Response.json({
    enrolled: true,
    accountId,
    points,
    rewardTiers: rewardTiers.map((t: any) => ({ id: t.id, name: t.name, points: t.points })),
  });
}
