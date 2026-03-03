import { NextRequest } from "next/server";
import { requireApiKey } from "@/lib/security";
import { squareFetch } from "@/lib/square";

type JsonRecord = Record<string, unknown>;

type RewardTier = { id: string; name: string; points: number };

function asRecord(value: unknown): JsonRecord {
  if (typeof value === "object" && value !== null) {
    return value as JsonRecord;
  }
  return {};
}

function asTrimmedString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function toNumber(value: unknown, fallback = 0): number {
  const numeric =
    typeof value === "number" ? value : typeof value === "string" ? Number(value) : Number.NaN;
  if (!Number.isFinite(numeric)) return fallback;
  return numeric;
}

function normalizeRewardTiers(input: unknown): RewardTier[] {
  if (!Array.isArray(input)) return [];
  return input
    .map((tierRaw) => {
      const tier = asRecord(tierRaw);
      const name = asTrimmedString(tier.name) ?? "Reward";
      const points = Math.max(0, Math.floor(toNumber(tier.points)));
      const id = asTrimmedString(tier.id) ?? `${name}-${points}`;
      return { id, name, points };
    })
    .filter((tier) => tier.name.length > 0);
}

function deriveTierName(points: number, tiers: RewardTier[]): string | null {
  if (tiers.length === 0) return null;
  const sorted = [...tiers].sort((a, b) => a.points - b.points);
  let best: RewardTier | null = null;
  for (const tier of sorted) {
    if (points >= tier.points) best = tier;
  }
  return best?.name ?? null;
}

function availableRewards(points: number, tiers: RewardTier[]): string[] {
  return [...tiers]
    .sort((a, b) => a.points - b.points)
    .filter((tier) => points >= tier.points && tier.name.trim().length > 0)
    .map((tier) => tier.name)
    .slice(0, 6);
}

export async function GET(req: NextRequest) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  const phone = req.nextUrl.searchParams.get("phone")?.trim() ?? "";
  if (!phone) return Response.json({ error: "Missing phone" }, { status: 400 });

  const search = await squareFetch("/v2/loyalty/accounts/search", {
    method: "POST",
    body: JSON.stringify({
      query: { mappings: [{ phone_number: phone }] },
      limit: 1,
    }),
  });

  if (!search.ok) {
    return Response.json(
      { error: "Square search failed", details: search.error },
      { status: 502 }
    );
  }

  const accounts = Array.isArray(search.data?.loyalty_accounts)
    ? search.data.loyalty_accounts
    : [];
  if (accounts.length === 0) {
    return Response.json(
      {
        enrolled: false,
        points: 0,
        tierName: null,
        availableRewards: [],
        rewardTiers: [],
        phoneNumber: phone,
        membershipStartDate: null,
        customerID: null,
      },
      { status: 200 }
    );
  }

  const firstAccount = asRecord(accounts[0]);
  const accountId = asTrimmedString(firstAccount.id);
  if (!accountId) {
    return Response.json(
      {
        enrolled: false,
        points: 0,
        tierName: null,
        availableRewards: [],
        rewardTiers: [],
        phoneNumber: phone,
        membershipStartDate: null,
        customerID: null,
      },
      { status: 200 }
    );
  }

  const acct = await squareFetch(`/v2/loyalty/accounts/${accountId}`, { method: "GET" });
  let account = firstAccount;
  if (acct.ok) {
    const loyaltyAccount = asRecord(acct.data?.loyalty_account);
    if (Object.keys(loyaltyAccount).length > 0) {
      account = loyaltyAccount;
    }
  }

  const program = await squareFetch("/v2/loyalty/programs/main", { method: "GET" });

  const points = Math.max(0, Math.floor(toNumber(account.balance)));
  const mapping = asRecord(account.mapping);
  const phoneNumber = asTrimmedString(mapping.phone_number) ?? phone;
  const membershipStartDate =
    asTrimmedString(account.enrolled_at) ?? asTrimmedString(account.created_at) ?? null;
  const customerID = asTrimmedString(account.customer_id);
  const rewardTiers = program.ok ? normalizeRewardTiers(program.data?.program?.reward_tiers) : [];
  const tierName = deriveTierName(points, rewardTiers);

  return Response.json({
    enrolled: true,
    accountId,
    points,
    tierName,
    availableRewards: availableRewards(points, rewardTiers),
    rewardTiers,
    phoneNumber,
    membershipStartDate,
    customerID,
  });
}
