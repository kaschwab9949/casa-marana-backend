import { NextRequest } from "next/server";
import { requireApiKey } from "@/lib/auth";
import { fetchNormalizedSquareMenu } from "@/lib/menu";

export async function GET(req: NextRequest) {
  const gate = requireApiKey(req);
  if (gate) return gate;

  const menu = await fetchNormalizedSquareMenu();
  if (!menu.ok) {
    return Response.json(
      { error: "Square menu fetch failed", details: menu.error },
      { status: 502 }
    );
  }

  return Response.json(menu.data, { status: 200 });
}
