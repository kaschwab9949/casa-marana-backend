export const runtime = "nodejs";

import { handleAccountDelete } from "@/app/api/account/delete/route";

export async function POST(req: Request) {
  return handleAccountDelete(req, "/api/auth/delete-account", true);
}
