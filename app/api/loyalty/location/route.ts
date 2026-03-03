import { handleLocationSample } from "@/app/api/location/sample/route";

export async function POST(req: Request) {
  return handleLocationSample(req, "/api/loyalty/location");
}
