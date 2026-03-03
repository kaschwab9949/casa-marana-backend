export const runtime = "nodejs";

const CONTRACT_VERSION = "2026-03-02";

const REQUIRED_ENV_VARS = [
  "CASA_APP_API_KEY",
  "SQUARE_ACCESS_TOKEN",
  "SQUARE_VERSION",
  "SUPABASE_DATABASE_URL",
] as const;

function isConfigured(name: string): boolean {
  return String(process.env[name] ?? "").trim().length > 0;
}

export async function GET() {
  const missingEnv = REQUIRED_ENV_VARS.filter((name) => !isConfigured(name));

  return Response.json(
    {
      ok: missingEnv.length === 0,
      status: missingEnv.length === 0 ? "healthy" : "degraded",
      contractVersion: CONTRACT_VERSION,
      build: {
        commit:
          process.env.VERCEL_GIT_COMMIT_SHA ??
          process.env.NEXT_PUBLIC_GIT_SHA ??
          "unknown",
        deployedAt:
          process.env.VERCEL_DEPLOYMENT_CREATED_AT ??
          process.env.BUILD_TIMESTAMP ??
          null,
      },
      missingEnv,
      routes: {
        locationSample: "/api/location/sample",
        locationAlias: "/api/loyalty/location",
        accountDelete: "/api/account/delete",
        accountDeleteAliases: ["/api/auth/account/delete", "/api/auth/delete-account"],
        menu: "/api/menu",
      },
    },
    { status: missingEnv.length === 0 ? 200 : 503 }
  );
}
