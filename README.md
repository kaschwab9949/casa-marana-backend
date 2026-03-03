# Casa Marana Backend

Next.js backend for loyalty, menu, phone verification, snake leaderboard, and app compatibility routes.

## Local Development

1. Install dependencies:

```bash
npm install
```

2. Create `.env.local` with required values:

```bash
CASA_APP_API_KEY=...
SQUARE_ACCESS_TOKEN=...
SQUARE_VERSION=2025-10-16
SUPABASE_DATABASE_URL=...
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_VERIFY_SERVICE_SID=...
```

3. Start locally:

```bash
npm run dev
```

## API Contracts

- Canonical Smart Check-In: `POST /api/location/sample`
- Compatibility alias: `POST /api/loyalty/location`
- Canonical account delete: `POST /api/account/delete`
- Compatibility aliases: `POST /api/auth/account/delete`, `POST /api/auth/delete-account`
- Canonical menu feed: `GET /api/menu`
- Compatibility aliases: `GET /api/menu/items`, `GET /api/catalog/menu`
- Health diagnostics: `GET /api/health`

Machine-readable contract:

- [docs/openapi.yaml](docs/openapi.yaml)

## Scripts

- `npm run dev` - local development
- `npm run build` - production build
- `npm run lint` - ESLint
- `./scripts/security_hygiene_check.sh` - blocks common secret/cert mistakes in tracked files

## Deployment

- Production is deployed on Vercel.
- For monorepo mode, set Vercel Root Directory to `/backend` after migration.
