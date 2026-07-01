# EmailDeliveryHero — code

A localhost web app that audits email deliverability (SPF, DKIM, DMARC, MX, DNS blacklists) and
tells you exactly how to fix any problems it finds. Node + TypeScript monorepo.

Product specs live in [`../pm/`](../pm/) — start with `pm/overview.mdx`.

## Layout

```
code/
├── packages/backend    # NestJS REST API (:9312, routes under /api)
└── packages/frontend   # React 19 + Vite SPA — UI WebApp (:4444)
```

## Authentication — OpenAuthFederated (external library)

We do **not** implement OAuth/SAML/session signing ourselves. We **consume** the OpenAuthFederated
open-source library, brought in as separate linked packages (see each package's `package.json`):

- Backend → `@auth/backend` (`link:../../../../OpenAuthFederated/code/packages/auth-backend`)
- Frontend → `@auth/react` (`link:../../../../OpenAuthFederated/code/packages/auth-react`)

The backend mounts the library's embedded Google-Workspace Frontend API at `/api/v1`, verifies inbound
Bearer tokens with `federatedClient.verifyToken`, and a global `JwtAuthGuard` enforces auth on every
route except those marked `@Public()`. This mirrors how our other internal app uses OpenAuthFederated.

To sign in you need a Google OAuth client. Set `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` in
`packages/backend/.env`, or add a `google` block under `email_delivery_hero` in
`~/.credentials/email_delivery_hero.json`. `GET /api/health/auth-config` reports whether it's configured.

## Run it

```sh
# From code/
pnpm install

# Terminal 1 — backend (:9312)
cp packages/backend/.env.example packages/backend/.env   # then fill in Google OAuth creds
pnpm --filter @edh/backend dev

# Terminal 2 — frontend / UI WebApp (:4444)  → open http://localhost:4444
pnpm --filter @edh/frontend dev
```

Or run both together: `pnpm dev`.

## Build & test

```sh
pnpm build            # builds both packages
pnpm --filter @edh/backend test   # audit-engine unit tests
```

## State

Runtime data (monitored-domain list, audit history, the auth session store and signing secret) lives
out-of-repo under `~/.email_delivery_hero/` (override with `EDH_STATE_DIR`). No database.

## Periodic audits

Set `EDH_PERIODIC_AUDIT_MINUTES` (backend env) to a positive number to re-audit every domain on that
interval; new problems surface automatically. Off by default.
