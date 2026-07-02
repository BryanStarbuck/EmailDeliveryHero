# syntax=docker/dockerfile:1
#
# EmailDeliveryHero — one image, both services (pm/engineering.mdx §9 "Deploy").
# docker-compose.yml runs this image twice: once as the NestJS backend (9312) and once as the
# React/Vite frontend (4444). The on-disk state dir is mounted as a volume by compose.
#
# IMPORTANT — build context: the backend/frontend depend on OpenAuthFederated via pnpm `link:`
# paths that resolve to a SIBLING checkout of the EmailDeliveryHero repo
# (link:../../../../OpenAuthFederated/code/packages/auth-*). The build context therefore has to be
# the PARENT directory that holds both checkouts (e.g. ~/BGit/Bryan_git). docker-compose.yml sets
# `context: ../..` and `dockerfile: EmailDeliveryHero/code/Dockerfile` accordingly. To build by
# hand:
#
#   cd ~/BGit/Bryan_git
#   docker build -f EmailDeliveryHero/code/Dockerfile -t email-delivery-hero .

FROM node:20-alpine AS build

# pnpm via corepack (the workspace pins packageManager in package.json).
RUN corepack enable

WORKDIR /workspace

# The externally-linked auth library first (it changes less often, so it caches well).
COPY OpenAuthFederated/ OpenAuthFederated/

# The app monorepo.
COPY EmailDeliveryHero/code/ EmailDeliveryHero/code/

# Build the linked OpenAuthFederated packages when they carry their own build step.
WORKDIR /workspace/OpenAuthFederated/code
RUN if [ -f package.json ]; then pnpm install && (pnpm -r build || true); fi

# Install + compile both EmailDeliveryHero packages (backend nest build, frontend vite build).
WORKDIR /workspace/EmailDeliveryHero/code
RUN pnpm install
RUN pnpm -r build

# ------------------------------------------------------------------------------------------------
# Runtime: the same tree (pnpm workspaces need node_modules layout intact for the linked lib).
# compose picks the service via `command:`; default is the backend.
# ------------------------------------------------------------------------------------------------
FROM node:20-alpine AS runtime
RUN corepack enable
WORKDIR /workspace/EmailDeliveryHero/code
COPY --from=build /workspace /workspace

# All persisted state (domains.yaml, config.yaml, audit runs, logs) lives in the state dir —
# compose mounts a volume here (pm/engineering.mdx §7).
ENV EDH_STATE_DIR=/state
ENV NODE_ENV=production

EXPOSE 9312 4444

# Default: the NestJS backend on 9312. The frontend service overrides `command` in compose.
CMD ["node", "packages/backend/dist/main.js"]
