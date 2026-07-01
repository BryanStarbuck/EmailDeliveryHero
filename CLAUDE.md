# EmailDeliveryHero

## Charter of This Directory

**EmailDeliveryHero** is an **open source project**.

* **Git Remote (origin):** https://github.com/BryanStarbuck/EmailDeliveryHero.git

### Purpose

EmailDeliveryHero is a web app (runs on localhost) for **auditing email deliverability** — determining whether your email domains are being caught by spam filters or landing on blacklists, and how to fix them.

### What It Does

* Checks whether your email domains are getting caught by spam filters or not.
* Checks whether your domains are on blacklists or not.
* Tells you how to fix any problems it finds.
* Runs periodic checks and looks for problems.
* Reports the problems it finds and the specific fixes to apply.

### Architecture & Conventions

* **Web app that runs on localhost.**
* **Language & runtime — always TypeScript on Node.** Everything we write is **TypeScript run on Node** (>= 20). The `code/` monorepo (pnpm workspace) is:
  * `code/packages/backend` — NestJS REST API (TypeScript, port 9312).
  * `code/packages/frontend` — React 19 + Vite SPA / UI WebApp (TypeScript, port 4444).
  * **Background / scheduled jobs use the same stack.** The macOS **plist-based cron jobs** (launchd) that run us in the background should run our own TypeScript-on-Node code — not raw shell or `curl`. The scheduler trigger lives at `code/deploy/launchd/trigger-scheduler.mjs` (Node, TypeScript-compatible) and is what the launchd agent invokes. Keep new background workers in this same language/runtime.
* **Task runner — `just`.** The repo-root `justfile` is the entry point:
  * `just build` — install deps, compile the TypeScript (frontend + backend), and install the launchd plist cron job on localhost.
  * `just run` — preflight (tools, `.env`, free ports, state dir), then run frontend + backend together as one localhost web app.
  * Helpers: `just install-agent` / `just uninstall-agent` (launchd), `just status`, `just stop`.
* **Tooling:** Internally we will often use **Brew-installed tools** (Homebrew) to do our work.
* **Authentication:** We use **OpenAuth Federated** for authentication.
  * Local repo: `~/BGit/Bryan_git/OpenAuthFederated/`
  * REPO: https://github.com/BryanStarbuck/OpenAuthFederated.git
  * OpenAuth Federated is our open source version of Clerk / Auth0, used much like Clerk.

### Directory Structure & Rules

* **`pm/`** — The PM spec directory. This is where the product/PM specifications (the PAR specs) live.
  * **NEVER put code under `pm/`.** It is for specifications only.
* **`code/`** — The source code directory. **Always put source code here.**
  * All code work belongs in `code/`, never in `pm/`.
