# EmailDeliveryHero — task runner.
#
#   just build   → compile the TypeScript (frontend + backend) and install the macOS launchd
#                  "plist-based cron job" so scheduled audits run on localhost.
#   just run     → verify nothing is blocking, then run BOTH the frontend and backend together as
#                  one localhost web app (http://localhost:4444, API proxied to :9312).
#
# The app is a TypeScript-on-Node monorepo under ./code (NestJS backend + Vite/React frontend).
# Requires Homebrew-installed `node`, `pnpm`, and `just`.

set shell := ["bash", "-uc"]

repo    := justfile_directory()
code    := repo / "code"
agents  := home_directory() / "Library/LaunchAgents"
label   := "com.emaildeliveryhero.scheduler"
plist   := agents / label + ".plist"
tmpl    := code / "deploy/launchd/com.emaildeliveryhero.scheduler.plist.tmpl"
trigger := code / "deploy/launchd/trigger-scheduler.mjs"

# App ports (keep in sync with pm/overview.mdx, code/packages/frontend/vite.config.ts and backend .env).
# web_port is the UI WebApp — always localhost:4444 (per pm/overview.mdx "Key facts").
web_port := "4444"
api_port := "9312"

# Default: show the recipe list.
default:
    @just --list

# ── Prerequisites ──────────────────────────────────────────────────────────────
# Fail fast (with a fix hint) if a required Homebrew tool is missing.
_preflight-tools:
    #!/usr/bin/env bash
    set -euo pipefail
    ok=1
    for tool in node pnpm; do
      if ! command -v "$tool" >/dev/null 2>&1; then
        echo "✗ missing '$tool' — install with: brew install $tool" >&2
        ok=0
      fi
    done
    [ "$ok" = 1 ] || { echo "Fix the above and re-run." >&2; exit 1; }
    echo "✓ node $(node -v)   pnpm $(pnpm -v)"

# ── build ──────────────────────────────────────────────────────────────────────
# Install deps, compile both packages, and install the launchd cron job on localhost.
build: _preflight-tools
    #!/usr/bin/env bash
    set -euo pipefail
    echo "▶ Installing dependencies…"
    pnpm -C "{{code}}" install
    echo "▶ Compiling TypeScript (frontend + backend)…"
    pnpm -C "{{code}}" build
    just install-agent
    echo "✓ build complete — run 'just run' to start the web app."

# Render the plist template with real paths and (re)load it via launchctl.
install-agent:
    #!/usr/bin/env bash
    set -euo pipefail
    node_bin="$(command -v node)"
    mkdir -p "{{agents}}"
    sed \
      -e "s#__NODE_BIN__#${node_bin}#g" \
      -e "s#__TRIGGER_SCRIPT__#{{trigger}}#g" \
      -e "s#__API_PORT__#{{api_port}}#g" \
      -e "s#__LOG_OUT__#/tmp/edh.scheduler.out.log#g" \
      -e "s#__LOG_ERR__#/tmp/edh.scheduler.err.log#g" \
      "{{tmpl}}" > "{{plist}}"
    # Reload cleanly whether or not it was previously loaded.
    launchctl unload "{{plist}}" >/dev/null 2>&1 || true
    launchctl load -w "{{plist}}"
    echo "✓ installed launchd agent: {{plist}}"
    echo "  fires the audit at 06:00 & 18:00 daily (edit times in the plist, then 'just install-agent')."

# Remove the launchd cron job.
uninstall-agent:
    #!/usr/bin/env bash
    set -euo pipefail
    launchctl unload "{{plist}}" >/dev/null 2>&1 || true
    rm -f "{{plist}}"
    echo "✓ removed launchd agent: {{label}}"

# ── run ────────────────────────────────────────────────────────────────────────
# Preflight (tools, env, free ports, state dir) then start frontend + backend as one web app.
run: _preflight-tools
    #!/usr/bin/env bash
    set -euo pipefail

    # 1) Backend env must exist (holds ports + Google OAuth creds for OpenAuthFederated).
    env_file="{{code}}/packages/backend/.env"
    if [ ! -f "$env_file" ]; then
      example="{{code}}/packages/backend/.env.example"
      cp "$example" "$env_file"
      echo "• created $env_file from .env.example — add GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET to sign in."
    fi

    # 2) State dir for domains/audit history/session store (out of repo; no DB).
    state_dir="${EDH_STATE_DIR:-$HOME/.email_delivery_hero}"
    mkdir -p "$state_dir"
    echo "• state dir: $state_dir"

    # 3) Ports must be free, or the app fails loudly (Vite uses strictPort).
    blocked=0
    for port in {{web_port}} {{api_port}}; do
      if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "✗ port $port is already in use:" >&2
        lsof -nP -iTCP:"$port" -sTCP:LISTEN | tail -n +1 >&2
        blocked=1
      fi
    done
    [ "$blocked" = 0 ] || { echo "Free the port(s) above (or 'just stop') and re-run." >&2; exit 1; }

    # 4) Dependencies present? (build may not have run yet.)
    if [ ! -d "{{code}}/node_modules" ]; then
      echo "• node_modules missing — installing…"
      pnpm -C "{{code}}" install
    fi

    echo "▶ Starting EmailDeliveryHero — web http://localhost:{{web_port}}  (API → :{{api_port}})"
    echo "  Ctrl-C stops both. Background audits keep running via the launchd agent."
    # `pnpm dev` runs @edh/frontend + @edh/backend in parallel = one web app (Vite proxies /api).
    exec pnpm -C "{{code}}" dev

# Stop anything left listening on the app ports (e.g. an orphaned dev server).
stop:
    #!/usr/bin/env bash
    set -euo pipefail
    for port in {{web_port}} {{api_port}}; do
      pids="$(lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
      if [ -n "$pids" ]; then
        echo "• killing PID(s) on :$port → $pids"
        kill $pids 2>/dev/null || true
      fi
    done
    echo "✓ ports {{web_port}} & {{api_port}} clear."

# Show status of the launchd agent and whether the web app ports are live.
status:
    #!/usr/bin/env bash
    set -euo pipefail
    if launchctl list | grep -q "{{label}}"; then
      echo "launchd agent: LOADED ({{label}})"
    else
      echo "launchd agent: not loaded — run 'just build' or 'just install-agent'"
    fi
    for port in {{web_port}} {{api_port}}; do
      if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "port $port: LISTENING"
      else
        echo "port $port: free"
      fi
    done
