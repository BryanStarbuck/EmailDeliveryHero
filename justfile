# EmailDeliveryHero — task runner.
#
#   just build   → compile the TypeScript (frontend + backend) and install the macOS launchd
#                  "plist-based cron job" so scheduled audits run on localhost.
#   just run     → stop any pre-existing instance, then start BOTH the frontend and backend in the
#                  BACKGROUND as one localhost web app (http://localhost:4444, API proxied to :9312).
#                  The backend is compiled and served from dist/ (no file watcher), so in-flight
#                  audit runs survive editors/git syncs touching the tree. Waits for both ports to
#                  bind, then frees the command line. `just logs` follows it.
#   just dev     → same, but the backend runs under `nest start --watch` (restarts on source
#                  changes — an API restart kills any audit run in flight; use while hacking only).
#   just stop    → kill the background webapp and free both ports.
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
# web_port is the UI WebApp — localhost:4444 by default (per pm/overview.mdx "Key facts").
# Overridable so the justfile agrees with the app when WEBAPP_PORT / API_PORT are set.
web_port := env_var_or_default("WEBAPP_PORT", "4444")
api_port := env_var_or_default("API_PORT", "9312")

# Background `run`: combined dev log + launcher pid. Kept in /tmp under the same
# `edh.` prefix as the scheduler's logs (see install-agent) so nothing lands in the repo.
webapp_log := "/tmp/edh.webapp.log"
pid_file   := "/tmp/edh.webapp.pid"

# How long `run` waits for each port to bind before giving up.
startup_timeout := "60"

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

# The auth library (@auth/backend, @auth/react) is consumed via pnpm `link:` deps that expect
# OpenAuthFederated as a SIBLING of this repo. On a machine where it lives elsewhere, find it
# (OPENAUTH_FEDERATED_DIR override, then a shallow search of common roots) and symlink it into
# place; if it isn't cloned at all, fail with the clone command. Also builds its dist/ if stale.
_preflight-openauth:
    #!/usr/bin/env bash
    set -euo pipefail
    sibling="$(dirname "{{repo}}")/OpenAuthFederated"
    marker="code/packages/auth-backend"
    found=""
    if [ -d "$sibling/$marker" ]; then
      found="$sibling"
    elif [ -n "${OPENAUTH_FEDERATED_DIR:-}" ] && [ -d "$OPENAUTH_FEDERATED_DIR/$marker" ]; then
      found="$OPENAUTH_FEDERATED_DIR"
    else
      for root in "$HOME/BGit" "$HOME/git" "$HOME/src" "$HOME/code" "$HOME/Projects" "$HOME"; do
        [ -d "$root" ] || continue
        hit="$(find "$root" -maxdepth 3 -type d -name OpenAuthFederated -not -path '*/node_modules/*' 2>/dev/null | head -n 1 || true)"
        if [ -n "$hit" ] && [ -d "$hit/$marker" ]; then found="$hit"; break; fi
      done
    fi
    if [ -z "$found" ]; then
      echo "✗ OpenAuthFederated not found on this machine." >&2
      echo "  Clone it next to this repo:" >&2
      echo "    git clone https://github.com/BryanStarbuck/OpenAuthFederated.git \"$sibling\"" >&2
      echo "  …or point OPENAUTH_FEDERATED_DIR at an existing checkout and re-run." >&2
      exit 1
    fi
    # Materialize the sibling layout the package.json `link:` deps expect.
    if [ ! -d "$sibling/$marker" ]; then
      rm -f "$sibling" 2>/dev/null || true   # clear a stale/broken symlink, never a real dir
      ln -s "$found" "$sibling"
      echo "✓ linked $sibling → $found"
    fi
    # The link: deps consume dist/ — build the library if it hasn't been built yet.
    if [ ! -f "$found/$marker/dist/index.js" ] || [ ! -f "$found/code/packages/auth-react/dist/index.js" ]; then
      echo "▶ Building OpenAuthFederated (dist/ missing)…"
      pnpm -C "$found/code" install
      pnpm -C "$found/code" -r build
    fi
    echo "✓ OpenAuthFederated ready: $found"

# ── build ──────────────────────────────────────────────────────────────────────
# Install deps, compile both packages, and install the launchd cron job on localhost.
build: _preflight-tools _preflight-openauth
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
# Preflight (tools, env, state dir), STOP any pre-existing instance, then start
# frontend + backend together in the BACKGROUND as one web app. Depending on `stop`
# guarantees a fresh restart (no port collision — Vite uses strictPort and would die
# on a stale :4444). The servers keep running after this recipe returns; the
# command line is freed. Follow output with `just logs`; shut down with `just stop`.
#
# The backend is compiled once and served from dist/ (`pnpm start` → node dist/main.js),
# NOT `nest start --watch`: a watch-mode API restarts on any source-file mtime change
# (editors, git pull/sync loops touching the tree) and every audit run in flight dies
# with it — the UI then pops "Audit failed" for each domain. Use `just dev` when you
# actually want restart-on-change.
#
# Start the web app in the BACKGROUND (fresh restart; web :4444 + API :9312).
run mode="app": _preflight-tools _preflight-openauth stop
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

    # 3) Dependencies present? (build may not have run yet.)
    if [ ! -d "{{code}}/node_modules" ]; then
      echo "• node_modules missing — installing…"
      pnpm -C "{{code}}" install
    fi

    # 4) Launch both packages in the background = one web app (Vite proxies /api → :{{api_port}}).
    #    app mode: compile the backend, then `pnpm start` (Vite UI + node dist/main.js — no watcher).
    #    dev mode: `pnpm dev` (Vite UI + `nest start --watch`).
    if [ "{{mode}}" = "dev" ]; then
      launch="dev"
    else
      echo "▶ Compiling backend…"
      pnpm -C "{{code}}" --filter @edh/backend build
      launch="start"
    fi
    echo "▶ Starting EmailDeliveryHero in the background — web :{{web_port}} + API :{{api_port}}…"
    nohup pnpm -C "{{code}}" "$launch" >"{{webapp_log}}" 2>&1 &
    pid=$!
    echo "$pid" >"{{pid_file}}"

    # Wait for a TCP port to bind. Bails out early (tailing the log) if the launcher
    # process dies, or after the timeout if the port never comes up.
    # Usage: wait_for_port <label> <port>
    wait_for_port() {
        local label="$1" port="$2"
        printf "  waiting for %s (:%s) " "$label" "$port"
        for _ in $(seq 1 {{startup_timeout}}); do
            if ! kill -0 "$pid" 2>/dev/null; then
                printf "\n\n✗ webapp exited during startup. Last log lines:\n\n" >&2
                tail -n 40 "{{webapp_log}}" >&2
                rm -f "{{pid_file}}"
                exit 1
            fi
            if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
                printf " up!\n"
                return 0
            fi
            printf "."
            sleep 1
        done
        printf "\n\n✗ %s did not come up on :%s within {{startup_timeout}}s. Last log lines:\n\n" "$label" "$port" >&2
        tail -n 40 "{{webapp_log}}" >&2
        exit 1
    }

    # Both must be up. Frontend (Vite) usually binds first; the backend (Nest) takes
    # longer to compile + map routes, so it is treated as required and waited on second.
    wait_for_port "frontend" "{{web_port}}"
    wait_for_port "backend"  "{{api_port}}"

    printf "\n"
    printf "  Web  → http://localhost:%s\n" "{{web_port}}"
    printf "  API  → http://localhost:%s   (proxied at /api)\n" "{{api_port}}"
    printf "  Logs → %s   (follow: just logs)\n" "{{webapp_log}}"
    printf "  PID  → %s   (stop: just stop)\n" "$pid"
    printf "  Background audits also keep running via the launchd agent.\n"
    exit 0

# A watch-mode API restart (on every backend source change) kills any audit run in
# flight — that is why `run` serves the compiled backend and this is a separate recipe.
#
# Start in DEV mode: backend under `nest start --watch` (restarts on source changes).
dev: (run "dev")

# Follow the background webapp log.
logs:
    @test -f "{{webapp_log}}" && tail -f "{{webapp_log}}" || echo "No log yet — start it with: just run"

# Kill the recorded launcher and free both ports (also catches an orphaned dev server).
#
# Stop the background webapp.
stop:
    #!/usr/bin/env bash
    set -uo pipefail
    # Recorded launcher pid first (kills the pnpm dev parent so children don't respawn).
    if [ -f "{{pid_file}}" ]; then
      pid="$(cat "{{pid_file}}" 2>/dev/null || true)"
      if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
        echo "• stopping launcher pid $pid"
        kill "$pid" 2>/dev/null || true
      fi
      rm -f "{{pid_file}}"
    fi
    # Then sweep anything still bound to the app ports.
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
    for pair in "web {{web_port}}" "api {{api_port}}"; do
      set -- $pair
      pids="$(lsof -nP -tiTCP:"$2" -sTCP:LISTEN 2>/dev/null | tr '\n' ' ' || true)"
      if [ -n "$pids" ]; then
        echo "port $2 ($1): LISTENING [pid $pids]"
      else
        echo "port $2 ($1): free"
      fi
    done
    if [ -f "{{pid_file}}" ]; then
      echo "recorded launcher pid: $(cat "{{pid_file}}" 2>/dev/null || echo '?')  ({{pid_file}})"
    fi
