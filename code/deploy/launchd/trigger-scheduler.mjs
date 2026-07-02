#!/usr/bin/env node
// EmailDeliveryHero — background scheduler trigger.
//
// This is the code the macOS launchd plist ("plist-based cron job") runs on a schedule while the
// UI is closed. It is deliberately the SAME runtime as the rest of the app — Node running our own
// (TypeScript-compatible) JavaScript — rather than a raw `curl`, so the background job stays inside
// our stack. It simply asks the always-on local backend to run every due deliverability audit.
//
// Contract: POST http://localhost:<API_PORT>/api/scheduler/run  (see pm/scheduled_checks.mdx).
// Exit 0 on success, non-zero on failure, so launchctl surfaces problems in the .err log.

const API_PORT = Number(process.env.API_PORT ?? process.env.PORT ?? 9312)
const URL = `http://localhost:${API_PORT}/api/scheduler/run`
const TIMEOUT_MS = 60_000

const stamp = () => new Date().toISOString()

async function main() {
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS)
  try {
    const res = await fetch(URL, {
      method: "POST",
      signal: ac.signal,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ trigger: "os" }),
    })
    const body = await res.text().catch(() => "")
    if (!res.ok) {
      console.error(`[${stamp()}] scheduler run failed: HTTP ${res.status} ${res.statusText} ${body}`)
      process.exit(1)
    }
    console.log(`[${stamp()}] scheduler run OK: ${body || res.status}`)
  } catch (err) {
    const reason = err?.name === "AbortError" ? `timed out after ${TIMEOUT_MS}ms` : String(err)
    // ECONNREFUSED here means the localhost web app is not running — start it with `just run`.
    console.error(`[${stamp()}] scheduler run error contacting ${URL}: ${reason}`)
    process.exit(1)
  } finally {
    clearTimeout(timer)
  }
}

main()
