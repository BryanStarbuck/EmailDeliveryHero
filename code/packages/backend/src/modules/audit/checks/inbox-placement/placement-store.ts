import { join } from "node:path"
import { type AppConfigFile, readAppConfig } from "@shared/config-store"
import { readJson, writeJson } from "@shared/json-store"
import { stateSubdir } from "@shared/state-dir"
import type { InboxPlacementTest } from "./placement"

/**
 * The per-domain seed-test store (pm/checks/inbox_placement.mdx §5). This module is the ONLY code
 * that knows recorded seed tests live under `~/.email_delivery_hero/placement/<domainId>/tests.json`
 * — the JSON-file incarnation of the future `inbox_placement_tests` + `inbox_placement_results`
 * tables (one array element per test envelope, each carrying its per-seed result children). A later
 * move to Postgres touches this module alone (spec §5 "promoting … is a single-module change").
 *
 * It also owns the SEND GATE (spec §6 / acceptance criteria #2 and #10): whether a "Send seed test
 * now" is allowed right now — the seed-list integration must be configured, sends are debounced so
 * a burst of manual clicks never fires many probes, and a configurable monthly budget bounds how
 * many credits/emails a month can spend. The gate is pure policy; the actual probe send is the
 * FUTURE seed-service/SMTP integration.
 */

/** Newest tests kept per domain — enough history for the §4 trend sparkline. */
const TESTS_KEPT = 60

/**
 * Minimum minutes between two probe sends for one domain (spec §6 "debounced/rate-limited … it
 * must never be triggered in a tight loop"): at least the full settle window, with headroom.
 */
export const SEND_DEBOUNCE_MINUTES = 60

function testsPath(domainId: string): string {
  return join(stateSubdir("placement", domainId), "tests.json")
}

/** All recorded seed tests for a domain, newest `sentAt` first. */
export function listPlacementTests(domainId: string): InboxPlacementTest[] {
  return readJson<InboxPlacementTest[]>(testsPath(domainId), []).sort((a, b) =>
    b.sentAt.localeCompare(a.sentAt),
  )
}

/**
 * Persist one completed seed test (the `inbox_placement_tests` row + its
 * `inbox_placement_results` children — spec §5, acceptance criteria #2/#3/#11). Newest first,
 * capped at TESTS_KEPT; re-recording the same `testToken` replaces the earlier copy (re-reading a
 * mailbox is idempotent on the test token — spec §3).
 */
export function recordPlacementTest(
  domainId: string,
  test: InboxPlacementTest,
): InboxPlacementTest {
  const rows = readJson<InboxPlacementTest[]>(testsPath(domainId), []).filter(
    (t) => t.testToken !== test.testToken,
  )
  rows.push(test)
  rows.sort((a, b) => b.sentAt.localeCompare(a.sentAt))
  writeJson(testsPath(domainId), rows.slice(0, TESTS_KEPT))
  return test
}

/** The app-level seed-list block (config.yaml → seedList — spec §5). */
export type SeedListConfig = AppConfigFile["seedList"]

/**
 * Whether the seed-list integration is configured at all (spec §6 feature gate): either a named
 * seed service (whose credentials live in the out-of-repo credentials file), or the self-hosted
 * path with at least one active seed mailbox. "" = dark — the whole family reports not configured.
 */
export function seedListConfigured(cfg: SeedListConfig): boolean {
  const service = cfg.service.trim().toLowerCase()
  if (service === "") return false
  if (service === "self_hosted") return cfg.seeds.some((s) => s.active)
  return true
}

/** How many recorded tests fall in the same UTC calendar month as `now` (the budget window). */
export function testsSentInMonth(tests: InboxPlacementTest[], now: Date): number {
  const prefix = now.toISOString().slice(0, 7) // "YYYY-MM"
  return tests.filter((t) => t.sentAt.slice(0, 7) === prefix).length
}

/** The send-gate verdict for "Send seed test now" (spec §6, acceptance criteria #2/#10). */
export interface SeedTestGate {
  allowed: boolean
  reason: "ok" | "not_configured" | "debounced" | "budget_exhausted"
  detail: string
}

/**
 * May a probe be sent for this domain right now? Enforces, in order: the feature gate (a
 * configured seed source), the send debounce (a burst of manual audits/clicks never fires many
 * probe sends), and the monthly budget cap. Pure policy — no probe is sent here.
 */
export function canSendSeedTest(domainId: string, now: Date = new Date()): SeedTestGate {
  const cfg = readAppConfig().seedList
  if (!seedListConfigured(cfg)) {
    return {
      allowed: false,
      reason: "not_configured",
      detail:
        "Configure a seed list to enable inbox placement testing: set config.yaml → seedList.service " +
        "to a seed-service name (glockapps / mailtrap / everest / mailreach) or to self_hosted with " +
        "active seed mailboxes.",
    }
  }
  const tests = listPlacementTests(domainId)
  const latest = tests[0]
  if (latest) {
    const ageMinutes = (now.getTime() - new Date(latest.sentAt).getTime()) / 60_000
    if (ageMinutes >= 0 && ageMinutes < SEND_DEBOUNCE_MINUTES) {
      return {
        allowed: false,
        reason: "debounced",
        detail: `A seed test was sent ${Math.round(ageMinutes)} min ago (token ${latest.testToken}). Sends are debounced to one per ${SEND_DEBOUNCE_MINUTES} minutes per domain so a burst of manual audits never fires many probe sends.`,
      }
    }
  }
  const used = testsSentInMonth(tests, now)
  if (used >= cfg.monthlyBudget) {
    return {
      allowed: false,
      reason: "budget_exhausted",
      detail: `The monthly seed-test budget is exhausted (${used}/${cfg.monthlyBudget} this month). Each test spends a seed-service credit and sends real email; raise config.yaml → seedList.monthlyBudget to allow more.`,
    }
  }
  return {
    allowed: true,
    reason: "ok",
    detail: `Sending is allowed: ${used}/${cfg.monthlyBudget} tests used this month.`,
  }
}
