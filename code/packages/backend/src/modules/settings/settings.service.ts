import { execFile } from "node:child_process"
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import { SchedulerService } from "@module/scheduler/scheduler.service"
import { BadRequestException, Injectable, ServiceUnavailableException } from "@nestjs/common"
import {
  readAppConfig,
  readUserConfig,
  updateAppConfig,
  updateUserConfig,
} from "@shared/config-store"
import type { AuthUser } from "@shared/current-user.decorator"
import { logError, logInfo } from "@shared/logging"
import { resolveStateDir } from "@shared/state-dir"
import { locateTool } from "@shared/tool-runner"
import { parse } from "yaml"
import type { UpdateAdminSettingsDto, UpdateUserSettingsDto } from "./dto/settings.dto"
import type {
  ResetResult,
  SettingsView,
  TestNotificationResult,
  ToolsDetection,
} from "./settings.types"
import { detectTools } from "./tools-detect"

const execFileAsync = promisify(execFile)

/** The state-dir entries GET /api/settings/export archives (pm/settings.mdx §5 — Export). */
const EXPORT_ENTRIES = [
  "config.yaml",
  "domains.yaml",
  "audits.json",
  "runs", // the per-run YAML history tree (pm/storage.mdx §7)
  "runs.json", // legacy pre-§7 single-file history, present until first-boot migration
  "blacklists",
  "blacklist_zones.yaml",
  "users",
]

/** Run-history state removed by "Reset audit history" (keeps domains + config, §5). */
const AUDIT_HISTORY_ENTRIES = ["audits.json", "runs", "runs.json", "blacklists"]

/**
 * "Reset app" clears the whole file store back to defaults (§5). Log files and the auth session
 * store/secret are deliberately kept so the reset request itself completes, stays attributable in
 * the fault trail, and the admin is not signed out mid-action.
 */
const APP_RESET_ENTRIES = [...EXPORT_ENTRIES, "scheduler-state.json"]

/**
 * The Settings service (pm/settings.mdx "REST contract"). All persistence goes through the
 * hierarchical config store of pm/storage.mdx — global/admin-owned blocks in <state dir>/config.yaml
 * (atomic temp+rename via the shared yaml-store), per-user preferences in users/<email>/config.yaml.
 * The §3 schedule block is owned by the scheduler module; admin writes that include `schedule`
 * delegate there so the in-process timer is re-armed on save.
 */
@Injectable()
export class SettingsService {
  private lastDetection: ToolsDetection | null = null

  constructor(private readonly scheduler: SchedulerService) {}

  /* ------------------------------------ reads ------------------------------------ */

  /** GET /api/settings — everything the current user may see, in one read. */
  async view(user: AuthUser): Promise<SettingsView> {
    const app = readAppConfig()
    const mine = readUserConfig(user.email)
    if (!this.lastDetection) {
      // First read after boot: probe once so §6 status is populated without a manual re-detect.
      this.lastDetection = await detectTools().catch(() => null)
    }
    return {
      stateDir: resolveStateDir(),
      config: {
        checks: app.checks,
        schedule: this.scheduler.getConfig(),
        notifications: app.notifications,
        storage: app.storage,
        tools: app.tools,
        access: app.access,
        dns_health: app.dns_health,
      },
      me: {
        sub: user.userId,
        email: user.email,
        notifications: mine.notifications,
        appearance: { theme: mine.theme, density: mine.density },
      },
      toolStatus: this.lastDetection,
    }
  }

  /* ------------------------------------ writes ------------------------------------ */

  /** PUT /api/settings — the caller's OWN per-user block (§4 prefs + §8 appearance). All-users. */
  async updateUser(user: AuthUser, dto: UpdateUserSettingsDto): Promise<SettingsView> {
    updateUserConfig(user.email, (cfg) => {
      if (dto.appearance?.theme !== undefined) cfg.theme = dto.appearance.theme
      if (dto.appearance?.density !== undefined) cfg.density = dto.appearance.density
      if (dto.notifications) cfg.notifications = { ...cfg.notifications, ...dto.notifications }
    })
    logInfo(`Per-user settings saved for ${user.email}`, "Settings")
    return this.view(user)
  }

  /**
   * PUT /api/settings/admin — admin-only global fields (§2 checks, §4 shared channels, §5
   * retention, §6 tools, §7 access; a `schedule` patch is delegated to the scheduler so the
   * in-process timer re-arms). The route guard (`@RequireRole("admin")`) is the authority —
   * non-admins never reach this code (pm/settings.mdx acceptance #11).
   */
  async updateAdmin(user: AuthUser, dto: UpdateAdminSettingsDto): Promise<SettingsView> {
    updateAppConfig((cfg) => {
      if (dto.checks) {
        if (dto.checks.enabled) cfg.checks.enabled = [...new Set(dto.checks.enabled)]
        if (dto.checks.spf?.maxLookups !== undefined)
          cfg.checks.spf.maxLookups = dto.checks.spf.maxLookups
        if (dto.checks.dkim?.defaultSelectors)
          cfg.checks.dkim.defaultSelectors = cleanList(dto.checks.dkim.defaultSelectors)
        if (dto.checks.dnsbl?.zones) cfg.checks.dnsbl.zones = cleanList(dto.checks.dnsbl.zones)
        // Content-scoring admin settings (pm/checks/content_scoring.mdx §4): threshold override,
        // inbox-safe target, network content tests on/off.
        if (dto.checks.content)
          cfg.checks.content = { ...cfg.checks.content, ...dto.checks.content }
        // BIMI admin settings (pm/checks/bimi.mdx §4/§5): the recognized-MVA allow-list the future
        // VMC/CMC certificate round matches issuer DNs against. Admin-only; replaces the list.
        if (dto.checks.bimi?.mvaAllowList)
          cfg.checks.bimi.mvaAllowList = dto.checks.bimi.mvaAllowList
            .map((m) => ({
              name: m.name.trim(),
              issuerDnMatch: m.issuerDnMatch.trim(),
              markTypes: [...new Set(m.markTypes)],
              enabled: m.enabled,
            }))
            .filter((m) => m.name.length > 0 && m.issuerDnMatch.length > 0)
        // DANE / TLSA admin settings (pm/checks/dane_tlsa.mdx §4): the FUTURE :25 cert-match
        // probe toggle + timeout and the require-AD-bit validating-resolver switch.
        if (dto.checks.dane) cfg.checks.dane = { ...cfg.checks.dane, ...dto.checks.dane }
        if (dto.checks.thresholds)
          cfg.checks.thresholds = { ...cfg.checks.thresholds, ...dto.checks.thresholds }
        if (dto.checks.weights)
          cfg.checks.weights = { ...cfg.checks.weights, ...dto.checks.weights }
      }
      if (dto.notifications?.webhook)
        cfg.notifications.webhook = { ...cfg.notifications.webhook, ...dto.notifications.webhook }
      if (dto.notifications?.smtp)
        cfg.notifications.smtp = { ...cfg.notifications.smtp, ...dto.notifications.smtp }
      if (dto.storage?.retentionDays !== undefined)
        cfg.storage.retentionDays = dto.storage.retentionDays
      if (dto.tools) {
        if (dto.tools.preferCli !== undefined) cfg.tools.preferCli = dto.tools.preferCli
        if (dto.tools.resolvers) cfg.tools.resolvers = cleanList(dto.tools.resolvers)
        if (dto.tools.timeoutMs !== undefined) cfg.tools.timeoutMs = dto.tools.timeoutMs
        // Per-tool binary-path overrides (config.yaml → tools.paths — the ToolLocator's explicit
        // resolution step 1). This carries the spamassassin/spamc binary-path admin setting of
        // pm/checks/content_scoring.mdx §4; an empty value clears the override.
        if (dto.tools.paths) {
          const paths = { ...cfg.tools.paths }
          for (const [name, value] of Object.entries(dto.tools.paths)) {
            const key = name.trim()
            if (!key || typeof value !== "string") continue
            const path = value.trim()
            if (path) paths[key] = path
            else delete paths[key]
          }
          cfg.tools.paths = paths
        }
      }
      if (dto.access?.allowedDomains)
        cfg.access.allowedDomains = cleanList(dto.access.allowedDomains)
      // Takeover-fingerprint list (pm/checks/dns_health.mdx §4/§5 — the `takeover_fingerprints`
      // reference table, admin-editable). Replaces the whole list; blank rows are dropped and
      // (provider, cname_suffix) pairs deduped, mirroring the SQL UNIQUE constraint.
      if (dto.dns_health?.fingerprints) {
        const seen = new Set<string>()
        cfg.dns_health.fingerprints = dto.dns_health.fingerprints
          .map((f) => ({
            provider: f.provider.trim(),
            cname_suffix: f.cname_suffix.trim().toLowerCase(),
            ...(f.unclaimed_signature?.trim()
              ? { unclaimed_signature: f.unclaimed_signature.trim() }
              : {}),
            enabled: f.enabled,
          }))
          .filter((f) => {
            if (!f.provider || !f.cname_suffix) return false
            const key = `${f.provider}|${f.cname_suffix}`
            if (seen.has(key)) return false
            seen.add(key)
            return true
          })
      }
    })
    if (dto.schedule) {
      // §3 owns scheduling — write through the scheduler so the active runner matches the save.
      await this.scheduler.updateConfig(dto.schedule as Record<string, unknown>)
    }
    logInfo(`Admin settings saved by ${user.email}`, "Settings")
    return this.view(user)
  }

  /* ------------------------------------ actions ------------------------------------ */

  /**
   * POST /api/settings/notifications/test (§4) — fire a sample notification on the channels the
   * caller has selected. Desktop is raised by the browser (the response tells the frontend to);
   * webhook posts a Slack-compatible payload; email goes out via swaks when an SMTP relay is
   * configured. Channel failures come back as data, never as an HTTP error.
   */
  async testNotification(user: AuthUser): Promise<TestNotificationResult> {
    const app = readAppConfig()
    const mine = readUserConfig(user.email)
    const result: TestNotificationResult = {
      desktop: {
        attempted: mine.notifications.desktop,
        detail: mine.notifications.desktop
          ? "The browser raises the desktop notification on receipt of this response."
          : "Desktop notifications are off in your preferences.",
      },
      email: { attempted: false, ok: false, detail: "" },
      webhook: { attempted: false, ok: false, detail: "" },
    }

    const { webhook, smtp } = app.notifications
    if (webhook.enabled && webhook.url) {
      result.webhook.attempted = true
      try {
        const res = await fetch(webhook.url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            text: `EmailDeliveryHero test notification — requested by ${user.email}.`,
          }),
          signal: AbortSignal.timeout(app.tools.timeoutMs),
        })
        result.webhook.ok = res.ok
        result.webhook.detail = res.ok
          ? "Webhook accepted the test post."
          : `Webhook returned ${res.status}.`
      } catch (err) {
        result.webhook.detail = `Webhook post failed: ${(err as Error).message}`
      }
    } else {
      result.webhook.detail = "The shared webhook channel is not enabled."
    }

    if (mine.notifications.email && smtp.host && user.email.includes("@")) {
      result.email.attempted = true
      const swaks = locateTool("swaks")
      if (!swaks) {
        result.email.detail = "swaks is not installed (brew install swaks)."
      } else {
        try {
          await execFileAsync(
            swaks,
            [
              "--to",
              user.email,
              "--from",
              smtp.from,
              "--server",
              `${smtp.host}:${smtp.port}`,
              "--header",
              "Subject: EmailDeliveryHero test notification",
              "--body",
              "This is a test notification from EmailDeliveryHero Settings.",
            ],
            { timeout: 30_000 },
          )
          result.email.ok = true
          result.email.detail = `Test email sent to ${user.email}.`
        } catch (err) {
          result.email.detail = `swaks failed: ${(err as Error).message}`
        }
      }
    } else {
      result.email.detail = mine.notifications.email
        ? "No SMTP relay is configured (admin-only, §4)."
        : "Email notifications are off in your preferences."
    }

    logInfo(`Test notification fired for ${user.email}`, "Settings")
    return result
  }

  /** POST /api/settings/tools/detect (§6) — re-probe the environment for dig/swaks. */
  async redetectTools(): Promise<ToolsDetection> {
    this.lastDetection = await detectTools()
    return this.lastDetection
  }

  /**
   * POST /api/settings/open-state-dir (§5 "Open state dir") — reveal the state dir in the OS file
   * manager (Finder on macOS). Localhost-only convenience; the path itself is always shown in the
   * UI, so a headless host losing this action costs nothing.
   */
  async openStateDir(): Promise<{ opened: boolean; stateDir: string }> {
    const stateDir = resolveStateDir()
    const opener =
      process.platform === "darwin"
        ? "open"
        : process.platform === "win32"
          ? "explorer"
          : "xdg-open"
    try {
      await execFileAsync(opener, [stateDir], { timeout: 10_000 })
      return { opened: true, stateDir }
    } catch (err) {
      logError("Could not open the state dir in the file manager", err, "Settings")
      return { opened: false, stateDir }
    }
  }

  /**
   * GET /api/settings/export (§5) — a zip of config.yaml + domains.yaml + the audit history,
   * built with the OS `zip` tool (Brew/OS tools are the house convention) into a temp file that is
   * removed after the bytes are read.
   */
  async exportArchive(): Promise<{ fileName: string; data: Buffer }> {
    const zip = locateTool("zip")
    if (!zip) throw new ServiceUnavailableException("The `zip` tool is not installed on this host")
    const stateDir = resolveStateDir()
    const entries = EXPORT_ENTRIES.filter((e) => existsSync(join(stateDir, e)))
    if (entries.length === 0) throw new BadRequestException("Nothing to export yet")
    const work = mkdtempSync(join(tmpdir(), "edh-export-"))
    const zipFile = join(work, "export.zip")
    try {
      await execFileAsync(zip, ["-r", "-q", zipFile, ...entries], {
        cwd: stateDir,
        timeout: 60_000,
      })
      const data = readFileSync(zipFile)
      const stamp = new Date().toISOString().slice(0, 10)
      logInfo(
        `Settings export produced (${entries.length} entries, ${data.length} bytes)`,
        "Settings",
      )
      return { fileName: `email-delivery-hero-${stamp}.zip`, data }
    } finally {
      rmSync(work, { recursive: true, force: true })
    }
  }

  /**
   * POST /api/settings/import (§5, admin-only) — restore from a previously exported archive.
   * The zip is unpacked to a staging dir and VALIDATED before anything touches the state dir:
   * it must contain a parseable config.yaml or domains.yaml, and only the known export entries
   * are copied over (a hostile archive cannot drop arbitrary files elsewhere).
   */
  async importArchive(archiveBase64: string): Promise<{ imported: string[] }> {
    const unzip = locateTool("unzip")
    if (!unzip)
      throw new ServiceUnavailableException("The `unzip` tool is not installed on this host")
    const work = mkdtempSync(join(tmpdir(), "edh-import-"))
    try {
      const zipFile = join(work, "import.zip")
      writeFileSync(zipFile, Buffer.from(archiveBase64, "base64"))
      const staging = join(work, "staging")
      try {
        await execFileAsync(unzip, ["-o", "-q", zipFile, "-d", staging], { timeout: 60_000 })
      } catch (err) {
        throw new BadRequestException(`Not a readable zip archive: ${(err as Error).message}`)
      }
      // Validate on read (pm/settings.mdx §5): the YAML stores must parse before we restore.
      for (const yamlName of ["config.yaml", "domains.yaml"]) {
        const path = join(staging, yamlName)
        if (!existsSync(path)) continue
        try {
          parse(readFileSync(path, "utf8"))
        } catch {
          throw new BadRequestException(`The archive's ${yamlName} is not valid YAML`)
        }
      }
      const found = EXPORT_ENTRIES.filter((e) => existsSync(join(staging, e)))
      if (found.length === 0)
        throw new BadRequestException("The archive contains none of the known state files")
      const stateDir = resolveStateDir()
      for (const entry of found) {
        cpSync(join(staging, entry), join(stateDir, entry), { recursive: true, force: true })
      }
      logInfo(`Settings import restored: ${found.join(", ")}`, "Settings")
      // The restored config.yaml may carry a different schedule — re-arm to match it.
      await this.scheduler.updateConfig({})
      return { imported: found }
    } finally {
      rmSync(work, { recursive: true, force: true })
    }
  }

  /**
   * POST /api/settings/reset (§5, admin-only) — `audit_history` deletes the run-history files and
   * keeps domains + config; `app` clears the entire file store back to defaults.
   */
  async reset(scope: "audit_history" | "app", user: AuthUser): Promise<ResetResult> {
    const stateDir = resolveStateDir()
    const targets = scope === "app" ? APP_RESET_ENTRIES : AUDIT_HISTORY_ENTRIES
    const removed: string[] = []
    for (const entry of targets) {
      const path = join(stateDir, entry)
      if (!existsSync(path)) continue
      try {
        rmSync(path, { recursive: true, force: true })
        removed.push(entry)
      } catch (err) {
        logError(`Reset could not remove ${entry}`, err, "Settings")
      }
    }
    logInfo(
      `Reset (${scope}) by ${user.email}: removed ${removed.join(", ") || "nothing"}`,
      "Settings",
    )
    if (scope === "app") {
      // config.yaml is gone → the schedule block is back to its defaults (OFF); disarm the timer.
      await this.scheduler.updateConfig({})
    }
    return { scope, removed }
  }
}

function cleanList(values: string[]): string[] {
  return [...new Set(values.map((v) => v.trim()).filter(Boolean))]
}
