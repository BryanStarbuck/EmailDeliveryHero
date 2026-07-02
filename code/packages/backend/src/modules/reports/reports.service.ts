import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync } from "node:fs"
import { join } from "node:path"
import { DomainsService } from "@module/domains/domains.service"
import { Injectable, type OnModuleDestroy, type OnModuleInit } from "@nestjs/common"
import { readAppConfig } from "@shared/config-store"
import { logError, logInfo, logWarn } from "@shared/logging"
import { stateSubdir } from "@shared/state-dir"
import {
  aggregateDmarc,
  aggregateTlsRpt,
  deriveDmarcReportFindings,
  deriveTlsRptFindings,
  type DmarcAggregate,
  type TlsRptAggregate,
} from "./derive-findings"
import { parseDmarcAggregateXml } from "./dmarc-xml"
import { classifyPayload, extractReportPayloads } from "./mime"
import {
  listDmarcReports,
  listTlsRptReports,
  readIngestState,
  saveDmarcReport,
  saveTlsRptReport,
  writeIngestState,
} from "./report-store"
import type { IngestSummary, ParsedTlsRptReport } from "./report.types"
import { parseTlsRptJson } from "./tlsrpt-json"

/** File extensions the drop folder accepts (pm/emails.mdx §4.1). */
const DROP_EXTENSIONS = /\.(eml|xml|json|gz|zip)$/i

/** What the per-domain Reports view renders (pm/emails.mdx §7.1). */
export interface DomainReportsView {
  domainId: string
  domain: string
  ingestionEnabled: boolean
  windowDays: number
  lastIngestAt: string | null
  dmarc: DmarcAggregate & { totalReportsStored: number }
  tlsrpt: TlsRptAggregate & { totalReportsStored: number }
  findings: ReturnType<typeof deriveDmarcReportFindings>
}

/**
 * Report-email ingestion (pm/emails.mdx §4): receive → classify → decode → parse → normalize →
 * dedupe → store. First-round source is the admin-configured DROP FOLDER of `.eml`/`.xml`/`.json`/
 * `.gz`/`.zip` files (default `<state>/reports/inbox`); ingested files move to `processed/`.
 * Reports route to a monitored domain by the report's OWN policy domain
 * (`<policy_published><domain>` / TLS-RPT policy-domain), never the mailbox or filename (§8).
 * The poller runs on its own cadence (default hourly, §10) — deliberately decoupled from the
 * DNS-audit schedule. Everything is TypeScript on Node per the charter (§4.1).
 */
@Injectable()
export class ReportsService implements OnModuleInit, OnModuleDestroy {
  private pollTimer: NodeJS.Timeout | null = null

  constructor(private readonly domains: DomainsService) {}

  onModuleInit(): void {
    this.armPoller()
  }

  onModuleDestroy(): void {
    if (this.pollTimer) clearInterval(this.pollTimer)
  }

  /** The report-driven poll (pm/emails.mdx §10): hourly-ish, independent of the audit cadence. */
  private armPoller(): void {
    const config = readAppConfig().reports
    if (!config.enabled) return
    const everyMs = Math.max(1, config.pollMinutes) * 60 * 1000
    this.pollTimer = setInterval(() => {
      this.ingest().catch((err) => logError("Scheduled report ingest failed", err, "ReportsService"))
    }, everyMs)
    this.pollTimer.unref?.()
  }

  /** The effective drop folder ("" in config → the default `<state>/reports/inbox`). */
  dropFolder(): string {
    const configured = readAppConfig().reports.dropFolder.trim()
    return configured.length > 0 ? configured : stateSubdir("reports", "inbox")
  }

  /**
   * One ingest pass over every configured source (§4.1) — also the "Ingest now" action (§7.1).
   * Idempotent: reports dedupe by (reporterOrg, reportId/reportDate) so re-ingesting the same
   * corpus stores nothing new (§4.5).
   */
  async ingest(): Promise<IngestSummary> {
    const config = readAppConfig().reports
    const summary: IngestSummary = { scanned: 0, ingested: 0, duplicates: 0, skipped: 0, errors: [] }
    if (!config.enabled) {
      summary.errors.push("Report ingestion is disabled in Settings → Admin.")
      return summary
    }

    // IMAP mailbox poll — future ingestion source (the drop folder covers the first round; the
    // spec's OAuth mailbox auto-discovery is explicitly future, pm/emails.mdx §11).
    if (config.imap.host.trim().length > 0) {
      logWarn(
        `IMAP report mailbox ${config.imap.host} is configured but IMAP polling is not implemented yet — use the drop folder (${this.dropFolder()}) meanwhile`,
        "ReportsService",
      )
    }

    this.ingestDropFolder(summary)

    const touched = new Set(this.domains.list().map((d) => d.id))
    const now = new Date().toISOString()
    for (const domainId of touched) {
      const state = readIngestState(domainId)
      writeIngestState(domainId, { ...state, lastIngestAt: now })
    }
    logInfo(
      `Report ingest: ${summary.scanned} file(s) scanned, ${summary.ingested} report(s) ingested, ${summary.duplicates} duplicate(s), ${summary.skipped} skipped`,
      "ReportsService",
    )
    return summary
  }

  /** Scan the drop folder; every ingested file moves to `processed/` (§4.1). */
  private ingestDropFolder(summary: IngestSummary): void {
    const folder = this.dropFolder()
    let files: string[] = []
    try {
      files = readdirSync(folder).filter(
        (f) => DROP_EXTENSIONS.test(f) && statSync(join(folder, f)).isFile(),
      )
    } catch {
      return // No folder yet — nothing to ingest.
    }
    const processedDir = join(folder, "processed")
    for (const file of files) {
      const path = join(folder, file)
      summary.scanned++
      try {
        this.ingestBuffer(readFileSync(path), file, summary)
      } catch (err) {
        summary.errors.push(`${file}: ${err instanceof Error ? err.message : String(err)}`)
        logError(`Could not ingest report file ${file}`, err, "ReportsService")
        continue
      }
      // Move handled files (stored OR recognized duplicates) out of the inbox; best-effort.
      try {
        mkdirSync(processedDir, { recursive: true })
        const target = existsSync(join(processedDir, file))
          ? join(processedDir, `${Date.now()}-${file}`)
          : join(processedDir, file)
        renameSync(path, target)
      } catch {
        // Leaving the file in place is safe — dedupe keeps the next pass idempotent (§4.5).
      }
    }
  }

  /**
   * Classify → decode → parse → route one raw file (an `.eml` or a bare report payload).
   * Returns true when at least one NEW report was stored.
   */
  private ingestBuffer(raw: Buffer, sourceName: string, summary: IngestSummary): boolean {
    const payloads = extractReportPayloads(raw)
    if (payloads.length === 0) {
      // A non-report email in the mailbox: skip, log info, never error (§2 robustness rules).
      summary.skipped++
      logInfo(`No report attachment found in ${sourceName}; skipped`, "ReportsService")
      return false
    }
    let stored = false
    for (const payload of payloads) {
      const kind = classifyPayload(payload)
      if (kind === "dmarc") {
        const report = parseDmarcAggregateXml(payload.content.toString("utf8"))
        if (!report) {
          summary.skipped++
          continue
        }
        const domain = this.matchDomain(report.policyPublished.domain)
        if (!domain) {
          summary.skipped++
          logInfo(
            `DMARC report from ${report.reporterOrg} is for unmonitored domain ${report.policyPublished.domain}; skipped`,
            "ReportsService",
          )
          continue
        }
        if (saveDmarcReport(domain.id, report)) {
          summary.ingested++
          stored = true
          logInfo(
            `Ingested DMARC aggregate report ${report.reporterOrg}/${report.reportId} for ${domain.name} (${report.rows.length} row(s))`,
            "ReportsService",
          )
        } else {
          summary.duplicates++
        }
      } else if (kind === "tlsrpt") {
        const report = parseTlsRptJson(payload.content.toString("utf8"))
        if (!report) {
          summary.skipped++
          continue
        }
        stored = this.routeTlsRpt(report, summary) || stored
      } else {
        summary.skipped++
        logInfo(`Unrecognized report payload in ${sourceName}; skipped`, "ReportsService")
      }
    }
    return stored
  }

  /** A TLS-RPT report routes per policy-domain — one stored copy per matching monitored domain. */
  private routeTlsRpt(report: ParsedTlsRptReport, summary: IngestSummary): boolean {
    const byDomain = new Map<string, ParsedTlsRptReport>()
    for (const policy of report.policies) {
      const domain = this.matchDomain(policy.policyDomain)
      if (!domain) continue
      const existing = byDomain.get(domain.id)
      if (existing) existing.policies.push(policy)
      else byDomain.set(domain.id, { ...report, policies: [policy] })
    }
    if (byDomain.size === 0) {
      summary.skipped++
      logInfo(
        `TLS-RPT report from ${report.reporterOrg} matches no monitored domain (${report.policies.map((p) => p.policyDomain).join(", ")}); skipped`,
        "ReportsService",
      )
      return false
    }
    let stored = false
    for (const [domainId, routed] of byDomain) {
      if (saveTlsRptReport(domainId, routed)) {
        summary.ingested++
        stored = true
        logInfo(
          `Ingested TLS-RPT report ${routed.reporterOrg}/${routed.reportDate} for domain ${domainId}`,
          "ReportsService",
        )
      } else {
        summary.duplicates++
      }
    }
    return stored
  }

  /**
   * Route a report to a monitored domain by the report's OWN policy domain (§8): exact name match
   * first, else the closest monitored parent (a report for a subdomain rolls up to its org domain).
   */
  private matchDomain(reportDomain: string): { id: string; name: string } | null {
    const wanted = reportDomain.replace(/\.$/, "").toLowerCase()
    if (!wanted) return null
    const all = this.domains.list()
    const exact = all.find((d) => d.name.toLowerCase() === wanted)
    if (exact) return exact
    const parents = all.filter((d) => wanted.endsWith(`.${d.name.toLowerCase()}`))
    parents.sort((a, b) => b.name.length - a.name.length)
    return parents[0] ?? null
  }

  /** Everything the per-domain Reports view needs (pm/emails.mdx §7.1). */
  view(domainId: string): DomainReportsView {
    const domain = this.domains.get(domainId)
    const config = readAppConfig().reports
    const dmarcReports = listDmarcReports(domainId)
    const tlsReports = listTlsRptReports(domainId)
    return {
      domainId,
      domain: domain.name,
      ingestionEnabled: config.enabled,
      windowDays: config.windowDays,
      lastIngestAt: readIngestState(domainId).lastIngestAt,
      dmarc: { ...aggregateDmarc(dmarcReports, config.windowDays), totalReportsStored: dmarcReports.length },
      tlsrpt: { ...aggregateTlsRpt(tlsReports, config.windowDays), totalReportsStored: tlsReports.length },
      findings: [
        ...deriveDmarcReportFindings(domainId, domain.name),
        ...deriveTlsRptFindings(domainId, domain.name),
      ],
    }
  }
}
