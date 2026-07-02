import { existsSync, readdirSync } from "node:fs"
import { join } from "node:path"
import { readJson, writeJson } from "@shared/json-store"
import { stateSubdir } from "@shared/state-dir"
import type { IngestState, ParsedDmarcReport, ParsedTlsRptReport } from "./report.types"

/**
 * The on-disk report store (pm/emails.mdx §9) — parsed reports persist as JSON under the state
 * root, one file per report, deduped by key:
 *
 *   <state>/reports/<domainId>/dmarc/<reporterOrg>-<reportId>.json
 *   <state>/reports/<domainId>/tlsrpt/<reporterOrg>-<reportDate>.json
 *   <state>/reports/<domainId>/ingest-state.json
 *
 * Pure module functions (no Nest DI) so both the ingestion service AND the audit checkers
 * (tls-rpt / dmarc-reports) read the same store; the file→DB move is a single-module change.
 */

/** A path-safe file stem from a report key part ("protection.outlook.com" → kept, "/" → "_"). */
function safeStem(value: string): string {
  const cleaned = value.replace(/[^A-Za-z0-9._@+-]+/g, "_").replace(/\.\./g, "_")
  return cleaned.length > 0 ? cleaned : "unknown"
}

function dmarcDir(domainId: string): string {
  return stateSubdir("reports", safeStem(domainId), "dmarc")
}

function tlsRptDir(domainId: string): string {
  return stateSubdir("reports", safeStem(domainId), "tlsrpt")
}

function ingestStatePath(domainId: string): string {
  return join(stateSubdir("reports", safeStem(domainId)), "ingest-state.json")
}

/** Dedupe key → file name for a DMARC aggregate report: (reporterOrg, reportId) (§4.5). */
function dmarcPath(domainId: string, report: ParsedDmarcReport): string {
  return join(
    dmarcDir(domainId),
    `${safeStem(report.reporterOrg)}-${safeStem(report.reportId)}.json`,
  )
}

/** Dedupe key → file name for a TLS-RPT report: (reporterOrg, reportDate) (§4.5). */
function tlsRptPath(domainId: string, report: ParsedTlsRptReport): string {
  return join(
    tlsRptDir(domainId),
    `${safeStem(report.reporterOrg)}-${safeStem(report.reportDate)}.json`,
  )
}

/** Store one DMARC report. Returns false (and writes nothing) when its key is already stored. */
export function saveDmarcReport(domainId: string, report: ParsedDmarcReport): boolean {
  const path = dmarcPath(domainId, report)
  if (existsSync(path)) return false
  writeJson(path, report)
  return true
}

/** Store one TLS-RPT report. Returns false when its (reporter, date) key is already stored. */
export function saveTlsRptReport(domainId: string, report: ParsedTlsRptReport): boolean {
  const path = tlsRptPath(domainId, report)
  if (existsSync(path)) return false
  writeJson(path, report)
  return true
}

function listDir<T>(dir: string): T[] {
  let files: string[] = []
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".json"))
  } catch {
    return []
  }
  const out: T[] = []
  for (const f of files) {
    const parsed = readJson<T | null>(join(dir, f), null)
    if (parsed) out.push(parsed)
  }
  return out
}

/** Every stored DMARC aggregate report for a domain, newest window first. */
export function listDmarcReports(domainId: string): ParsedDmarcReport[] {
  return listDir<ParsedDmarcReport>(dmarcDir(domainId)).sort((a, b) =>
    (b.window.end ?? "").localeCompare(a.window.end ?? ""),
  )
}

/** Every stored TLS-RPT report for a domain, newest first. */
export function listTlsRptReports(domainId: string): ParsedTlsRptReport[] {
  return listDir<ParsedTlsRptReport>(tlsRptDir(domainId)).sort((a, b) =>
    (b.reportDate ?? "").localeCompare(a.reportDate ?? ""),
  )
}

/** True when at least one report of either kind has ever been ingested for this domain. */
export function hasAnyReports(domainId: string): boolean {
  return listDmarcReports(domainId).length > 0 || listTlsRptReports(domainId).length > 0
}

export function readIngestState(domainId: string): IngestState {
  return readJson<IngestState>(ingestStatePath(domainId), { lastIngestAt: null, processedIds: [] })
}

export function writeIngestState(domainId: string, state: IngestState): void {
  writeJson(ingestStatePath(domainId), state)
}
