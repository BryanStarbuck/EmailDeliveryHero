import { locateTool, runTool } from "@shared/tool-runner"
import { resolveCname, resolveTxt } from "../dns-util"
import type { CheckContext, CheckOutcome, Checker, Finding, Severity } from "../types"

/**
 * DMARC (pm/checks/dmarc.mdx). Resolves `_dmarc.<domain>`, parses the full tag map, and runs the
 * first-round sub-check set: presence, single-record, syntax/order, policy enforcement (p/sp/np),
 * alignment (adkim/aspf), deprecated pct, reporting (rua/ruf/fo/ri/rf), per-URI size suffixes,
 * external-report authorization (`<domain>._report._dmarc.<report-domain>`), org-domain walk-up
 * coverage, and the PS-03 misplaced-record heuristics. Returns findings plus the structured
 * `results.dmarc` payload — the §5 `dmarc:` section of the run YAML: worst-severity `status`, the
 * parsed observation (`record`), the shell-out provenance (`tool_runs[]` — doggo, checkdmarc, and
 * conditional kdig per §3), the per-sub-test `tests[]` rows, and the derived `problem_states`.
 */

const POLICIES = ["none", "quarantine", "reject"] as const
type Policy = (typeof POLICIES)[number]
const POLICY_RANK: Record<Policy, number> = { none: 0, quarantine: 1, reject: 2 }

/**
 * All tags we parse: the DMARCbis set (RFC 9989 adds np/psd/t) plus the legacy RFC 7489 tags that
 * DMARCbis removed (pct/rf/ri) — still parsed, but flagged as obsolete.
 */
const KNOWN_TAGS = new Set([
  "v",
  "p",
  "sp",
  "np",
  "psd",
  "t",
  "adkim",
  "aspf",
  "pct",
  "rua",
  "ruf",
  "fo",
  "ri",
  "rf",
])
const OBSOLETE_TAGS = new Set(["pct", "rf", "ri"])

export interface DmarcExternalAuth {
  report_kind: "rua" | "ruf"
  report_uri: string
  report_domain: string
  /** The name that must hold a v=DMARC1 TXT: `<audited>._report._dmarc.<report-domain>`. */
  auth_name: string
  authorized: boolean
}

/** The parsed observation — §5's `record:` block (field names match `dmarc_check_results` §10). */
export interface DmarcResults {
  query_name: string
  record_found: boolean
  record_count: number
  /** Where the effective record lives — `_dmarc.<domain>` or a parent when covered via walk-up. */
  found_at: string | null
  raw_record: string | null
  parsed: Record<string, string> | null
  policy: Policy | null
  /** Effective subdomain policy (sp=, defaulting to p=). */
  subdomain_policy: Policy | null
  np_policy: string | null
  pct: number | null
  adkim: string
  aspf: string
  rua_uris: string[]
  ruf_uris: string[]
  fo: string | null
  ri: number | null
  is_enforcing: boolean
  external_reports_authorized: boolean | null
  external_report_auth: DmarcExternalAuth[]
}

/**
 * One external-tool invocation captured during a run — the LOCKED `tool_runs[]` entry shape shared
 * by all six category specs (pm/checks/dmarc.mdx §3/§5): exact argv `command`, ISO `started_at`,
 * wall-clock `duration_ms`, `exit_code` (null on timeout/kill/spawn failure), `output_format`,
 * the pruned `parsed` stdout, and `error` (stderr / "timeout after <n>ms") on failure.
 */
export interface DmarcToolRun {
  tool: string
  command: string
  started_at: string
  duration_ms: number
  exit_code: number | null
  output_format: "json" | "text"
  parsed: unknown | null
  error: string | null
}

/** One per-sub-test row of §5's `tests:` list (`result` ⇔ finding severity ok/critical/warning/info). */
export interface DmarcTestRow {
  id: string
  title: string
  result: "pass" | "fail" | "warn" | "info"
  detail?: string
  evidence?: string
  fix?: string
}

/**
 * The whole `dmarc:` section of the run YAML (pm/checks/dmarc.mdx §5) — what this checker returns
 * as `results.dmarc` and the runs-store persists verbatim under the top-level `dmarc` key.
 */
export interface DmarcSection {
  /** Worst severity across the tests below. */
  status: Severity
  record: DmarcResults
  tool_runs: DmarcToolRun[]
  tests: DmarcTestRow[]
  /** Matched §9 problem-state ids, e.g. ["PS-05", "PS-10"]. */
  problem_states: string[]
}

interface ParsedTag {
  name: string
  value: string
}

/** Tokenize a raw DMARC record into ordered tag/value pairs (names lower-cased, values trimmed). */
export function parseDmarcRecord(raw: string): ParsedTag[] {
  return raw
    .split(";")
    .map((t) => t.trim())
    .filter(Boolean)
    .map((token) => {
      const eq = token.indexOf("=")
      if (eq === -1) return { name: token.toLowerCase(), value: "" }
      return { name: token.slice(0, eq).trim().toLowerCase(), value: token.slice(eq + 1).trim() }
    })
}

/** Split a rua/ruf value into URIs, stripping an optional `!<size>` suffix. */
function splitReportUris(value: string): { uri: string; size: string | null; raw: string }[] {
  return value
    .split(",")
    .map((u) => u.trim())
    .filter(Boolean)
    .map((raw) => {
      const bang = raw.lastIndexOf("!")
      if (bang > 0) return { uri: raw.slice(0, bang), size: raw.slice(bang + 1), raw }
      return { uri: raw, size: null, raw }
    })
}

/** The mail domain of a mailto: report URI (null for non-mailto or malformed). */
function reportDomainOf(uri: string): string | null {
  const m = /^mailto:[^@]+@([a-z0-9.-]+)/i.exec(uri.trim())
  return m ? m[1].toLowerCase().replace(/\.$/, "") : null
}

/** True when `child` equals `parent` or is a subdomain of it (report URI on our own domain). */
function sameOrSubdomainOf(child: string, parent: string): boolean {
  return child === parent || child.endsWith(`.${parent}`)
}

interface Analysis {
  findings: Finding[]
  results: DmarcResults
  /** Distinct external report domains (kind + uri) still needing the _report._dmarc probe. */
  externalReports: { kind: "rua" | "ruf"; uri: string; domain: string }[]
}

/**
 * Pure analysis of one DMARC record for one audited domain — everything that needs no further DNS.
 * `foundAt` is the DNS name the record was read from (own `_dmarc` or a parent via walk-up).
 */
export function analyzeDmarcRecord(domain: string, raw: string, foundAt: string): Analysis {
  const findings: Finding[] = []
  const tags = parseDmarcRecord(raw)
  const map: Record<string, string> = {}
  for (const t of tags) if (!(t.name in map)) map[t.name] = t.value

  // Syntax / ordering: v=DMARC1 must be the first tag; p= should be the second (RFC 7489).
  if (tags.length === 0 || tags[0].name !== "v" || tags[0].value.toUpperCase() !== "DMARC1") {
    findings.push({
      id: "dmarc.syntax",
      checkId: "dmarc",
      title: "DMARC record does not start with v=DMARC1",
      severity: "critical",
      detail:
        "Receivers ignore a DMARC record whose first tag is not v=DMARC1 — the domain is treated as having no policy.",
      remediation: "Rewrite the record so it begins exactly with v=DMARC1; followed by p=.",
      evidence: raw,
    })
  } else if (tags.length < 2 || tags[1].name !== "p") {
    findings.push({
      id: "dmarc.syntax_p_position",
      checkId: "dmarc",
      title: "p= is not the second tag",
      severity: "warning",
      detail:
        "RFC 7489 requires the p= tag immediately after v=DMARC1. Most receivers tolerate it elsewhere, but some strict parsers discard the record.",
      remediation: `Reorder the record: v=DMARC1; p=${map.p ?? "quarantine"}; …`,
      evidence: raw,
    })
  }

  // Policy (p=).
  const policyRaw = map.p?.toLowerCase()
  const policy = (POLICIES as readonly string[]).includes(policyRaw ?? "")
    ? (policyRaw as Policy)
    : null
  if (!policyRaw) {
    findings.push({
      id: "dmarc.no_policy",
      checkId: "dmarc",
      title: "DMARC record has no p= tag",
      severity: "critical",
      detail:
        "Without a policy tag the record is invalid and receivers treat the domain as unprotected.",
      remediation: 'Add a policy, e.g. "; p=quarantine" (or p=none to start monitoring).',
      evidence: raw,
    })
  } else if (!policy) {
    findings.push({
      id: "dmarc.policy",
      checkId: "dmarc",
      title: `Invalid DMARC policy "p=${policyRaw}"`,
      severity: "critical",
      detail: "p= must be none, quarantine, or reject; anything else invalidates the record.",
      remediation: "Set p=none (monitor), p=quarantine, or p=reject.",
      evidence: raw,
    })
  } else if (policy === "none") {
    findings.push({
      id: "dmarc.p_none",
      checkId: "dmarc",
      title: "DMARC policy is monitor-only (p=none)",
      severity: "warning",
      detail:
        "p=none collects reports but tells receivers to deliver failing (spoofed) mail normally — zero protection.",
      remediation:
        "Once aggregate (rua) reports show legitimate mail passing aligned, raise to p=quarantine, then p=reject.",
      evidence: raw,
    })
  } else {
    findings.push({
      id: "dmarc.policy_ok",
      checkId: "dmarc",
      title: `DMARC enforced (p=${policy})`,
      severity: "ok",
      detail: `Receivers are instructed to ${policy} mail that fails DMARC alignment.`,
      evidence: raw,
    })
  }

  // Subdomain policy (sp=, defaults to p=) and np= (DMARCbis non-existent-subdomain policy).
  const spRaw = map.sp?.toLowerCase()
  const sp = (POLICIES as readonly string[]).includes(spRaw ?? "") ? (spRaw as Policy) : null
  const effectiveSp = sp ?? policy
  if (spRaw && !sp) {
    findings.push({
      id: "dmarc.subdomain",
      checkId: "dmarc",
      title: `Invalid subdomain policy "sp=${spRaw}"`,
      severity: "warning",
      detail: "sp= must be none, quarantine, or reject.",
      remediation: "Fix the sp= value, or remove it to inherit p=.",
      evidence: raw,
    })
  } else if (
    policy &&
    POLICY_RANK[policy] > 0 &&
    effectiveSp &&
    POLICY_RANK[effectiveSp] < POLICY_RANK[policy]
  ) {
    findings.push({
      id: "dmarc.subdomain",
      checkId: "dmarc",
      title: `Subdomains weaker than the org policy (sp=${effectiveSp})`,
      severity: "warning",
      detail: `p=${policy} protects the exact domain but sp=${effectiveSp} leaves every subdomain (e.g. anything@foo.${domain}) spoofable.`,
      remediation: `Set sp=${policy} (or remove sp= so subdomains inherit p=${policy}).`,
      evidence: raw,
    })
  } else if (policy && POLICY_RANK[policy] > 0) {
    findings.push({
      id: "dmarc.subdomain_ok",
      checkId: "dmarc",
      title: `Subdomains covered (effective sp=${effectiveSp})`,
      severity: "ok",
      detail: sp
        ? "An explicit sp= covers all subdomains."
        : `No sp= tag, so subdomains inherit p=${policy}.`,
    })
  }
  if (policy && POLICY_RANK[policy] > 0 && !map.np) {
    findings.push({
      id: "dmarc.np",
      checkId: "dmarc",
      title: "No np= (non-existent subdomain) policy",
      severity: "info",
      detail:
        "DMARCbis adds np= so mail from subdomains that do not exist in DNS can be rejected outright.",
      remediation: "If you never send from subdomains, add np=reject.",
    })
  }

  // Alignment modes (adkim / aspf, default relaxed).
  const adkim = (map.adkim ?? "r").toLowerCase()
  const aspf = (map.aspf ?? "r").toLowerCase()
  for (const [tag, value] of [
    ["adkim", adkim],
    ["aspf", aspf],
  ] as const) {
    if (value !== "r" && value !== "s") {
      findings.push({
        id: "dmarc.alignment",
        checkId: "dmarc",
        title: `Invalid alignment mode ${tag}=${value}`,
        severity: "warning",
        detail: `${tag} must be r (relaxed) or s (strict).`,
        remediation: `Set ${tag}=r (or remove the tag; relaxed is the default).`,
        evidence: raw,
      })
    } else if (value === "s") {
      findings.push({
        id: `dmarc.${tag}_strict`,
        checkId: "dmarc",
        title: `Strict ${tag === "adkim" ? "DKIM" : "SPF"} alignment (${tag}=s)`,
        severity: "warning",
        detail: `Strict alignment requires the ${tag === "adkim" ? "DKIM d=" : "Return-Path"} domain to exactly equal the From: domain — mail sent from subdomains or many ESPs will fail DMARC.`,
        remediation: `Use ${tag}=r (relaxed) unless every sender uses the exact From: domain.`,
        evidence: raw,
      })
    }
  }

  // pct= — deprecated in DMARCbis; pct<100 also masks a partial rollout.
  let pct: number | null = null
  if (map.pct !== undefined) {
    pct = /^\d+$/.test(map.pct) ? Number(map.pct) : null
    if (pct === null || pct > 100) {
      findings.push({
        id: "dmarc.pct",
        checkId: "dmarc",
        title: `Invalid pct=${map.pct}`,
        severity: "warning",
        detail: "pct must be an integer 0–100 — and is deprecated in DMARCbis anyway.",
        remediation: "Remove the pct tag.",
        evidence: raw,
      })
    } else if (pct < 100) {
      findings.push({
        id: "dmarc.pct",
        checkId: "dmarc",
        title: `Policy applies to only ${pct}% of mail (pct=${pct})`,
        severity: "warning",
        detail: `Receivers apply the policy to a ${pct}% sample; the rest of failing mail is delivered. DMARCbis deprecates pct entirely — receivers may ignore it.`,
        remediation:
          "Finish the rollout: remove the pct tag so the policy applies to 100% of mail.",
        evidence: raw,
      })
    } else {
      findings.push({
        id: "dmarc.pct",
        checkId: "dmarc",
        title: "Deprecated pct= tag present",
        severity: "info",
        detail: "pct=100 is the default; the tag is deprecated in DMARCbis and can be removed.",
        remediation: "Remove pct=100 at the next DNS edit.",
        evidence: raw,
      })
    }
  }

  // Aggregate reporting (rua=).
  const ruaEntries = map.rua ? splitReportUris(map.rua) : []
  const rufEntries = map.ruf ? splitReportUris(map.ruf) : []
  if (ruaEntries.length === 0) {
    findings.push({
      id: "dmarc.rua",
      checkId: "dmarc",
      title: "No aggregate reporting (rua=)",
      severity: "warning",
      detail:
        "Without rua= you get no visibility into who is sending as your domain or whether legitimate mail is failing alignment.",
      remediation: `Add rua=mailto:dmarc@${domain} (or your report-analytics mailbox).`,
      evidence: raw,
    })
  } else {
    const bad = ruaEntries.filter((e) => !reportDomainOf(e.uri))
    if (bad.length > 0) {
      findings.push({
        id: "dmarc.rua_invalid",
        checkId: "dmarc",
        title: "Invalid rua= report URI",
        severity: "warning",
        detail: `These rua entries are not valid mailto: URIs: ${bad.map((b) => b.raw).join(", ")}`,
        remediation: `Use comma-separated mailto: URIs, e.g. rua=mailto:dmarc@${domain}`,
        evidence: map.rua,
      })
    } else {
      findings.push({
        id: "dmarc.rua_ok",
        checkId: "dmarc",
        title: `Aggregate reports requested (${ruaEntries.length} destination${ruaEntries.length === 1 ? "" : "s"})`,
        severity: "ok",
        detail: `rua=${map.rua}`,
      })
    }
  }
  if (rufEntries.length === 0) {
    findings.push({
      id: "dmarc.ruf",
      checkId: "dmarc",
      title: "No failure reports (ruf=) — optional",
      severity: "info",
      detail:
        "ruf= per-failure samples are optional and privacy-sensitive; most receivers redact or skip them.",
      remediation: `Optionally add ruf=mailto:forensics@${domain}; fo=1.`,
    })
  }

  // fo / ri / rf sanity.
  if (map.fo !== undefined) {
    const tokens = map.fo.split(":").map((t) => t.trim().toLowerCase())
    if (tokens.some((t) => !["0", "1", "d", "s"].includes(t))) {
      findings.push({
        id: "dmarc.fo",
        checkId: "dmarc",
        title: `Invalid fo=${map.fo}`,
        severity: "info",
        detail: "fo tokens must be 0, 1, d, or s (colon-separated).",
        remediation: "Set fo=1 to get a report when either SPF or DKIM fails alignment.",
        evidence: raw,
      })
    }
  } else if (rufEntries.length > 0) {
    findings.push({
      id: "dmarc.fo",
      checkId: "dmarc",
      title: "ruf= set but fo= defaults to 0",
      severity: "info",
      detail:
        "With fo=0 (the default) failure reports are sent only when BOTH SPF and DKIM fail — you miss single-mechanism breakage.",
      remediation: "Add fo=1.",
      evidence: raw,
    })
  }
  let ri: number | null = null
  if (map.ri !== undefined) {
    ri = /^\d+$/.test(map.ri) ? Number(map.ri) : null
    if (ri === null) {
      findings.push({
        id: "dmarc.ri",
        checkId: "dmarc",
        title: `Invalid ri=${map.ri}`,
        severity: "info",
        detail: "ri must be a number of seconds (default 86400 = daily).",
        remediation: "Remove ri or set ri=86400.",
        evidence: raw,
      })
    } else if (ri < 3600) {
      findings.push({
        id: "dmarc.ri",
        checkId: "dmarc",
        title: `Report interval unrealistically low (ri=${ri})`,
        severity: "info",
        detail:
          "Most receivers send aggregate reports daily regardless; very low ri values are ignored.",
        remediation: "Set ri=86400 (or remove the tag).",
        evidence: raw,
      })
    }
  }
  if (map.rf !== undefined && map.rf.toLowerCase() !== "afrf") {
    findings.push({
      id: "dmarc.rf",
      checkId: "dmarc",
      title: `Non-standard report format rf=${map.rf}`,
      severity: "info",
      detail: "The only registered failure-report format is afrf.",
      remediation: "Remove rf (afrf is the default) or set rf=afrf.",
      evidence: raw,
    })
  }

  // Malformed !size suffixes on report URIs.
  const badSizes = [...ruaEntries, ...rufEntries].filter(
    (e) => e.size !== null && !/^\d+[kmgt]?$/i.test(e.size),
  )
  if (badSizes.length > 0) {
    findings.push({
      id: "dmarc.report_uri_size",
      checkId: "dmarc",
      title: "Malformed !size suffix on a report URI",
      severity: "info",
      detail: `Bad size limit on: ${badSizes.map((b) => b.raw).join(", ")} (expected e.g. !10m).`,
      remediation: "Fix the suffix or drop it (plain mailto: is fine).",
    })
  }

  // Unknown / deprecated tags.
  const unknown = tags.filter((t) => !KNOWN_TAGS.has(t.name)).map((t) => t.name)
  if (unknown.length > 0) {
    findings.push({
      id: "dmarc.deprecated_tags",
      checkId: "dmarc",
      title: `Unknown DMARC tag${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`,
      severity: "info",
      detail: "Unknown tags are ignored by receivers but usually indicate a typo.",
      remediation: "Remove or correct the unknown tags.",
      evidence: raw,
    })
  }
  const obsolete = tags
    .filter((t) => OBSOLETE_TAGS.has(t.name) && t.name !== "pct")
    .map((t) => t.name)
  if (obsolete.length > 0) {
    findings.push({
      id: "dmarc.deprecated_tags",
      checkId: "dmarc",
      title: `Obsolete tag${obsolete.length === 1 ? "" : "s"}: ${obsolete.join(", ")}`,
      severity: "info",
      detail: "These tags were removed in DMARCbis (RFC 9989); receivers ignore them.",
      remediation: "Drop the obsolete tags at the next DNS edit.",
      evidence: raw,
    })
  }

  // t=y (RFC 9989 testing flag — the pct=0 replacement): the policy is advisory only.
  if (map.t?.toLowerCase() === "y") {
    findings.push({
      id: "dmarc.testing",
      checkId: "dmarc",
      title: "Record is in testing mode (t=y)",
      severity: "warning",
      detail: `t=y tells receivers the policy is being tested and should not be enforced — effectively p=none regardless of p=${policy ?? "?"}.`,
      remediation: "Remove t=y (or set t=n) once you are ready to enforce the published policy.",
      evidence: raw,
    })
  }

  // External report destinations that need a _report._dmarc authorization probe.
  const externalReports: Analysis["externalReports"] = []
  const seen = new Set<string>()
  for (const [kind, entries] of [
    ["rua", ruaEntries],
    ["ruf", rufEntries],
  ] as const) {
    for (const e of entries) {
      const rd = reportDomainOf(e.uri)
      if (!rd || sameOrSubdomainOf(rd, domain)) continue
      const key = `${kind}:${rd}`
      if (seen.has(key)) continue
      seen.add(key)
      externalReports.push({ kind, uri: e.uri, domain: rd })
    }
  }

  const results: DmarcResults = {
    query_name: `_dmarc.${domain}`,
    record_found: true,
    record_count: 1,
    found_at: foundAt,
    raw_record: raw,
    parsed: map,
    policy,
    subdomain_policy: effectiveSp,
    np_policy: map.np?.toLowerCase() ?? null,
    pct,
    adkim,
    aspf,
    rua_uris: ruaEntries.map((e) => e.uri),
    ruf_uris: rufEntries.map((e) => e.uri),
    fo: map.fo ?? null,
    ri,
    // §5: policy in (quarantine, reject) AND not t=y — testing mode makes the policy advisory only.
    is_enforcing:
      (policy === "quarantine" || policy === "reject") && map.t?.toLowerCase() !== "y",
    external_reports_authorized: null,
    external_report_auth: [],
  }
  return { findings, results, externalReports }
}

/** Parent names to try when the domain itself has no record (approximate org-domain walk-up). */
export function walkUpCandidates(domain: string): string[] {
  const labels = domain.split(".").filter(Boolean)
  const out: string[] = []
  for (let i = 1; i <= labels.length - 2; i++) out.push(labels.slice(i).join("."))
  return out
}

const SEVERITY_RANK: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

/** Finding severity ⇔ §5 `tests[].result` (ok→pass, critical→fail, warning→warn, info→info). */
const RESULT_OF: Record<Severity, DmarcTestRow["result"]> = {
  ok: "pass",
  critical: "fail",
  warning: "warn",
  info: "info",
}

/** Findings → §5 `tests[]` rows — pass rows included so the page renders one explicit row per test. */
export function buildTests(findings: Finding[]): DmarcTestRow[] {
  return findings.map((f) => ({
    id: f.id,
    title: f.title,
    result: RESULT_OF[f.severity],
    ...(f.detail ? { detail: f.detail } : {}),
    ...(f.evidence ? { evidence: f.evidence } : {}),
    ...(f.remediation ? { fix: f.remediation } : {}),
  }))
}

function worstSeverity(findings: Finding[]): Severity {
  let worst: Severity = "ok"
  for (const f of findings) if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) worst = f.severity
  return worst
}

/**
 * The §9 problem-state mapping: finding ids (at their non-ok severities) → PS ids, plus the
 * misplaced-record heuristic (PS-03), the cross-category forwarding-fragility check (PS-13), and
 * the healthy goal state (PS-00). PS-11/PS-12 are FUTURE (rua ingestion, §12) and never derived.
 */
export function deriveProblemStates(
  findings: Finding[],
  opts: { misplacedHit?: boolean; enforcing?: boolean; dkimUnhealthy?: boolean } = {},
): string[] {
  const failing = new Map<string, Severity>()
  for (const f of findings) {
    if (f.severity === "ok") continue
    const seen = failing.get(f.id)
    if (!seen || SEVERITY_RANK[f.severity] > SEVERITY_RANK[seen]) failing.set(f.id, f.severity)
  }
  const has = (...ids: string[]): boolean => ids.some((id) => failing.has(id))
  const hasAt = (id: string, sev: Severity): boolean => failing.get(id) === sev
  const out: string[] = []
  if (has("dmarc.missing")) out.push("PS-01")
  if (has("dmarc.multiple")) out.push("PS-02")
  if (has("dmarc.missing") && opts.misplacedHit) out.push("PS-03")
  if (has("dmarc.syntax", "dmarc.no_policy") || hasAt("dmarc.policy", "critical")) out.push("PS-04")
  if (has("dmarc.p_none", "dmarc.testing")) out.push("PS-05")
  if (hasAt("dmarc.pct", "warning")) out.push("PS-06")
  if (has("dmarc.subdomain", "dmarc.np")) out.push("PS-07")
  if (has("dmarc.adkim_strict", "dmarc.aspf_strict")) out.push("PS-08")
  if (has("dmarc.rua", "dmarc.rua_invalid")) out.push("PS-09")
  if (hasAt("dmarc.external_report_auth", "critical")) out.push("PS-10")
  if (opts.enforcing && opts.dkimUnhealthy) out.push("PS-13")
  const unhealthy = [...failing.values()].some((s) => s === "warning" || s === "critical")
  if (out.length === 0 && !unhealthy && opts.enforcing) out.push("PS-00")
  return out
}

/** The §5 `record:` block for a domain where nothing was observed (missing / lookup failure). */
function emptyRecord(queryName: string): DmarcResults {
  return {
    query_name: queryName,
    record_found: false,
    record_count: 0,
    found_at: null,
    raw_record: null,
    parsed: null,
    policy: null,
    subdomain_policy: null,
    np_policy: null,
    pct: null,
    adkim: "r",
    aspf: "r",
    rua_uris: [],
    ruf_uris: [],
    fo: null,
    ri: null,
    is_enforcing: false,
    external_reports_authorized: null,
    external_report_auth: [],
  }
}

// ---------------------------------------------------------------------------------------------
// Shell-out provenance (§3 "How a test run executes the tools"): every external-tool invocation
// during a run lands as one `tool_runs[]` entry. In-process node:dns lookups are NOT tool runs.
// ---------------------------------------------------------------------------------------------

/** Brew formula per tool — named in the info finding when a binary is missing (§3: skipped). */
const TOOL_INSTALL: Record<string, string> = { doggo: "doggo", checkdmarc: "checkdmarc", kdig: "knot" }

/** Per-tool hard timeouts from the §3 execution table. */
const DOGGO_TIMEOUT_MS = 10_000
const CHECKDMARC_TIMEOUT_MS = 60_000
const KDIG_TIMEOUT_MS = 10_000

/**
 * Resolve a tool binary: the run's Stage-0 discovery map when provided (pm/run_checks.mdx §5.2),
 * else a direct PATH/fallback-dir search. null = not installed → the invocation is skipped.
 */
function toolPath(ctx: CheckContext, name: string): string | null {
  if (ctx.tools && name in ctx.tools) return ctx.tools[name]
  return locateTool(name)
}

interface ToolInvocation {
  entry: DmarcToolRun
  /** Raw stdout of a successful run (for cross-checks); null on failure/timeout. */
  stdout: string | null
}

/** One ToolRunner spawn → one locked-shape `tool_runs[]` entry (§3 execution rules). */
async function invokeTool(
  path: string,
  tool: string,
  args: readonly string[],
  timeoutMs: number,
  format: "json" | "text",
  prune: (parsed: unknown, stdout: string) => unknown,
  signal?: AbortSignal,
): Promise<ToolInvocation> {
  const started_at = new Date().toISOString()
  const t0 = Date.now()
  const res = await runTool(path, args, { timeoutMs, signal })
  const base = {
    tool,
    // Exact argv with every input substituted — copy-paste-reproducible from the UI (§3).
    command: `${tool} ${args.join(" ")}`,
    started_at,
    duration_ms: Date.now() - t0,
    output_format: format,
  }
  if (res.timedOut) {
    const entry = { ...base, exit_code: null, parsed: null, error: `timeout after ${timeoutMs}ms` }
    return { entry, stdout: null }
  }
  if (res.code !== 0) {
    const entry = {
      ...base,
      exit_code: res.code,
      parsed: null,
      error: res.stderr.trim() || `exit ${res.code ?? "?"}`,
    }
    return { entry, stdout: null }
  }
  if (format === "text") {
    return { entry: { ...base, exit_code: 0, parsed: prune(null, res.stdout), error: null }, stdout: res.stdout }
  }
  try {
    const parsed = prune(JSON.parse(res.stdout), res.stdout)
    return { entry: { ...base, exit_code: 0, parsed, error: null }, stdout: res.stdout }
  } catch {
    const entry = { ...base, exit_code: 0, parsed: null, error: "stdout was not parseable JSON" }
    return { entry, stdout: res.stdout }
  }
}

/** Pull every `answers[]` row out of doggo's JSON (tolerant of the exact envelope shape). */
export function extractDoggoAnswers(parsed: unknown): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = []
  const visit = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) visit(item)
      return
    }
    if (node && typeof node === "object") {
      const answers = (node as { answers?: unknown }).answers
      if (Array.isArray(answers)) {
        for (const a of answers) {
          if (a && typeof a === "object") out.push(a as Record<string, unknown>)
        }
      } else {
        for (const v of Object.values(node)) visit(v)
      }
    }
  }
  visit(parsed)
  return out
}

/** The TXT string values among doggo answers (quotes stripped) — feeds the resolver cross-check. */
export function doggoTxtValues(answers: Record<string, unknown>[]): string[] {
  const vals: string[] = []
  for (const a of answers) {
    const v = a.answer ?? a.value ?? a.rdata ?? a.address
    if (typeof v === "string") vals.push(v.replace(/"\s+"/g, "").replace(/^"|"$/g, "").trim())
  }
  return vals
}

/** Prune checkdmarc's JSON to the `dmarc` object fields we consume (§3 row 3). */
function pruneCheckdmarc(parsed: unknown): unknown {
  if (parsed && typeof parsed === "object" && "dmarc" in parsed) {
    const d = (parsed as { dmarc: unknown }).dmarc
    if (d && typeof d === "object") {
      const src = d as Record<string, unknown>
      const keep: Record<string, unknown> = {}
      for (const k of ["record", "valid", "location", "tags", "warnings", "error"]) {
        if (k in src) keep[k] = src[k]
      }
      return { dmarc: keep }
    }
    return { dmarc: d }
  }
  return parsed
}

/** Append a cross-check note to the first present finding among `ids` (mismatch provenance, §3). */
function appendDetail(findings: Finding[], ids: string[], note: string): void {
  const f = ids.map((id) => findings.find((x) => x.id === id)).find(Boolean) ?? findings[0]
  if (f) f.detail = f.detail ? `${f.detail} ${note}` : note
}

/**
 * PS-03 misplaced-record heuristics (§4 edge cases, §12 first-round): a DMARC-looking TXT string
 * at the apex or at `dmarc.<domain>` (missing underscore), or `_dmarc` being a CNAME whose target
 * yields no record — the owner published something, but receivers never see a policy.
 */
async function probeMisplacedRecord(domain: string): Promise<string[]> {
  const dmarcish = (r: string): boolean => r.trim().toLowerCase().startsWith("v=dmarc1")
  const [apex, noUnderscore, cname] = await Promise.all([
    resolveTxt(domain),
    resolveTxt(`dmarc.${domain}`),
    resolveCname(`_dmarc.${domain}`),
  ])
  const hits: string[] = []
  if (apex.records.some(dmarcish)) hits.push(domain)
  if (noUnderscore.records.some(dmarcish)) hits.push(`dmarc.${domain}`)
  if (cname.records.length > 0) {
    hits.push(`_dmarc.${domain} is a CNAME to ${cname.records[0]} (target answers no DMARC record)`)
  }
  return hits
}

export const dmarcCheck: Checker = {
  id: "dmarc",
  label: "DMARC record",
  async run(ctx): Promise<CheckOutcome> {
    const name = `_dmarc.${ctx.domain}`
    const findings: Finding[] = []
    let record: DmarcResults = emptyRecord(name)
    let externalReports: Analysis["externalReports"] = []
    let misplacedHit = false
    let lookupFailed = false

    const lookup = await resolveTxt(name)
    if (lookup.error) {
      // SERVFAIL/timeout is transient — a warning to re-run, never a false "no record" critical.
      lookupFailed = true
      findings.push({
        id: "dmarc.lookup_failed",
        checkId: "dmarc",
        title: "Could not look up DMARC",
        severity: "warning",
        detail: `DNS lookup for TXT ${name} failed (${lookup.error}).`,
        remediation:
          "Retry the audit; if it persists, verify the domain's nameservers respond for _dmarc.",
      })
    } else {
      let dmarc = lookup.records.filter((r) => r.toLowerCase().startsWith("v=dmarc1"))
      let foundAt = name

      // Tree walk toward the org domain (RFC 9989): a subdomain with no record of its own is
      // still covered by the closest parent record's sp=.
      if (dmarc.length === 0) {
        for (const parent of walkUpCandidates(ctx.domain)) {
          const parentLookup = await resolveTxt(`_dmarc.${parent}`)
          const parentRecords = parentLookup.records.filter((r) =>
            r.toLowerCase().startsWith("v=dmarc1"),
          )
          if (parentRecords.length > 0) {
            dmarc = parentRecords
            foundAt = `_dmarc.${parent}`
            break
          }
        }
      }

      if (dmarc.length === 0) {
        const misplaced = await probeMisplacedRecord(ctx.domain)
        misplacedHit = misplaced.length > 0
        findings.push({
          id: "dmarc.missing",
          checkId: "dmarc",
          title: "No DMARC record",
          severity: "critical",
          detail:
            `${name} has no v=DMARC1 record (and no parent domain covers it). Anyone can spoof the exact From: domain, and Gmail/Yahoo bulk-sender rules penalize senders without DMARC.` +
            (misplacedHit
              ? ` A DMARC-looking record WAS found in the wrong place: ${misplaced.join("; ")} — receivers only read ${name}.`
              : ""),
          remediation: `Publish a TXT record at _dmarc.${ctx.domain} — start with "v=DMARC1; p=none; rua=mailto:dmarc@${ctx.domain}" to collect reports, then move to p=quarantine and finally p=reject.`,
          ...(misplacedHit ? { evidence: misplaced.join("; ") } : {}),
        })
      } else if (dmarc.length > 1) {
        findings.push({
          id: "dmarc.multiple",
          checkId: "dmarc",
          title: "Multiple DMARC records",
          severity: "critical",
          detail:
            "More than one v=DMARC1 record is published; per the spec receivers discard ALL of them, so the domain has no effective policy.",
          remediation: `Delete the extra TXT record(s) so exactly one v=DMARC1 string remains at ${foundAt}.`,
          evidence: dmarc.join(" | "),
        })
        record = {
          ...emptyRecord(name),
          record_found: true,
          record_count: dmarc.length,
          found_at: foundAt,
          raw_record: dmarc.join(" | "),
        }
      } else {
        const analysis = analyzeDmarcRecord(ctx.domain, dmarc[0], foundAt)
        record = analysis.results
        externalReports = analysis.externalReports

        if (foundAt !== name) {
          analysis.findings.unshift({
            id: "dmarc.present",
            checkId: "dmarc",
            title: `Covered by the parent record at ${foundAt}`,
            severity: "info",
            detail: `${name} has no record of its own; receivers fall back to ${foundAt}, whose subdomain policy (sp=${record.subdomain_policy ?? "none"}) governs this domain.`,
            remediation: `Publish a dedicated record at ${name} if this subdomain needs its own policy or reporting.`,
            evidence: dmarc[0],
          })
        } else {
          analysis.findings.unshift({
            id: "dmarc.present",
            checkId: "dmarc",
            title: "DMARC record found",
            severity: "ok",
            detail: `A single v=DMARC1 record is published at ${name}.`,
            evidence: dmarc[0],
          })
        }
        findings.push(...analysis.findings)

        // External-report authorization: for every rua/ruf destination on a foreign domain, the
        // receiver domain must publish `<audited>._report._dmarc.<report-domain>` = v=DMARC1, or
        // the reports are silently dropped.
        for (const ext of externalReports) {
          const authName = `${ctx.domain}._report._dmarc.${ext.domain}`
          const probe = await resolveTxt(authName)
          const authorized = probe.records.some((r) => r.toLowerCase().startsWith("v=dmarc1"))
          record.external_report_auth.push({
            report_kind: ext.kind,
            report_uri: ext.uri,
            report_domain: ext.domain,
            auth_name: authName,
            authorized,
          })
          if (probe.error && !authorized) {
            findings.push({
              id: "dmarc.external_report_auth",
              checkId: "dmarc",
              title: `Could not verify report authorization for ${ext.domain}`,
              severity: "info",
              detail: `Lookup of ${authName} failed (${probe.error}); re-run to confirm the ${ext.kind} destination is authorized.`,
            })
          } else if (!authorized) {
            findings.push({
              id: "dmarc.external_report_auth",
              checkId: "dmarc",
              title: `Report destination ${ext.domain} is not authorized`,
              severity: "critical",
              detail: `${ext.kind}= points at ${ext.uri}, but ${authName} has no v=DMARC1 TXT record — ${ext.domain} will silently discard your reports.`,
              remediation: `Have ${ext.domain} publish TXT ${authName} = "v=DMARC1" (report providers document this), or point ${ext.kind}= at a mailbox on ${ctx.domain}.`,
            })
          }
        }
        if (externalReports.length > 0) {
          const allAuthorized = record.external_report_auth.every((a) => a.authorized)
          record.external_reports_authorized = allAuthorized
          if (allAuthorized) {
            findings.push({
              id: "dmarc.external_report_auth_ok",
              checkId: "dmarc",
              title: "External report destinations authorized",
              severity: "ok",
              detail: `All ${record.external_report_auth.length} external report domain(s) publish the _report._dmarc authorization.`,
            })
          }
        }
      }
    }

    // ---- Shell-out provenance (§3 execution table, rows 1–4) ----------------------------------
    const toolRuns: DmarcToolRun[] = []
    const missingTools: string[] = []
    let resolverDisagrees = false

    const doggoPath = toolPath(ctx, "doggo")
    if (!doggoPath) {
      missingTools.push("doggo")
    } else {
      // Row 1: the record lookup — the raw TXT evidence cross-checking the in-process answer.
      const inv = await invokeTool(
        doggoPath,
        "doggo",
        [name, "TXT", "--json"],
        DOGGO_TIMEOUT_MS,
        "json",
        (p) => ({ answers: extractDoggoAnswers(p) }),
        ctx.signal,
      )
      toolRuns.push(inv.entry)
      if (inv.entry.exit_code === 0 && inv.entry.parsed) {
        const values = doggoTxtValues(
          (inv.entry.parsed as { answers: Record<string, unknown>[] }).answers,
        ).filter((v) => v.toLowerCase().startsWith("v=dmarc1"))
        const ownRecord =
          record.found_at === name && record.record_count === 1 ? record.raw_record : null
        if (ownRecord && values.length > 0 && !values.includes(ownRecord)) {
          resolverDisagrees = true
          appendDetail(
            findings,
            ["dmarc.present"],
            `Cross-check: doggo saw a different TXT answer (${values.join(" | ")}) — resolver inconsistency.`,
          )
        } else if (!record.record_found && !lookupFailed && values.length > 0) {
          resolverDisagrees = true
          appendDetail(
            findings,
            ["dmarc.missing"],
            `Cross-check: doggo DID see a v=DMARC1 answer (${values.join(" | ")}) — resolver inconsistency; re-run to confirm.`,
          )
        }
      }
      // Row 2: one authorization probe per DISTINCT external report domain (deduped).
      for (const rd of [...new Set(externalReports.map((e) => e.domain))]) {
        const probe = await invokeTool(
          doggoPath,
          "doggo",
          [`${ctx.domain}._report._dmarc.${rd}`, "TXT", "--json"],
          DOGGO_TIMEOUT_MS,
          "json",
          (p) => ({ answers: extractDoggoAnswers(p) }),
          ctx.signal,
        )
        toolRuns.push(probe.entry)
      }
    }

    // Row 3: checkdmarc — the conformance oracle cross-validating our parser.
    const checkdmarcPath = toolPath(ctx, "checkdmarc")
    if (!checkdmarcPath) {
      missingTools.push("checkdmarc")
    } else {
      const inv = await invokeTool(
        checkdmarcPath,
        "checkdmarc",
        [ctx.domain, "-f", "json"],
        CHECKDMARC_TIMEOUT_MS,
        "json",
        pruneCheckdmarc,
        ctx.signal,
      )
      toolRuns.push(inv.entry)
      if (inv.entry.exit_code === 0 && inv.entry.parsed && typeof inv.entry.parsed === "object") {
        const d = (inv.entry.parsed as { dmarc?: { valid?: unknown } }).dmarc
        const oracleValid = d && typeof d === "object" ? d.valid : undefined
        const oursInvalid = findings.some(
          (f) =>
            f.severity === "critical" &&
            ["dmarc.syntax", "dmarc.no_policy", "dmarc.policy", "dmarc.multiple", "dmarc.missing"].includes(f.id),
        )
        // Disagreement between the oracle and our verdict → note it on the affected test row.
        if (typeof oracleValid === "boolean" && oracleValid === oursInvalid) {
          appendDetail(
            findings,
            ["dmarc.present", "dmarc.missing", "dmarc.multiple", "dmarc.syntax"],
            `Cross-check: checkdmarc disagrees (valid=${String(oracleValid)}) — compare its output in the tool-runs footer.`,
          )
        }
      }
    }

    // Row 4 (conditional): kdig against a public resolver — only on resolver disagreement or a
    // failed in-process lookup ("does 8.8.8.8 see the same record?").
    if (lookupFailed || resolverDisagrees) {
      const kdigPath = toolPath(ctx, "kdig")
      if (!kdigPath) {
        missingTools.push("kdig")
      } else {
        const inv = await invokeTool(
          kdigPath,
          "kdig",
          ["@8.8.8.8", "+short", "TXT", name],
          KDIG_TIMEOUT_MS,
          "text",
          (_p, stdout) => ({ lines: stdout.trim().split("\n").filter(Boolean) }),
          ctx.signal,
        )
        toolRuns.push(inv.entry)
      }
    }

    // Rows 5–6 (mailauth / parsedmarc) are optional/future: mailauth needs a user-supplied .eml,
    // parsedmarc runs inside the rua-ingestion job (pm/emails.mdx) — neither input exists here.

    // Missing binary → invocation skipped, surfaced ONCE per run as an info finding (§3).
    if (missingTools.length > 0) {
      const formulas = [...new Set(missingTools.map((m) => TOOL_INSTALL[m] ?? m))]
      findings.push({
        id: "dmarc.tool_missing",
        checkId: "dmarc",
        title: `Debug tool${missingTools.length === 1 ? "" : "s"} not installed: ${missingTools.join(", ")}`,
        severity: "info",
        detail: `The ${missingTools.join(", ")} invocation${missingTools.length === 1 ? " was" : "s were"} skipped; the first-round DNS checks above still ran in-process.`,
        remediation: `brew install ${formulas.join(" ")}`,
      })
    }

    // ---- The §5 `dmarc:` section — status, record, tool_runs, tests, problem_states ----------
    const dkim = ctx.upstream?.dkim as { working_selectors?: number } | undefined
    const dkimUnhealthy = typeof dkim?.working_selectors === "number" && dkim.working_selectors === 0
    const section: DmarcSection = {
      status: worstSeverity(findings),
      record,
      tool_runs: toolRuns,
      tests: buildTests(findings),
      problem_states: deriveProblemStates(findings, {
        misplacedHit,
        enforcing: record.is_enforcing,
        dkimUnhealthy,
      }),
    }
    return { findings, results: section }
  },
}
