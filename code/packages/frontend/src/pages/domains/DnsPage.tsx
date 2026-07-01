import { Link, useNavigate, useParams } from "@tanstack/react-router"
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Info,
  Network,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from "lucide-react"
import { useState } from "react"
import { useAuditResults } from "@/api/audit"
import { useDomains } from "@/api/domains"
import type {
  DnsHealthResults,
  DnssecResults,
  Finding,
  MxRoutingResults,
  ReverseDnsResults,
  Severity,
} from "@/api/types"
import { CopyFixButton } from "@/components/CopyFixButton"
import { StatusCell } from "@/components/StatusCell"
import { NEVER_CELL, rollupCategories } from "@/lib/categories"
import { type FamilyRollup, infraFindings, rollupFamilies } from "@/lib/dns-families"
import { matchDnsProblemStates } from "@/lib/dns-problems"
import { cn } from "@/lib/utils"
import { useScanProgress, useScanRunner } from "@/scan/ScanProgressContext"

const ORDER: Record<Severity, number> = { critical: 0, warning: 1, info: 2, ok: 3 }

/**
 * The full-page DNS & Infrastructure view (pm/checks/dns.mdx §6.2/§7) — everything about one
 * domain's plumbing: the ten-chip family strip, the §8 fix-order-ladder verdict + CTA, the Mail
 * path panel (MX → IP → PTR), the Zone panel (NS/SOA/TTL/wildcard/DNSSEC), the family-grouped
 * fail-first test-results table, and problem-state cards linking to the drill-down pages.
 */
export function DnsPage() {
  const { id = "" } = useParams({ strict: false }) as { id?: string }
  const { data: domains } = useDomains()
  const { data: results } = useAuditResults()
  const runDomains = useScanRunner()
  const scanning = useScanProgress().some((s) => s.domainId === id)
  const navigate = useNavigate()

  const domain = (domains ?? []).find((d) => d.id === id)
  const result = (results ?? []).find((r) => r.domainId === id)
  const findings = infraFindings(result?.findings)
  const families = rollupFamilies(findings)
  const cell = rollupCategories(result?.findings).dnsInfra ?? NEVER_CELL
  const problems = matchDnsProblemStates(findings)

  const mx = result?.results?.["infra.mx_routing"] as MxRoutingResults | undefined
  const rdns = result?.results?.["infra.reverse_dns"] as ReverseDnsResults | undefined
  const zone = result?.results?.["infra.dns_health"] as DnsHealthResults | undefined
  const dnssec = result?.results?.["infra.dnssec"] as DnssecResults | undefined

  const onRunAgain = () => runDomains([{ id, name: domain?.name ?? id }])

  return (
    <div className="mx-auto max-w-5xl">
      <div className="mb-4 flex items-center justify-between">
        <button
          type="button"
          onClick={() => navigate({ to: "/domains/$id", params: { id } })}
          className="inline-flex items-center gap-1 text-sm text-[var(--edh-muted)] hover:text-slate-700"
        >
          <ArrowLeft className="h-4 w-4" /> Back to {domain?.name ?? id}
        </button>
        <button
          type="button"
          onClick={onRunAgain}
          disabled={scanning}
          className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          <RefreshCw className={scanning ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
          Re-run
        </button>
      </div>

      <h1 className="text-2xl font-bold">DNS & Infrastructure</h1>
      <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-[var(--edh-muted)]">
        <span className="font-medium text-slate-900">{domain?.name ?? id}</span>
        <span className="w-32">
          <StatusCell status={cell} />
        </span>
        {result && <span>· ran {new Date(result.ranAt).toLocaleString()}</span>}
      </div>

      {!result ? (
        <div className="mt-6 rounded-lg border border-dashed border-[var(--edh-border)] p-10 text-center">
          <p className="text-slate-600">No audit yet.</p>
          <button
            type="button"
            onClick={onRunAgain}
            className="mt-2 inline-flex items-center gap-2 text-[var(--edh-primary)] underline"
          >
            Run checks
          </button>
        </div>
      ) : (
        <>
          <FamilyStrip families={families} findings={findings} dnssec={dnssec} />

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <MailPathPanel mx={mx} rdns={rdns} />
            <ZonePanel zone={zone} dnssec={dnssec} />
          </div>

          <TestResultsByFamily families={families} />

          {problems.length > 0 && (
            <section className="mt-6">
              <h2 className="mb-2 font-semibold">Problem states</h2>
              <div className="grid gap-3 sm:grid-cols-2">
                {problems.map((ps) => (
                  <Link
                    key={ps.id}
                    to="/domains/$id/dns/$problemId"
                    params={{ id, problemId: ps.id }}
                    className="group rounded-lg border border-[var(--edh-border)] bg-white p-4 hover:border-[var(--edh-primary)]"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold uppercase text-[var(--edh-muted)]">
                        {ps.id}
                      </span>
                      <ChevronRight className="h-4 w-4 text-[var(--edh-muted)] group-hover:text-[var(--edh-primary)]" />
                    </div>
                    <div className="mt-1 font-medium">{ps.title}</div>
                    <p className="mt-1 text-sm text-slate-600">{ps.hook}</p>
                  </Link>
                ))}
              </div>
            </section>
          )}
        </>
      )}
    </div>
  )
}

/** True when any warning/critical finding's id (after "infra.") starts with one of the prefixes. */
function anyFailing(findings: Finding[], prefixes: string[], severities: Severity[]): boolean {
  return findings.some((f) => {
    if (!severities.includes(f.severity)) return false
    const bare = f.id.startsWith("infra.") ? f.id.slice("infra.".length) : f.id
    return prefixes.some((p) => bare.startsWith(p))
  })
}

/**
 * The §8 fix-order ladder: first matching rung wins, so a registration hold outranks an MX
 * problem, which outranks rDNS, and DANE advice never appears while FCrDNS is failing.
 */
function ladderNextStep(findings: Finding[], dnssec?: DnssecResults): string {
  const crit: Severity[] = ["critical"]
  const warnUp: Severity[] = ["critical", "warning"]
  if (anyFailing(findings, ["hold_status", "pending_delete", "domain_expiry"], crit))
    return "Fix the registration first — a domain on hold or expiring resolves for no one; nothing else matters until it's back."
  if (anyFailing(findings, ["mx_", "dangling_include.mx"], crit))
    return "Restore inbound routing: publish MX records whose targets resolve to public A/AAAA hosts. Bounces, FBL mail, and DMARC reports all depend on it."
  if (anyFailing(findings, ["ptr_", "fcrdns"], crit))
    return "Close FCrDNS on every mail IP — a hard Gmail/Microsoft gate, not a score. Open the hosting-provider PTR ticket today, or disable outbound IPv6 until its PTR exists."
  if (anyFailing(findings, ["tls_transport"], crit))
    return "Get every MX offering STARTTLS with a valid certificate matching the MX hostname — TLS in transit is required by all three major receivers."
  if (anyFailing(findings, ["dnssec_ds_algo_match"], crit))
    return "Fix or temporarily remove the DS at the registrar — a bogus DNSSEC chain SERVFAILs your whole zone at Google/Cloudflare/Quad9 resolvers."
  if (
    anyFailing(
      findings,
      [
        "ns_",
        "glue_records",
        "soa_",
        "ttl_sanity",
        "wildcard",
        "cname_at_apex",
        "multi_txt_spf",
        "txt_bloat",
        "recursion_open",
        "zone_transfer",
        "dangling_",
      ],
      warnUp,
    )
  )
    return "Stabilize the zone: second NS provider, sane SOA/TTLs, no wildcard or dangling records. Flaky DNS causes intermittent auth failures everywhere else."
  if (anyFailing(findings, ["dnssec_"], warnUp))
    return "Clean up DNSSEC: modern algorithm (13), SHA-256 DS, no stale keys — a broken chain is an outage waiting to happen."
  if (anyFailing(findings, ["mta_sts"], warnUp))
    return "Publish MTA-STS (mode: testing with TLS-RPT for 14–30 days, then enforce with max_age 604800)."
  if (anyFailing(findings, ["tls_rpt"], warnUp))
    return "Add TLS-RPT (_smtp._tls TXT) — you can't run an enforce-mode TLS policy blind."
  if (dnssec && !dnssec.signed)
    return "Sign the zone (algorithm 13, automated re-signing, CDS/CDNSKEY for the DS) — the prerequisite for DANE."
  if (dnssec?.dane_ready && anyFailing(findings, ["dane_"], warnUp))
    return "Publish a 3 1 1 TLSA record for every MX host (current + next during rollover); verify with gnutls-cli --dane."
  return "Keep it healthy: registrar auto-renew + transfer lock, RRSIG-expiry watch, scheduled re-runs — regressions are the real enemy now."
}

/** The plain-language verdict line above the CTA — rejected now / eroding / hardening / healthy. */
function verdictLine(findings: Finding[]): string {
  const gate = [
    "ptr_",
    "fcrdns",
    "mx_",
    "tls_transport",
    "hold_status",
    "pending_delete",
    "smtp_security",
    "dnssec_ds_algo_match",
    "dangling_",
  ]
  if (anyFailing(findings, gate, ["critical"]))
    return "Mail is being REJECTED: a hard receiver gate (FCrDNS, MX, TLS, or registration) is failing."
  if (findings.some((f) => f.severity === "critical"))
    return "A critical infrastructure problem is hurting delivery."
  if (findings.some((f) => f.severity === "warning"))
    return "Delivery works, but reputation-eroding infrastructure warnings are open."
  return "Plumbing healthy end to end — hardening options below are optional upgrades."
}

const CHIP_STYLE: Record<string, string> = {
  critical: "bg-red-600 text-white",
  warning: "bg-amber-500 text-white",
  info: "bg-slate-200 text-slate-600",
  ok: "bg-emerald-600 text-white",
  never: "border border-slate-300 text-slate-400",
}

function chipGlyph(worst: Severity | null): string {
  if (worst === "critical") return "✗"
  if (worst === "warning") return "⚠"
  if (worst === "info") return "ⓘ"
  if (worst === "ok") return "✓"
  return "·"
}

/** The hero band: ten family chips (anchor-linked to their table groups) + verdict + one CTA. */
function FamilyStrip({
  families,
  findings,
  dnssec,
}: {
  families: FamilyRollup[]
  findings: Finding[]
  dnssec?: DnssecResults
}) {
  return (
    <div className="mt-4 rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <div className="flex flex-wrap gap-2">
        {families.map((fam) => (
          <button
            key={fam.def.key}
            type="button"
            onClick={() =>
              document
                .getElementById(`fam-${fam.def.key}`)
                ?.scrollIntoView({ behavior: "smooth", block: "start" })
            }
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium",
              CHIP_STYLE[fam.worst ?? "never"],
            )}
            title={`${fam.def.header} — ${fam.findings.length} tests, ${fam.failCount} failing`}
          >
            {chipGlyph(fam.worst)} {fam.def.chip}
          </button>
        ))}
      </div>
      <p className="mt-3 text-sm text-slate-700">{verdictLine(findings)}</p>
      <p className="mt-1 text-sm font-medium text-[var(--edh-primary)]">
        Next step: {ladderNextStep(findings, dnssec)}
      </p>
    </div>
  )
}

/** MX → IP → PTR topology with per-hop status (pm/checks/dns.mdx §7 "Mail path"). */
function MailPathPanel({ mx, rdns }: { mx?: MxRoutingResults; rdns?: ReverseDnsResults }) {
  const ptrByIp = new Map((rdns?.ips ?? []).map((r) => [r.ip, r]))
  return (
    <section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <h2 className="mb-2 flex items-center gap-2 font-semibold">
        <Network className="h-4 w-4 text-[var(--edh-muted)]" /> Mail path
      </h2>
      {!mx ? (
        <p className="text-sm text-slate-600">No MX topology captured — re-run the audit.</p>
      ) : !mx.mx_found ? (
        <p className="text-sm text-slate-600">
          No MX record.{" "}
          {mx.implicit_a_fallback
            ? "Mail implicit-routes to the apex A record (fragile)."
            : "Inbound mail has nowhere to go."}
        </p>
      ) : mx.null_mx && mx.hosts.length === 0 ? (
        <p className="text-sm text-slate-600">
          Null MX (<span className="font-mono text-xs">MX 0 "."</span>) — this domain declares it
          accepts no mail.
        </p>
      ) : (
        <ul className="space-y-2">
          {mx.hosts.map((h) => (
            <li key={h.host} className="rounded-md border border-[var(--edh-border)] p-2 text-sm">
              <div className="flex items-center gap-2">
                <span className="w-8 shrink-0 text-right font-mono text-xs text-[var(--edh-muted)]">
                  {h.priority}
                </span>
                <span className="break-all font-mono text-xs font-semibold">{h.host}</span>
                {h.is_cname && (
                  <span className="rounded bg-red-100 px-1 text-[10px] font-semibold uppercase text-red-700">
                    CNAME ✗
                  </span>
                )}
              </div>
              <ul className="mt-1 space-y-0.5 pl-10">
                {h.ips.length === 0 && (
                  <li className="text-xs text-red-600">no A/AAAA — dangling target</li>
                )}
                {h.ips.map((ip) => {
                  const bad = h.non_public.find((n) => n.ip === ip)
                  const ptr = ptrByIp.get(ip)
                  return (
                    <li key={ip} className="flex flex-wrap items-center gap-1 font-mono text-xs">
                      <span className={cn(bad && "text-red-600")}>{ip}</span>
                      {bad && <span className="text-red-600">({bad.cls}) ✗</span>}
                      {ptr && (
                        <>
                          <span className="text-slate-400">→</span>
                          {ptr.ptr ? (
                            <span
                              className={cn(
                                ptr.forward_confirmed && !ptr.generic
                                  ? "text-emerald-700"
                                  : "text-amber-600",
                              )}
                            >
                              {ptr.ptr}
                              {ptr.forward_confirmed ? " ✓" : " (no FCrDNS) ✗"}
                              {ptr.generic ? " generic" : ""}
                            </span>
                          ) : (
                            <span className="text-red-600">no PTR ✗</span>
                          )}
                        </>
                      )}
                    </li>
                  )
                })}
              </ul>
            </li>
          ))}
          <li className="pl-10 text-xs text-[var(--edh-muted)]">
            {mx.redundancy.host_count} host{mx.redundancy.host_count === 1 ? "" : "s"} ·{" "}
            {mx.redundancy.network_count} network{mx.redundancy.network_count === 1 ? "" : "s"}
          </li>
        </ul>
      )}
    </section>
  )
}

/** NS / parent-child / SOA-with-ranges / TTL / wildcard / DNSSEC digest (§7 "Zone"). */
function ZonePanel({ zone, dnssec }: { zone?: DnsHealthResults; dnssec?: DnssecResults }) {
  const soaRows: { label: string; value: number | string; range: string }[] = zone?.soa
    ? [
        { label: "serial", value: zone.soa.serial, range: "YYYYMMDDnn" },
        { label: "refresh", value: zone.soa.refresh, range: "3600–86400" },
        { label: "retry", value: zone.soa.retry, range: "< refresh" },
        { label: "expire", value: zone.soa.expire, range: "604800–2419200" },
        { label: "min TTL", value: zone.soa.min_ttl, range: "300–86400" },
      ]
    : []
  return (
    <section className="rounded-lg border border-[var(--edh-border)] bg-white p-4">
      <h2 className="mb-2 font-semibold">Zone</h2>
      {!zone ? (
        <p className="text-sm text-slate-600">No zone snapshot captured — re-run the audit.</p>
      ) : (
        <div className="space-y-2 text-sm">
          <div>
            <span className="text-[var(--edh-muted)]">NS </span>
            <span className="break-all font-mono text-xs">
              {zone.ns.length > 0 ? zone.ns.map((n) => n.host).join(" · ") : "(none of its own)"}
            </span>
            {zone.ns_count > 0 && (
              <span className="ml-1 text-xs text-[var(--edh-muted)]">
                — {zone.ns_count} server{zone.ns_count === 1 ? "" : "s"}, {zone.network_count}{" "}
                network{zone.network_count === 1 ? "" : "s"}{" "}
                {zone.ns_count >= 2 && zone.network_count >= 2 ? "✓" : "⚠"}
              </span>
            )}
          </div>
          <div className="text-xs text-[var(--edh-muted)]">
            parent/child match:{" "}
            {zone.parent_child_match === null
              ? "pending probe"
              : zone.parent_child_match
                ? "✓"
                : "✗"}
          </div>
          {soaRows.length > 0 && (
            <table className="w-full text-xs">
              <tbody>
                {soaRows.map((r) => (
                  <tr key={r.label} className="border-t border-[var(--edh-border)]">
                    <td className="py-1 pr-2 text-[var(--edh-muted)]">SOA {r.label}</td>
                    <td className="py-1 pr-2 font-mono">{r.value}</td>
                    <td className="py-1 text-slate-400">{r.range}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="text-xs">
            wildcard:{" "}
            {zone.wildcard.detected ? (
              <span className="text-amber-600">detected ({zone.wildcard.types.join(", ")}) ⚠</span>
            ) : (
              <span className="text-emerald-700">none ✓</span>
            )}
            {" · apex CNAME: "}
            {zone.cname_at_apex ? (
              <span className="text-red-600">present ✗</span>
            ) : (
              <span className="text-emerald-700">none ✓</span>
            )}
          </div>
          <div className="border-t border-[var(--edh-border)] pt-2 text-xs">
            <span className="text-[var(--edh-muted)]">DNSSEC </span>
            {!dnssec ? (
              "state not captured"
            ) : !dnssec.signed ? (
              <span className="text-slate-600">unsigned (advisory — required for DANE)</span>
            ) : dnssec.ds_matches_dnskey === false ? (
              <span className="font-semibold text-red-600">
                BROKEN — DS does not match a live key; validating resolvers SERVFAIL this zone ✗
              </span>
            ) : (
              <span className="text-emerald-700">
                signed · alg {dnssec.algorithms.join("/") || "?"} · DS{" "}
                {dnssec.ds_present === null ? "?" : dnssec.ds_present ? "✓" : "missing ⚠"}
                {dnssec.dane_ready ? " · DANE-ready" : ""}
              </span>
            )}
          </div>
        </div>
      )}
    </section>
  )
}

/** The main table: one group per family (spec order), fail-first rows inside each group. */
function TestResultsByFamily({ families }: { families: FamilyRollup[] }) {
  const all = families.flatMap((f) => f.findings)
  const counts = {
    pass: all.filter((f) => f.severity === "ok").length,
    fail: all.filter((f) => f.severity === "critical").length,
    warn: all.filter((f) => f.severity === "warning").length,
    info: all.filter((f) => f.severity === "info").length,
  }
  return (
    <section className="mt-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="font-semibold">Test results</h2>
        <span className="text-xs text-[var(--edh-muted)]">
          {counts.pass} passed · {counts.fail} failed · {counts.warn} warnings · {counts.info} info
        </span>
      </div>
      <div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
        {all.length === 0 ? (
          <p className="p-4 text-sm text-slate-600">
            No DNS & Infrastructure tests in the latest run.
          </p>
        ) : (
          families
            .filter((fam) => fam.findings.length > 0)
            .map((fam) => (
              <div key={fam.def.key} id={`fam-${fam.def.key}`} className="scroll-mt-4">
                <div className="flex items-center justify-between border-t border-[var(--edh-border)] bg-slate-50 px-3 py-1.5 first:border-t-0">
                  <span className="text-xs font-semibold uppercase tracking-wide text-slate-600">
                    {fam.def.header}
                  </span>
                  <span className="text-xs text-[var(--edh-muted)]">
                    {fam.failCount > 0
                      ? `${fam.failCount} of ${fam.findings.length} failing`
                      : `${fam.findings.length} tests`}
                  </span>
                </div>
                <ul>
                  {[...fam.findings]
                    .sort((a, b) => ORDER[a.severity] - ORDER[b.severity])
                    .map((f) => (
                      <TestRow key={f.id + f.title} finding={f} />
                    ))}
                </ul>
              </div>
            ))
        )}
      </div>
    </section>
  )
}

function TestRow({ finding: f }: { finding: Finding }) {
  const [open, setOpen] = useState(f.severity === "critical")
  const icon =
    f.severity === "ok" ? (
      <ShieldCheck className="h-4 w-4 text-emerald-600" />
    ) : f.severity === "info" ? (
      <Info className="h-4 w-4 text-sky-600" />
    ) : (
      <ShieldAlert
        className={cn("h-4 w-4", f.severity === "critical" ? "text-red-600" : "text-amber-500")}
      />
    )
  return (
    <li className="border-t border-[var(--edh-border)] first:border-t-0">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-slate-50"
      >
        {icon}
        <span className="font-mono text-xs uppercase text-[var(--edh-muted)]">{f.id}</span>
        <span className="font-medium">{f.title}</span>
        <ChevronDown
          className={cn(
            "ml-auto h-4 w-4 shrink-0 text-[var(--edh-muted)] transition-transform",
            open && "rotate-180",
          )}
        />
      </button>
      {open && (
        <div className="px-3 pb-3 pl-9">
          <p className="text-sm text-slate-600">{f.detail}</p>
          {f.evidence && (
            <p className="mt-1 break-all rounded bg-slate-50 p-2 font-mono text-xs text-slate-600">
              observed: {f.evidence}
            </p>
          )}
          {f.remediation && f.severity !== "ok" && (
            <div className="mt-2 flex items-start justify-between gap-2 rounded-md bg-slate-50 p-2 text-sm text-slate-700">
              <span className="flex items-start gap-2">
                <Wrench className="mt-0.5 h-4 w-4 shrink-0 text-[var(--edh-primary)]" />
                <span>
                  <span className="font-medium">Fix: </span>
                  {f.remediation}
                </span>
              </span>
              <CopyFixButton text={f.remediation} />
            </div>
          )}
        </div>
      )}
    </li>
  )
}
