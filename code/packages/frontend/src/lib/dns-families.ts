/**
 * The ten DNS & Infrastructure test families (pm/checks/dns.mdx §2) and the finding-id → family
 * matcher. Many `infra.*` finding ids carry a `.<host>` / `.<ip>` suffix, so matching is by id
 * prefix — longest/most-specific prefix first (e.g. `dnssec_ds_at_registrar` belongs to the
 * registration family even though it starts with `dnssec_`).
 */
import type { Finding, Severity } from "@/api/types"

export type DnsFamilyKey =
  | "mx_routing"
  | "reverse_dns"
  | "tls_transport"
  | "mta_sts"
  | "tls_rpt"
  | "dane_tlsa"
  | "dnssec"
  | "dns_health"
  | "domain_reputation"
  | "smtp_security"

export interface DnsFamilyDef {
  key: DnsFamilyKey
  /** Short chip label for the family status strip. */
  chip: string
  /** Full group header on the test-results table. */
  header: string
  /** Finding-id prefixes (after the leading "infra.") that roll into this family. */
  prefixes: string[]
}

/** The ten families in spec §2 order. Order matters for both the strip and the table groups. */
export const DNS_FAMILIES: DnsFamilyDef[] = [
  {
    key: "mx_routing",
    chip: "MX",
    header: "MX records & mail routing",
    prefixes: ["mx_", "backup_mx_hygiene"],
  },
  {
    key: "reverse_dns",
    chip: "rDNS",
    header: "Reverse DNS / PTR / FCrDNS",
    // "reverse_dns" catches the checker-scoped ids (infra.reverse_dns, .error, .did_not_complete).
    prefixes: ["ptr_", "fcrdns", "helo_match", "reverse_dns"],
  },
  {
    key: "tls_transport",
    chip: "TLS",
    header: "STARTTLS & MX certificates",
    prefixes: ["tls_transport"],
  },
  { key: "mta_sts", chip: "MTA-STS", header: "MTA-STS", prefixes: ["mta_sts"] },
  { key: "tls_rpt", chip: "TLS-RPT", header: "TLS-RPT", prefixes: ["tls_rpt"] },
  { key: "dane_tlsa", chip: "DANE", header: "DANE / TLSA", prefixes: ["dane_"] },
  // dnssec_ds_at_registrar is emitted by the registration checker — listed there, checked first.
  // The bare "dnssec" prefix catches checker-scoped ids (infra.dnssec.error, .did_not_complete).
  { key: "dnssec", chip: "DNSSEC", header: "DNSSEC", prefixes: ["dnssec_", "dnssec"] },
  {
    key: "dns_health",
    chip: "Zone",
    header: "DNS zone & nameserver health",
    prefixes: [
      "ns_",
      "soa_",
      "ttl_sanity",
      "wildcard",
      "cname_at_apex",
      "multi_txt_spf",
      "txt_bloat",
      "glue_records",
      "recursion_open",
      "zone_transfer",
      "dangling_",
      "dns_health",
    ],
  },
  {
    key: "domain_reputation",
    chip: "Domain",
    header: "Domain registration",
    prefixes: [
      "dnssec_ds_at_registrar",
      "domain_",
      "registrar_",
      "registrant_privacy",
      "auto_renew",
      "hold_status",
      "pending_delete",
      "recent_transfer",
      "record_available",
      "parked",
      "parking_nameservers",
      "tld_risk",
      "name_similarity",
      "idn_homograph",
      "update_lock",
      "delete_lock",
    ],
  },
  {
    key: "smtp_security",
    chip: "SMTP",
    header: "SMTP server security",
    prefixes: ["smtp_security"],
  },
]

/** Ordered (family, prefix) pairs — most specific prefix first so overlaps resolve correctly. */
const PREFIX_ORDER: { prefix: string; key: DnsFamilyKey }[] = DNS_FAMILIES.flatMap((f) =>
  f.prefixes.map((prefix) => ({ prefix, key: f.key })),
).sort((a, b) => b.prefix.length - a.prefix.length)

/** Which family an `infra.*` finding id belongs to; null for non-infra ids. */
export function familyOf(findingId: string): DnsFamilyKey | null {
  if (!findingId.startsWith("infra.")) return null
  const id = findingId.slice("infra.".length)
  for (const { prefix, key } of PREFIX_ORDER) if (id.startsWith(prefix)) return key
  return null
}

/** All findings from the latest run that belong to the DNS & Infrastructure category. */
export function infraFindings(findings: Finding[] | undefined): Finding[] {
  return (findings ?? []).filter((f) => f.checkId.split(".")[0] === "infra")
}

const WORST: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

export interface FamilyRollup {
  def: DnsFamilyDef
  findings: Finding[]
  /** Worst severity in the family; null when the family produced no findings this run. */
  worst: Severity | null
  failCount: number
}

/** Group the category's findings into the ten families, preserving spec order. */
export function rollupFamilies(findings: Finding[]): FamilyRollup[] {
  const byFamily = new Map<DnsFamilyKey, Finding[]>()
  for (const f of findings) {
    const key = familyOf(f.id)
    if (!key) continue
    const list = byFamily.get(key) ?? []
    list.push(f)
    byFamily.set(key, list)
  }
  return DNS_FAMILIES.map((def) => {
    const fam = byFamily.get(def.key) ?? []
    let worst: Severity | null = null
    for (const f of fam) if (worst === null || WORST[f.severity] > WORST[worst]) worst = f.severity
    return {
      def,
      findings: fam,
      worst,
      failCount: fam.filter((f) => f.severity === "warning" || f.severity === "critical").length,
    }
  })
}
