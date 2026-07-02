/**
 * The ten DNS & Infrastructure test families (pm/checks/dns.mdx §2) and the finding-id → family
 * matcher. Many `infra.*` finding ids carry a `.<host>` / `.<ip>` suffix, so matching is by id
 * prefix — longest/most-specific prefix first (e.g. `dnssec_ds_at_registrar` belongs to the
 * registration family even though it starts with `dnssec_`).
 */
import type { Finding, Severity } from "@/api/types";

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
	| "smtp_security";

export interface DnsFamilyDef {
	key: DnsFamilyKey;
	/**
	 * The `:checkKey` route slug of the family's check-detail explainer page (pm/checks/dns.mdx
	 * §14.1): the kebab-case of the family key, deliberately equal to the backend check directory
	 * name (code/packages/backend/src/modules/audit/checks/<slug>/). Fixed — never invent new slugs.
	 */
	slug: string;
	/** Short chip label for the family status strip. */
	chip: string;
	/** Full group header on the test-results table. */
	header: string;
	/** The §14.1 row label — used everywhere the family renders as a clickable row. */
	label: string;
	/** The §14.1 one-line meaning shown on family rows (run report's ten-family list). */
	meaning: string;
	/** Finding-id prefixes (after the leading "infra.") that roll into this family. */
	prefixes: string[];
}

/** The ten families in spec §2 order. Order matters for both the strip and the table groups. */
export const DNS_FAMILIES: DnsFamilyDef[] = [
	{
		key: "mx_routing",
		slug: "mx-routing",
		chip: "MX",
		header: "MX records & mail routing",
		label: "MX routing",
		meaning:
			"Can the world route mail to this domain — and bounces and reports back to you?",
		prefixes: ["mx_", "backup_mx_hygiene"],
	},
	{
		key: "reverse_dns",
		slug: "reverse-dns",
		chip: "rDNS",
		header: "Reverse DNS / PTR / FCrDNS",
		label: "Reverse DNS (PTR / FCrDNS)",
		meaning:
			"Does every sending/MX IP reverse-resolve to a real hostname that points back to it?",
		// "reverse_dns" catches the checker-scoped ids (infra.reverse_dns, .error, .did_not_complete).
		prefixes: ["ptr_", "fcrdns", "helo_match", "reverse_dns"],
	},
	{
		key: "tls_transport",
		slug: "tls-transport",
		chip: "TLS",
		header: "STARTTLS & MX certificates",
		label: "STARTTLS & MX certificates",
		meaning:
			"Is mail to this domain encrypted in transit with a valid, matching certificate?",
		prefixes: ["tls_transport"],
	},
	{
		key: "mta_sts",
		slug: "mta-sts",
		chip: "MTA-STS",
		header: "MTA-STS",
		label: "MTA-STS",
		meaning:
			"Is there a downgrade-resistant TLS policy that senders must honor?",
		prefixes: ["mta_sts"],
	},
	{
		key: "tls_rpt",
		slug: "tls-rpt",
		chip: "TLS-RPT",
		header: "TLS-RPT",
		label: "TLS-RPT",
		meaning:
			"Will anyone tell you when senders can't negotiate TLS with your MX?",
		prefixes: ["tls_rpt"],
	},
	{
		key: "dane_tlsa",
		slug: "dane-tlsa",
		chip: "DANE",
		header: "DANE / TLSA",
		label: "DANE / TLSA",
		meaning: "Is the MX certificate pinned in DNS for DANE-validating senders?",
		prefixes: ["dane_"],
	},
	// dnssec_ds_at_registrar is emitted by the registration checker — listed there, checked first.
	// The bare "dnssec" prefix catches checker-scoped ids (infra.dnssec.error, .did_not_complete).
	{
		key: "dnssec",
		slug: "dnssec",
		chip: "DNSSEC",
		header: "DNSSEC",
		label: "DNSSEC",
		meaning:
			"Are this zone's DNS answers cryptographically signed — and validly so?",
		prefixes: ["dnssec_", "dnssec"],
	},
	{
		key: "dns_health",
		slug: "dns-health",
		chip: "Zone",
		header: "DNS zone & nameserver health",
		label: "Zone & nameserver health",
		meaning:
			"Will every receiver's resolver get a fast, consistent, honest answer?",
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
		slug: "domain-reputation",
		chip: "Domain",
		header: "Domain registration",
		label: "Domain registration",
		meaning:
			"Does the registration look stable, locked, and mature — not throwaway?",
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
		slug: "smtp-security",
		chip: "SMTP",
		header: "SMTP server security",
		label: "SMTP hardening",
		meaning:
			"Is the mail server itself abusable — open relay, enumeration, plaintext auth?",
		prefixes: ["smtp_security"],
	},
];

/**
 * Resolve a `:checkKey` route param to its family (pm/checks/dns.mdx §14.1). The kebab-case slug
 * is canonical; the snake_case family key is tolerated so older links keep working. The mapping
 * `:checkKey` ↔ family key ↔ checker id `infra.<family_key>` is 1:1:1 and lives ONLY here.
 */
export function familyForCheckKey(checkKey: string): DnsFamilyDef | undefined {
	return DNS_FAMILIES.find((f) => f.slug === checkKey || f.key === checkKey);
}

/** Ordered (family, prefix) pairs — most specific prefix first so overlaps resolve correctly. */
const PREFIX_ORDER: { prefix: string; key: DnsFamilyKey }[] =
	DNS_FAMILIES.flatMap((f) =>
		f.prefixes.map((prefix) => ({ prefix, key: f.key })),
	).sort((a, b) => b.prefix.length - a.prefix.length);

/** Which family an `infra.*` finding id belongs to; null for non-infra ids. */
export function familyOf(findingId: string): DnsFamilyKey | null {
	if (!findingId.startsWith("infra.")) return null;
	const id = findingId.slice("infra.".length);
	for (const { prefix, key } of PREFIX_ORDER)
		if (id.startsWith(prefix)) return key;
	return null;
}

/** All findings from the latest run that belong to the DNS & Infrastructure category. */
export function infraFindings(findings: Finding[] | undefined): Finding[] {
	return (findings ?? []).filter((f) => f.checkId.split(".")[0] === "infra");
}

const WORST: Record<Severity, number> = {
	ok: 0,
	info: 1,
	warning: 2,
	critical: 3,
};

export interface FamilyRollup {
	def: DnsFamilyDef;
	findings: Finding[];
	/** Worst severity in the family; null when the family produced no findings this run. */
	worst: Severity | null;
	failCount: number;
}

/** Group the category's findings into the ten families, preserving spec order. */
export function rollupFamilies(findings: Finding[]): FamilyRollup[] {
	const byFamily = new Map<DnsFamilyKey, Finding[]>();
	for (const f of findings) {
		const key = familyOf(f.id);
		if (!key) continue;
		const list = byFamily.get(key) ?? [];
		list.push(f);
		byFamily.set(key, list);
	}
	return DNS_FAMILIES.map((def) => {
		const fam = byFamily.get(def.key) ?? [];
		let worst: Severity | null = null;
		for (const f of fam)
			if (worst === null || WORST[f.severity] > WORST[worst])
				worst = f.severity;
		return {
			def,
			findings: fam,
			worst,
			failCount: fam.filter(
				(f) => f.severity === "warning" || f.severity === "critical",
			).length,
		};
	});
}
