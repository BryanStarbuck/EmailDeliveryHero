import type { AuditResult, DnssecResults, Severity } from "@/api/types";

/**
 * Cross-domain DNSSEC derivation (pm/checks/dnssec.mdx §19 / §21.3).
 *
 * The fleet view (/dnssec) and the RRSIG expiry radar (/dnssec/expiry) are pure roll-ups over the
 * newest run per domain — no new storage, no new checker work. This module owns the small amount of
 * shared logic: read `results["infra.dnssec"]`, fold the `infra.dnssec_*` findings into one worst
 * severity, normalise the snake/camel field variants, and compute days-to-expiry for the radar.
 */

export const SEV_RANK: Record<Severity, number> = {
	ok: 0,
	info: 1,
	warning: 2,
	critical: 3,
};

export const SEV_DOT: Record<Severity, string> = {
	critical: "bg-red-700",
	warning: "bg-amber-500",
	info: "bg-sky-600",
	ok: "bg-green-700",
};

export const SEV_BADGE: Record<Severity, string> = {
	critical: "bg-red-700 text-white",
	warning: "bg-amber-500 text-black",
	info: "bg-gray-200 text-gray-800",
	ok: "bg-green-700 text-white",
};

/** One domain's DNSSEC posture for the fleet/expiry boards. */
export interface DnssecFleetRow {
	domainId: string;
	domain: string;
	/** Worst severity across this run's `infra.dnssec_*` findings. */
	severity: Severity;
	signed: boolean;
	/** DS at the parent — null = the DS lookup itself could not resolve ("unknown", not "missing"). */
	dsPresent: boolean | null;
	/** AD=1 — null when the deep validation path did not run this scan. */
	validates: boolean | null;
	/** true only after the CD-flag disambiguation (a real broken chain). */
	bogus: boolean;
	algorithms: number[];
	/** Soonest apex RRSIG expiry, ISO — null when not captured (deep path off). */
	rrsigEarliestExpiry: string | null;
	/** Whole-number days until the soonest RRSIG expires; negative = already expired; null if unknown. */
	daysToExpiry: number | null;
	/** Newest run id (for deep-link scoping); may be undefined on very old runs. */
	runId?: string;
	/** true when there is a run but it carries no `infra.dnssec` snapshot (transient lookup failure). */
	unknown: boolean;
}

function worstDnssecSeverity(run: AuditResult): Severity {
	let worst: Severity = "ok";
	for (const f of run.findings ?? []) {
		if (!f.checkId?.startsWith("infra.dnssec")) continue;
		if (SEV_RANK[f.severity] > SEV_RANK[worst]) worst = f.severity;
	}
	return worst;
}

/** ms → whole days, floored toward the past so an expiry 12 h out reads "0 days" not "1". */
export function daysUntil(iso: string | null | undefined, now: number): number | null {
	if (!iso) return null;
	const t = Date.parse(iso);
	if (Number.isNaN(t)) return null;
	return Math.floor((t - now) / 86_400_000);
}

/**
 * Fold one domain's newest run into a fleet row. `now` is passed in (never read from the clock here)
 * so the caller controls it and the function stays pure/testable.
 */
export function toDnssecFleetRow(run: AuditResult, now: number): DnssecFleetRow {
	const d = run.results?.["infra.dnssec"] as DnssecResults | undefined;
	const rrsigExpiry = d?.rrsigEarliestExpiry ?? null;
	return {
		domainId: run.domainId,
		domain: run.domain,
		severity: worstDnssecSeverity(run),
		signed: d?.signed ?? false,
		dsPresent: d?.dsPresent ?? d?.ds_present ?? null,
		validates: d?.validates ?? null,
		bogus: d?.bogus ?? false,
		algorithms: d?.algorithms ?? [],
		rrsigEarliestExpiry: rrsigExpiry,
		daysToExpiry: daysUntil(rrsigExpiry, now),
		runId: run.runId,
		unknown: !d,
	};
}

/** IANA algorithm number → mnemonic, for compact display (pm/checks/dnssec.mdx §12.3). */
export function algName(n: number): string {
	switch (n) {
		case 5:
			return "RSASHA1";
		case 7:
			return "RSASHA1-NSEC3";
		case 8:
			return "RSASHA256";
		case 10:
			return "RSASHA512";
		case 13:
			return "ECDSAP256SHA256";
		case 14:
			return "ECDSAP384SHA384";
		case 15:
			return "ED25519";
		case 16:
			return "ED448";
		default:
			return `alg ${n}`;
	}
}

/** Deprecated signing algorithms (RSASHA1 family) — pm/checks/dnssec.mdx §16. */
export function isDeprecatedAlgo(n: number): boolean {
	return n === 5 || n === 7;
}

/**
 * Fleet sort order (pm/checks/dnssec.mdx §19.1): broken first, then near/expired, then unsigned,
 * then healthy. Within a bucket, sooner expiry first, then domain name.
 */
export function compareFleetRows(a: DnssecFleetRow, b: DnssecFleetRow): number {
	const sev = SEV_RANK[b.severity] - SEV_RANK[a.severity];
	if (sev !== 0) return sev;
	const ae = a.daysToExpiry ?? Number.POSITIVE_INFINITY;
	const be = b.daysToExpiry ?? Number.POSITIVE_INFINITY;
	if (ae !== be) return ae - be;
	return a.domain.localeCompare(b.domain);
}
