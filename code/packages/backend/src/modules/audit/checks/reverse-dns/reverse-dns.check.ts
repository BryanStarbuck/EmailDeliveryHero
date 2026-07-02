import { isIPv6 } from "node:net";
import {
	resolve4,
	resolve6,
	resolveCname,
	resolveMx,
	reverse,
	reverseIpv4,
} from "../dns-util";
import type { Checker, CheckOutcome, Finding } from "../types";

/**
 * Reverse DNS / PTR / FCrDNS. For every sending IP the domain claims, audits the reverse-lookup
 * posture receivers (Gmail, Yahoo, Microsoft, Proofpoint) use at SMTP connect time:
 *   - infra.ptr_present  — the IP has at least one PTR record            (critical when absent, v4)
 *   - infra.ptr_ipv6     — the IPv6 IP has a PTR under ip6.arpa          (critical when absent, v6)
 *   - infra.fcrdns       — the PTR host forward-resolves back to the IP  (critical on mismatch)
 *   - infra.ptr_single   — exactly one PTR (no multi-PTR ambiguity)      (warning when > 1)
 *   - infra.ptr_generic  — PTR is not an ISP/cloud auto-generated name   (warning on match)
 *   - infra.ptr_no_ip_literal — PTR does not re-encode the IP octets     (warning on match)
 *   - infra.ptr_tld_valid — PTR is a public FQDN, not .local/single-label(warning when invalid)
 *   - infra.ptr_matches_sender_domain — PTR under ctx.domain             (info, advisory)
 *   - infra.ptr_cname    — reverse name is CNAMEd (RFC 2317 delegation)  (info, advisory)
 *   - infra.helo_match   — HELO/EHLO matches PTR                         (future: needs SMTP probe)
 *
 * All lookups degrade gracefully: transient resolver failures (ESERVFAIL/timeout) become `info`
 * ("retry later"), distinct from a genuine ENOTFOUND/ENODATA (= no record). The authoritative party
 * for a reverse zone is the IP's network owner, so remediation names the provider control-panel
 * action, not a domain-owner DNS edit.
 */

const LOOKUP_TIMEOUT_MS = 5000;

/** Dynamic/residential PTR keyword tokens (matched as `.`/`-` delimited labels, case-insensitive). */
const GENERIC_KEYWORD_RE =
	/(^|[.-])(dhcp|dynamic|dyn|dsl|dialup|pppoe|ppp|cable|broadband|pool|residential|wireless|unassigned|client|customer|cust|user|res)([.-]|$)/i;
/** `host12`, `no-rdns`, and hex/random leftmost labels also read as auto-generated. */
const GENERIC_HOSTNUM_RE = /(^|[.-])(host\d+|no-rdns|unknown)([.-]|$)/i;
/** Known cloud/ISP default reverse-DNS suffixes — generic even though they forward-confirm. */
const CLOUD_DEFAULT_RES: RegExp[] = [
	/\.compute(-\d+)?\.amazonaws\.com$/i,
	/\.bc\.googleusercontent\.com$/i,
	/\.cloudapp\.azure\.com$/i,
	/\.vultr(usercontent)?\.com$/i,
	/\.(ip\.)?linode(usercontent)?\.com$/i,
	/\.members\.linode\.com$/i,
];
/** Reserved / non-public suffixes that are never valid reverse DNS on a mail IP. */
const INVALID_SUFFIXES = [
	".local",
	".lan",
	".internal",
	".home.arpa",
	".home",
	".corp",
	".localdomain",
];

/** Race a lookup against a short timeout so a lame reverse zone cannot hang the audit. */
function withTimeout<T extends { error?: string }>(
	p: Promise<T>,
	timeoutValue: T,
): Promise<T> {
	return Promise.race([
		p,
		new Promise<T>((r) => setTimeout(() => r(timeoutValue), LOOKUP_TIMEOUT_MS)),
	]);
}

const TIMED_OUT = { records: [] as string[], empty: false, error: "ETIMEOUT" };

/** Reverse-lookup with one jittered back-off retry before classifying a transient error. */
async function reverseWithRetry(ip: string) {
	let res = await withTimeout(reverse(ip), TIMED_OUT);
	if (res.error) {
		await new Promise((r) =>
			setTimeout(r, 120 + Math.floor(Math.random() * 180)),
		);
		res = await withTimeout(reverse(ip), TIMED_OUT);
	}
	return res;
}

/** Expand an IPv6 address to its full 8-group lowercase form for reliable equality tests. */
function expandIpv6(raw: string): string | null {
	const ip = raw.split("%")[0];
	if (!isIPv6(ip)) return null;
	const [headPart, tailPart] = ip.includes("::") ? ip.split("::") : [ip, null];
	const head = headPart ? headPart.split(":") : [];
	const tail = tailPart !== null && tailPart !== "" ? tailPart.split(":") : [];
	if (tailPart === null && head.length !== 8) return null;
	const missing = 8 - head.length - tail.length;
	if (missing < 0) return null;
	const groups = [
		...head,
		...new Array(tailPart === null ? 0 : missing).fill("0"),
		...tail,
	];
	return groups
		.map((g) => g.padStart(4, "0"))
		.join(":")
		.toLowerCase();
}

/** Canonicalize an IP so forward-resolve results and the configured IP compare exactly. */
function normIp(ip: string): string {
	const t = ip.trim();
	return isIPv6(t) ? (expandIpv6(t) ?? t.toLowerCase()) : t;
}

/** Build the dashed/dotted IPv4 octet variants that appear in generic PTR hostnames. */
function ipLiteralMatch(host: string, ip: string): string | null {
	const h = host.toLowerCase();
	if (isIPv6(ip)) {
		const groups = (expandIpv6(ip) ?? "")
			.split(":")
			.map((g) => g.replace(/^0+/, "") || "0");
		for (const sep of ["-", ".", ":"]) {
			const cand = groups.join(sep);
			if (cand.length > 3 && h.includes(cand)) return cand;
		}
		return null;
	}
	const octets = ip.split(".");
	if (octets.length !== 4) return null;
	for (const order of [octets, [...octets].reverse()]) {
		for (const sep of ["-", ".", "x"]) {
			const cand = order.join(sep);
			if (h.includes(cand)) return cand;
		}
	}
	return null;
}

/** Classify a PTR host against the generic/dynamic/cloud-default pattern set. */
function genericMatch(host: string, ip: string): string | null {
	const h = host.toLowerCase();
	const kw = GENERIC_KEYWORD_RE.exec(h) ?? GENERIC_HOSTNUM_RE.exec(h);
	if (kw) return kw[2];
	for (const re of CLOUD_DEFAULT_RES) if (re.test(h)) return re.source;
	const literal = ipLiteralMatch(h, ip);
	if (literal) return `embedded-ip:${literal}`;
	// long vowel-less leftmost label reads as a random/hex host.
	const first = h.split(".")[0] ?? "";
	if (
		first.length >= 12 &&
		!/[aeiou]/.test(first) &&
		/^[0-9a-f-]+$/.test(first)
	)
		return "random-label";
	return null;
}

/** Reject single-label, empty, or reserved-suffix PTR hosts. */
function invalidFqdnReason(host: string): string | null {
	const h = host.toLowerCase().replace(/\.$/, "");
	if (!h) return "empty hostname";
	if (!h.includes(".")) return "single-label name (no public TLD)";
	for (const suf of INVALID_SUFFIXES)
		if (h === suf.slice(1) || h.endsWith(suf)) return `reserved suffix ${suf}`;
	return null;
}

/** Registrable-domain (last two labels) comparison for sender-domain alignment. */
function sharesOrgDomain(host: string, domain: string): boolean {
	const norm = (s: string) => s.toLowerCase().replace(/\.$/, "");
	const h = norm(host);
	const d = norm(domain);
	if (h === d || h.endsWith(`.${d}`)) return true;
	const reg = (s: string) => s.split(".").slice(-2).join(".");
	return reg(h) !== "" && reg(h) === reg(d);
}

/**
 * One row of the structured snapshot persisted at results["infra.reverse_dns"]
 * (pm/checks/dns.mdx §5) — the PTR/FCrDNS map the DNS page's Mail path panel joins by IP.
 */
export interface ReverseDnsIpResult {
	ip: string;
	source: "mx" | "sending_ip";
	ptr: string | null;
	forward_confirmed: boolean;
	generic: boolean;
	/** Every PTR host returned for this IP (multi-PTR evidence) — pm/checks/reverse_dns.mdx §11. */
	ptrs: string[];
	/** Number of PTR records returned (drives the parsed-table row + trend marker). */
	ptr_count: number;
	/** Addresses the PTR host(s) forward-resolved to (raw panel / FCrDNS loop). */
	forward_ips: string[];
	/** Which §3 generic/dynamic pattern matched, for transparency; null when non-generic. */
	generic_pattern: string | null;
	/** Transient resolver error observed this run (ETIMEOUT | ESERVFAIL | …), else null. */
	error: string | null;
}

export interface ReverseDnsResults {
	ips: ReverseDnsIpResult[];
}

interface IpAudit {
	findings: Finding[];
	snap: ReverseDnsIpResult;
}

/** Audit one IP; returns its per-IP findings (ids suffixed with the IP so they stay unique). */
async function auditIp(
	ip: string,
	domain: string,
	source: "mx" | "sending_ip",
): Promise<IpAudit> {
	const findings: Finding[] = [];
	const snap: ReverseDnsIpResult = {
		ip,
		source,
		ptr: null,
		forward_confirmed: false,
		generic: false,
		ptrs: [],
		ptr_count: 0,
		forward_ips: [],
		generic_pattern: null,
		error: null,
	};
	const v6 = isIPv6(ip);
	const family = v6 ? "IPv6" : "IPv4";
	const mailHost = `mail1.${domain}`;
	const rev = await reverseWithRetry(ip);

	if (rev.error) {
		snap.error = rev.error;
		findings.push({
			id: `infra.ptr_transient.${ip}`,
			checkId: "infra",
			title: `Reverse lookup for ${ip} timed out`,
			severity: "info",
			detail: `The reverse (PTR) lookup for ${ip} failed transiently (${rev.error}) after one retry. Reverse zones are sometimes lame-delegated or slow; this is not a confirmed missing record.`,
			remediation:
				"Re-run the audit later. If it persists, verify the reverse zone's nameservers with your host/ISP.",
			evidence: rev.error,
		});
		return { findings, snap };
	}

	if (rev.empty || rev.records.length === 0) {
		findings.push(
			v6
				? {
						id: `infra.ptr_ipv6.${ip}`,
						checkId: "infra",
						title: `No ip6.arpa PTR for ${ip}`,
						severity: "critical",
						detail: `IPv6 ${ip} sends mail but has no PTR under ip6.arpa. Gmail/Yahoo require reverse DNS on the actual connecting IP, which may be IPv6, so receivers will reject or heavily filter this host.`,
						remediation: `Add an ip6.arpa PTR for ${ip} → ${mailHost} and publish ${mailHost}. AAAA ${ip}. Or disable IPv6 sending until reverse DNS is configured.`,
						evidence: `${family} ${ip}`,
					}
				: {
						id: `infra.ptr_present.${ip}`,
						checkId: "infra",
						title: `No PTR record for ${ip}`,
						severity: "critical",
						detail: `${ip} has no PTR record. Many receivers reject IPs with no reverse DNS at connect time (450/550 no reverse DNS), and the 2024 Gmail/Yahoo bulk-sender rules make a PTR a hard gate.`,
						remediation: `Ask your host/ISP to add a PTR for ${ip} → ${mailHost}. In AWS: Route 53 "Request reverse DNS" or the EC2 Elastic IP reverse DNS form. In a cPanel/WHM or provider panel: set rDNS = ${mailHost}.`,
						evidence: `${family} ${ip}`,
					},
		);
		return { findings, snap };
	}

	const hosts = rev.records;
	snap.ptr = hosts[0] ?? null;
	snap.ptrs = [...hosts];
	snap.ptr_count = hosts.length;
	let problem = false;

	if (hosts.length > 1) {
		problem = true;
		findings.push({
			id: `infra.ptr_single.${ip}`,
			checkId: "infra",
			title: `${ip} returns ${hosts.length} PTR records`,
			severity: "warning",
			detail: `${ip} returns ${hosts.length} PTR records (${hosts.join(", ")}). Receivers may pick either, and FCrDNS can fail on the wrong one.`,
			remediation: `Reduce to a single PTR = ${mailHost}. Remove stale reverse-zone entries at your provider.`,
			evidence: hosts.join(", "),
		});
	}

	// FCrDNS: pass if ANY returned PTR host forward-resolves back to this IP.
	const want = normIp(ip);
	let fcrdnsOk = false;
	let fcrdnsTransient = false;
	let fcrdnsError: string | null = null;
	const observed: string[] = [];
	for (const host of hosts) {
		const fwd = v6
			? await withTimeout(resolve6(host), TIMED_OUT)
			: await withTimeout(resolve4(host), TIMED_OUT);
		if (fwd.error) {
			fcrdnsTransient = true;
			fcrdnsError = fwd.error;
			continue;
		}
		const norm = fwd.records.map(normIp);
		observed.push(...fwd.records);
		if (norm.includes(want)) {
			fcrdnsOk = true;
			break;
		}
	}
	snap.forward_confirmed = fcrdnsOk;
	snap.forward_ips = [...new Set(observed)];

	if (!fcrdnsOk && fcrdnsTransient && observed.length === 0) {
		if (!snap.error) snap.error = fcrdnsError;
		findings.push({
			id: `infra.fcrdns_transient.${ip}`,
			checkId: "infra",
			title: `Could not forward-confirm PTR for ${ip}`,
			severity: "info",
			detail: `Forward resolution of the PTR host(s) for ${ip} failed transiently. FCrDNS could not be confirmed this run.`,
			remediation:
				"Re-run the audit later; if it persists, verify the forward A/AAAA zone with your DNS provider.",
			evidence: hosts.join(", "),
		});
		problem = true;
	} else if (!fcrdnsOk) {
		findings.push({
			id: `infra.fcrdns.${ip}`,
			checkId: "infra",
			title: `FCrDNS fails for ${ip}`,
			severity: "critical",
			detail: `PTR ${hosts[0]} does not forward-resolve back to ${ip} (got ${observed.length ? observed.join(", ") : "no A/AAAA records"}). Forward-Confirmed reverse DNS fails, causing deferrals and spam scoring.`,
			remediation: `Publish ${hosts[0]}. ${v6 ? "AAAA" : "A"} ${ip} so the PTR forward-confirms, or change the PTR to a hostname whose ${v6 ? "AAAA" : "A"} record already points to ${ip}. Ensure the record matches the PTR exactly.`,
			evidence: `PTR ${hosts[0]} → ${observed.join(", ") || "(none)"}`,
		});
		problem = true;
	}

	// Remaining name-quality checks use the first host (all are reported above).
	const host = hosts[0];

	const generic = genericMatch(host, ip);
	if (generic) {
		problem = true;
		snap.generic = true;
		snap.generic_pattern = generic;
		findings.push({
			id: `infra.ptr_generic.${ip}`,
			checkId: "infra",
			title: `Generic/dynamic PTR for ${ip}`,
			severity: "warning",
			detail: `PTR ${host} looks auto-generated (matched "${generic}"); it reads as a dynamic/residential or cloud-default host, a strong spam signal (SpamAssassin RDNS_DYNAMIC).`,
			remediation: `Replace the provider-default rDNS with a dedicated mail hostname, e.g. ${mailHost}, and publish the matching A/AAAA record. Never leave the ISP-generated PTR on a mail-sending IP.`,
			evidence: `${host} (pattern: ${generic})`,
		});
	}

	const literal = ipLiteralMatch(host, ip);
	if (literal) {
		problem = true;
		snap.generic = true;
		if (!snap.generic_pattern) snap.generic_pattern = `embedded-ip:${literal}`;
		findings.push({
			id: `infra.ptr_no_ip_literal.${ip}`,
			checkId: "infra",
			title: `PTR for ${ip} embeds the literal IP`,
			severity: "warning",
			detail: `PTR ${host} re-encodes the IP address ("${literal}") — the classic generic/dynamic naming pattern.`,
			remediation: `Replace with a semantic mail hostname (${mailHost}).`,
			evidence: host,
		});
	}

	const fqdnBad = invalidFqdnReason(host);
	if (fqdnBad) {
		problem = true;
		findings.push({
			id: `infra.ptr_tld_valid.${ip}`,
			checkId: "infra",
			title: `PTR for ${ip} is not a public FQDN`,
			severity: "warning",
			detail: `PTR ${host} is not a valid public FQDN (${fqdnBad}); receivers treat it as invalid reverse DNS.`,
			remediation: `Set the PTR to a fully-qualified public hostname, e.g. ${mailHost}, and ensure its zone is publicly resolvable.`,
			evidence: host,
		});
	}

	// Advisory: sender-domain alignment (info only, never turns the dashboard cell amber).
	if (!sharesOrgDomain(host, domain)) {
		findings.push({
			id: `infra.ptr_matches_sender_domain.${ip}`,
			checkId: "infra",
			title: `PTR for ${ip} is not under ${domain}`,
			severity: "info",
			detail: `PTR ${host} is valid but not under ${domain}; branding/alignment is weaker. This is acceptable when sending through an ESP whose pool it owns.`,
			remediation: `Optional: if you run your own IPs, name them under your domain (${mailHost}) for brand alignment. When using an ESP, the ESP-owned PTR is expected and fine.`,
			evidence: host,
		});
	}

	// Advisory: RFC 2317 classless reverse delegation (in-addr.arpa CNAME), IPv4 only.
	if (!v6) {
		const revName = reverseIpv4(ip);
		if (revName) {
			const cname = await withTimeout(
				resolveCname(`${revName}.in-addr.arpa`),
				TIMED_OUT,
			);
			if (!cname.error && cname.records.length > 0) {
				findings.push({
					id: `infra.ptr_cname.${ip}`,
					checkId: "infra",
					title: `Reverse name for ${ip} is CNAMEd (RFC 2317)`,
					severity: "info",
					detail: `The reverse name ${revName}.in-addr.arpa is a CNAME to ${cname.records.join(", ")} — a valid RFC 2317 /24 sub-delegation. Confirm the delegated PTR forward-confirms.`,
					remediation:
						"No action if the delegated PTR forward-confirms; otherwise fix the delegated PTR at the sub-delegated provider.",
					evidence: cname.records.join(", "),
				});
			}
		}
	}

	if (!problem) {
		findings.push({
			id: `infra.ptr_ok.${ip}`,
			checkId: "infra",
			title: `Reverse DNS clean for ${ip}`,
			severity: "ok",
			detail: `${ip} (${family}) has a single PTR ${host} that forward-confirms (FCrDNS) and is not generic.`,
			evidence: `${ip} → ${host}`,
		});
	}

	return { findings, snap };
}

/** Bounded-concurrency map (no p-limit dependency) preserving input order. */
async function mapPool<T, R>(
	items: T[],
	limit: number,
	fn: (t: T) => Promise<R>,
): Promise<R[]> {
	const out: R[] = new Array(items.length);
	let next = 0;
	const worker = async () => {
		while (true) {
			const idx = next++;
			if (idx >= items.length) break;
			out[idx] = await fn(items[idx]);
		}
	};
	const workers = new Array(Math.min(limit, items.length || 1))
		.fill(0)
		.map(worker);
	await Promise.all(workers);
	return out;
}

/** Resolve the domain's MX targets to their A/AAAA addresses (the spec's MX-IP fallback). */
async function mxIps(domain: string): Promise<string[]> {
	const mx = await resolveMx(domain);
	if (mx.error || mx.records.length === 0) return [];
	const hosts = [
		...new Set(
			mx.records
				.map((r) => r.exchange.trim().toLowerCase().replace(/\.$/, ""))
				.filter((h) => h !== "" && h !== "."),
		),
	];
	const out = new Set<string>();
	for (const host of hosts) {
		const [v4, v6] = await Promise.all([resolve4(host), resolve6(host)]);
		for (const ip of [...v4.records, ...v6.records]) out.add(ip);
	}
	return [...out];
}

export const reverseDnsCheck: Checker = {
	id: "infra.reverse_dns",
	label: "Reverse DNS / PTR",
	async run(ctx): Promise<CheckOutcome> {
		const findings: Finding[] = [];
		const snaps: ReverseDnsIpResult[] = [];

		// Configured sending IPs first; fall back to the MX hosts' addresses so the audit still
		// covers the inbound path (and the Gmail dual-stack trap) when none are configured
		// (pm/checks/dns.mdx §5 — snapshot rows carry source: mx | sending_ip).
		let ips = [
			...new Set(ctx.sendingIps.map((ip) => ip.trim()).filter(Boolean)),
		];
		let source: "mx" | "sending_ip" = "sending_ip";
		if (ips.length === 0) {
			ips = await mxIps(ctx.domain);
			source = "mx";
		}

		if (ips.length === 0) {
			findings.push({
				id: "infra.ptr_no_ips",
				checkId: "infra",
				title: "No sending IPs to audit",
				severity: "info",
				detail: `No sending IPs are recorded for ${ctx.domain} and its MX hosts resolve to no addresses, so reverse DNS (PTR/FCrDNS) could not be audited.`,
				remediation: `Add the IPs your mail actually sends from to ${ctx.domain} (or import from SPF ip4:/ip6: mechanisms or MX A/AAAA records) so reverse DNS can be verified.`,
			});
		} else {
			const perIp = await mapPool(ips, 8, (ip) =>
				auditIp(ip, ctx.domain, source),
			);
			for (const audit of perIp) {
				findings.push(...audit.findings);
				snaps.push(audit.snap);
			}
		}

		// infra.helo_match is FUTURE: it needs an outbound SMTP probe to read the HELO/EHLO string.
		// Emit exactly one non-actionable info finding; never warning/critical first-round.
		findings.push({
			id: "infra.helo_match.pending",
			checkId: "infra",
			title: "HELO/EHLO ↔ PTR match (pending SMTP probe)",
			severity: "info",
			detail:
				"The infra.helo_match sub-check verifies the sending MTA's SMTP HELO/EHLO FQDN matches its PTR and forward DNS. It requires an outbound SMTP probe (or MTA-log ingestion) that is not available in the first round.",
			remediation:
				"When the SMTP probe ships, configure the MTA HELO/EHLO to the FCrDNS-valid hostname (Postfix myhostname, exim primary_hostname). See ./smtp_security.mdx.",
		});

		return { findings, results: { ips: snaps } satisfies ReverseDnsResults };
	},
};
