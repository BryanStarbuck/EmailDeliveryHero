import { createHash } from "node:crypto";
import { request as httpsRequest } from "node:https";
import { checkServerIdentity, type TLSSocket } from "node:tls";
import { withResource } from "@shared/concurrency";
import { readAppConfig } from "@shared/config-store";
import { resolveMx, resolveTxt } from "../dns-util";
import type { CheckContext, Checker, CheckOutcome, Finding } from "../types";

/**
 * MTA-STS (SMTP MTA Strict Transport Security, RFC 8461 — pm/checks/mta_sts.mdx). MTA-STS has two
 * moving parts on different transports, and per the spec we split them:
 *
 *  1. A DNS TXT record at `_mta-sts.<domain>` (`v=STSv1; id=<version>`) — pure DNS, FIRST-ROUND:
 *     infra.mta_sts_txt, infra.mta_sts_version, infra.mta_sts_txt_single, infra.mta_sts_id_format,
 *     infra.mta_sts_vs_tlsrpt. These always run.
 *  2. An HTTPS policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt` — the served-policy
 *     sub-checks (infra.mta_sts_policy / _https_cert / _policy_version / _mode / _mx_present /
 *     _mx_match / _max_age / _id_freshness / _txt_policy_consistency / _https_redirect /
 *     _content_type) run only when the global `checks.mtaSts.httpsProbeEnabled` feature flag
 *     (spec key `mtaSts.httpsProbe.enabled`, §4 "Admin-only settings") is ON and a TXT record is
 *     present (a sender never fetches a policy the TXT does not advertise, §6). With the flag OFF
 *     they are simply absent — never reported as failing (spec §8 AC 8) — with one collapsed
 *     `info` "pending" note.
 *
 * The structured observation (spec §5 `mta_sts_check_results` — today the `checkResults.mta_sts`
 * object embedded in the audit JSON) is returned as this checker's `results` payload and lands at
 * `AuditResult.results["infra.mta_sts"]`, one per (run, domain). The `id_freshness` diff reads the
 * previous audit's payload from `ctx.previousResults`.
 */

const CHECK_ID = "infra.mta_sts";

/** id token: 1–32 printable ASCII, alphanumeric (RFC 8461 §3.1 style, monotonic-friendly). */
const ID_RE = /^[A-Za-z0-9]{1,32}$/;

/** max_age sanity bounds (spec §2 / AC 12): warn when missing, < 1 day, or > ~1 year. */
const MAX_AGE_MIN = 86_400;
const MAX_AGE_MAX = 31_557_600;
/** Recommended cache duration (one week) used in remediation strings. */
const MAX_AGE_RECOMMENDED = 604_800;

/** Defensive HTTPS-fetch defaults (spec §3/§6) when the config block is absent. */
const DEFAULT_FETCH_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BODY_BYTES = 65_536;

/**
 * The structured, parsed MTA-STS observation for one domain in one audit run — the JSON-file
 * projection of the spec §5 `mta_sts_check_results` row (`checkResults.mta_sts`, camelCase exactly
 * as the spec's JSON example). When storage graduates to Postgres this object becomes one row
 * keyed by (audit_run_id, domain_id) — a store-only change, no checker changes.
 */
export interface MtaStsResults {
	/** TXT part (first-round, pure DNS). */
	txtPresent: boolean;
	/** Concatenated `_mta-sts` TXT value as observed (the primary record). */
	txtRaw: string | null;
	/** Parsed id= token. */
	txtId: string | null;
	/** Parsed v= token (expect "STSv1"). */
	txtVersion: string | null;
	/** Number of STSv1 TXT records found (duplicate detection). */
	txtCount: number;
	/** HTTPS policy part (probe round, gated on checks.mtaSts.httpsProbeEnabled). */
	policyFetched: boolean;
	/** HTTP status of the policy fetch (200, 404, ...); null when no response was received. */
	policyStatus: number | null;
	/** Raw policy body (capped at the configured max body size). */
	policyRaw: string | null;
	/** sha256 of the normalized policy body (powers the id_freshness cross-run diff). */
	policyHash: string | null;
	/** Parsed `mode:` when valid — 'enforce' | 'testing' | 'none'. */
	mode: "enforce" | "testing" | "none" | null;
	/** Parsed max_age seconds (null when missing/non-numeric). */
	maxAge: number | null;
	/** The `mx:` patterns from the policy. */
	policyMx: string[];
	/** The resolved live MX hosts at audit time. */
	liveMx: string[];
	/** True when every live MX matched a policy pattern; null until both sides are known. */
	mxMatch: boolean | null;
	/** The policy host presented a valid, name-matching cert; null when no TLS handshake happened. */
	httpsCertOk: boolean | null;
	/** The policy fetch hit a (forbidden) redirect; null when no HTTP response was received. */
	redirected: boolean | null;
	checkedAt: string;
}

interface ParsedTxt {
	raw: string;
	tags: string[];
	map: Record<string, string>;
	firstKey: string;
	versionOk: boolean;
	id: string | undefined;
}

/** Parse a `;`-separated MTA-STS tag list into a first-tag-aware map. */
function parseStsTxt(raw: string): ParsedTxt {
	const tags = raw
		.split(";")
		.map((t) => t.trim())
		.filter(Boolean);
	const map: Record<string, string> = {};
	for (const tag of tags) {
		const eq = tag.indexOf("=");
		if (eq === -1) continue;
		const key = tag.slice(0, eq).trim().toLowerCase();
		const value = tag.slice(eq + 1).trim();
		if (!(key in map)) map[key] = value;
	}
	const firstEq = tags.length > 0 ? tags[0].indexOf("=") : -1;
	const firstKey =
		firstEq > -1 ? tags[0].slice(0, firstEq).trim().toLowerCase() : "";
	const versionOk = firstKey === "v" && (map.v ?? "").toLowerCase() === "stsv1";
	return { raw, tags, map, firstKey, versionOk, id: map.id };
}

/** The parsed key/value policy body (spec §3 future path, step 3). */
interface ParsedPolicy {
	/** Every parsed key, in order (first-line/version ordering check). */
	keys: string[];
	version: string | null;
	/** True when `version` is the FIRST key in the body (spec: first policy line). */
	versionFirst: boolean;
	modeRaw: string | null;
	maxAgeRaw: string | null;
	mx: string[];
}

/** Parse the policy body line-by-line: `key: value`, blank lines ignored, repeated `mx` collected. */
function parsePolicy(body: string): ParsedPolicy {
	const keys: string[] = [];
	let version: string | null = null;
	let modeRaw: string | null = null;
	let maxAgeRaw: string | null = null;
	const mx: string[] = [];
	for (const line of body.split(/\r?\n/)) {
		if (line.trim() === "") continue;
		const m = /^([A-Za-z0-9_]+)\s*:\s*(.*)$/.exec(line.trim());
		if (!m) continue;
		const key = m[1].toLowerCase();
		const value = m[2].trim();
		keys.push(key);
		if (key === "version" && version === null) version = value;
		else if (key === "mode" && modeRaw === null) modeRaw = value;
		else if (key === "max_age" && maxAgeRaw === null) maxAgeRaw = value;
		else if (key === "mx" && value !== "") mx.push(value);
	}
	return {
		keys,
		version,
		versionFirst: keys[0] === "version",
		modeRaw,
		maxAgeRaw,
		mx,
	};
}

/** Normalize a hostname/pattern for comparison: lowercase, strip the trailing root dot. */
function normalizeHost(host: string): string {
	return host.trim().toLowerCase().replace(/\.$/, "");
}

/**
 * RFC 8461 §4.1 MX matching: a `*.` pattern matches EXACTLY ONE label to the left
 * (`*.example.com` matches `a.example.com` but not `a.b.example.com`); anything else must match
 * the MX host exactly.
 */
export function mxPatternMatches(pattern: string, host: string): boolean {
	const p = normalizeHost(pattern);
	const h = normalizeHost(host);
	if (p.startsWith("*.")) {
		const suffix = p.slice(1); // ".example.com"
		if (!h.endsWith(suffix)) return false;
		const left = h.slice(0, h.length - suffix.length);
		return left.length > 0 && !left.includes(".");
	}
	return p === h;
}

/** sha256 of the normalized (CRLF→LF, trimmed) policy body — the id_freshness pair (spec §5). */
function policyBodyHash(body: string): string {
	return createHash("sha256")
		.update(body.replace(/\r\n/g, "\n").trim())
		.digest("hex");
}

/** What one defensive policy fetch observed (spec §3 future path, steps 1–2). */
interface PolicyFetchOutcome {
	/** An HTTP response was received (any status). */
	ok: boolean;
	status: number | null;
	body: string | null;
	contentType: string | null;
	/** Chain + expiry + name-match verdict; null when no TLS handshake completed. */
	certOk: boolean | null;
	/** Why the certificate failed (authorization error / name mismatch). */
	certDetail: string | null;
	/** Transport-level failure (timeout, refused, DNS) — reported as a finding, never a crash. */
	error: string | null;
	/** The body hit the max-size cap and was truncated. */
	truncated: boolean;
}

/**
 * One conservative HTTPS GET of `https://mta-sts.<domain>/.well-known/mta-sts.txt` (spec §3):
 * SNI = the policy host, NO redirect following (a 3xx is returned as-is and judged by
 * `infra.mta_sts_https_redirect`), a hard total timeout, and a capped body. The TLS handshake is
 * allowed to complete even with an invalid certificate (`rejectUnauthorized: false`) so the cert
 * verdict is OUR finding (`infra.mta_sts_https_cert`) rather than an opaque fetch failure — the
 * chain/expiry verdict comes from `socket.authorized`, the name match from `checkServerIdentity`.
 */
function fetchPolicy(
	host: string,
	timeoutMs: number,
	maxBodyBytes: number,
	signal?: AbortSignal,
): Promise<PolicyFetchOutcome> {
	return new Promise((resolve) => {
		let settled = false;
		const done = (outcome: PolicyFetchOutcome): void => {
			if (settled) return;
			settled = true;
			clearTimeout(hardTimer);
			resolve(outcome);
		};
		const req = httpsRequest(
			{
				host,
				servername: host,
				port: 443,
				path: "/.well-known/mta-sts.txt",
				method: "GET",
				// The cert verdict is a finding, not a fetch failure (infra.mta_sts_https_cert).
				rejectUnauthorized: false,
				timeout: timeoutMs,
				...(signal ? { signal } : {}),
				headers: {
					host,
					accept: "text/plain",
					"user-agent": "EmailDeliveryHero-audit/1.0",
				},
			},
			(res) => {
				const socket = res.socket as TLSSocket;
				const cert = socket.getPeerCertificate?.();
				const hasCert = Boolean(cert && Object.keys(cert).length > 0);
				const nameErr = hasCert
					? checkServerIdentity(host, cert)
					: new Error("no peer certificate");
				const certOk = socket.authorized === true && !nameErr;
				const certDetail = certOk
					? null
					: socket.authorized !== true
						? String(
								socket.authorizationError ?? "certificate chain not trusted",
							)
						: (nameErr?.message ?? "hostname mismatch");
				const chunks: Buffer[] = [];
				let size = 0;
				let truncated = false;
				res.on("data", (chunk: Buffer) => {
					if (size + chunk.length > maxBodyBytes) {
						truncated = true;
						chunks.push(chunk.subarray(0, maxBodyBytes - size));
						size = maxBodyBytes;
						res.destroy(); // body cap (spec §3): stop reading past the limit
					} else {
						chunks.push(chunk);
						size += chunk.length;
					}
				});
				const finish = (): void =>
					done({
						ok: true,
						status: res.statusCode ?? null,
						body: Buffer.concat(chunks).toString("utf8"),
						contentType:
							typeof res.headers["content-type"] === "string"
								? res.headers["content-type"]
								: null,
						certOk,
						certDetail,
						error: null,
						truncated,
					});
				res.on("end", finish);
				res.on("close", finish);
				res.on("error", finish);
			},
		);
		// Hard total-time budget on top of the socket-inactivity timeout.
		const hardTimer = setTimeout(
			() => req.destroy(new Error("timeout")),
			timeoutMs,
		);
		hardTimer.unref?.();
		req.on("timeout", () => req.destroy(new Error("timeout")));
		req.on("error", (err) =>
			done({
				ok: false,
				status: null,
				body: null,
				contentType: null,
				certOk: null,
				certDetail: null,
				error: err instanceof Error ? err.message : String(err),
				truncated: false,
			}),
		);
		req.end();
	});
}

/** The example policy served as remediation copy for the policy-file findings. */
function examplePolicy(domain: string): string {
	return `version: STSv1\nmode: enforce\nmx: mail.${domain}\nmax_age: ${MAX_AGE_RECOMMENDED}`;
}

export const mtaStsCheck: Checker = {
	id: CHECK_ID,
	label: "MTA-STS",
	async run(ctx: CheckContext): Promise<CheckOutcome> {
		const findings: Finding[] = [];
		// One structured observation per (run, domain) — persisted even when the feature is absent
		// (spec §8 AC 14: exactly one checkResults.mta_sts object per audit).
		const results: MtaStsResults = {
			txtPresent: false,
			txtRaw: null,
			txtId: null,
			txtVersion: null,
			txtCount: 0,
			policyFetched: false,
			policyStatus: null,
			policyRaw: null,
			policyHash: null,
			mode: null,
			maxAge: null,
			policyMx: [],
			liveMx: [],
			mxMatch: null,
			httpsCertOk: null,
			redirected: null,
			checkedAt: new Date().toISOString(),
		};

		const txtName = `_mta-sts.${ctx.domain}`;
		const policyHost = `mta-sts.${ctx.domain}`;
		const policyUrl = `https://${policyHost}/.well-known/mta-sts.txt`;

		// resolveTxt concatenates each record's 255-byte character-string chunks into one string
		// (spec §3 step 1 / AC 5) and maps ENODATA/ENOTFOUND to a clean "no record" (AC 7).
		const txt = await resolveTxt(txtName);

		// Transient DNS failure (SERVFAIL / timeout) — retry later, never a false problem.
		if (txt.error) {
			findings.push({
				id: "infra.mta_sts_txt",
				checkId: CHECK_ID,
				title: "Could not look up MTA-STS TXT",
				severity: "info",
				detail: `DNS lookup for TXT ${txtName} failed transiently (${txt.error}). MTA-STS status is unknown this run.`,
				remediation: `Retry the audit. If it persists, verify the authoritative nameservers for ${ctx.domain} are responding.`,
			});
			return { findings, results };
		}

		// Candidate MTA-STS records: anything that looks like a v=STS* tag set (catches STSv1 and typos).
		const candidates = txt.records.filter((r) => /v=sts/i.test(r));
		if (candidates.length === 0) {
			// Feature absent — a SINGLE info, never warning/critical (spec §3 severity mapping, AC 2).
			// Per the roll-up rule this must NOT turn the DNS & Infrastructure cell amber on its own.
			findings.push({
				id: "infra.mta_sts_txt",
				checkId: CHECK_ID,
				title: "No MTA-STS policy published",
				severity: "info",
				detail: `${ctx.domain} has no _mta-sts TXT record. MTA-STS is optional but recommended: it tells sending servers to always use TLS to your MX hosts and forbids downgrade attacks.`,
				remediation: `Publish a TXT record at ${txtName}: "v=STSv1; id=20260701000000" and serve the matching policy at ${policyUrl}`,
			});
			return { findings, results };
		}

		const parsed = candidates.map(parseStsTxt);
		const stsv1 = parsed.filter((p) => p.versionOk);
		// Inspect a primary record: prefer a correctly-versioned one, else the first candidate.
		const primary = stsv1[0] ?? parsed[0];
		const id = primary.id;
		results.txtPresent = true;
		results.txtRaw = primary.raw;
		results.txtId = id ?? null;
		results.txtVersion = primary.map.v ?? null;
		results.txtCount = stsv1.length;

		// --- infra.mta_sts_txt_single: exactly one STSv1 record (duplicates are undefined) ---
		if (stsv1.length > 1) {
			findings.push({
				id: "infra.mta_sts_txt_single",
				checkId: CHECK_ID,
				title: "Multiple MTA-STS TXT records",
				severity: "warning",
				detail: `${txtName} publishes ${stsv1.length} STSv1 TXT records (${candidates.join(" | ")}); it is undefined which one a sender uses.`,
				remediation: `Remove the extra _mta-sts TXT record so exactly one "v=STSv1; id=..." remains.`,
			});
		} else {
			findings.push({
				id: "infra.mta_sts_txt_single",
				checkId: CHECK_ID,
				title: "Single MTA-STS TXT record",
				severity: "ok",
				detail: "Exactly one _mta-sts STSv1 TXT record is published.",
				evidence: primary.raw,
			});
		}

		// --- infra.mta_sts_version: first tag must be exactly v=STSv1 ---
		if (primary.versionOk) {
			findings.push({
				id: "infra.mta_sts_version",
				checkId: CHECK_ID,
				title: "MTA-STS version tag valid",
				severity: "ok",
				detail: 'The record begins with "v=STSv1".',
				evidence: primary.raw,
			});
		} else {
			findings.push({
				id: "infra.mta_sts_version",
				checkId: CHECK_ID,
				title: "MTA-STS version tag invalid",
				severity: "warning",
				detail: `The _mta-sts TXT must begin with the exact token "v=STSv1" as its first tag. Observed: "${primary.raw}".`,
				remediation: `Correct the record to begin with "v=STSv1;", e.g. "v=STSv1; id=20260701000000".`,
			});
		}

		// --- infra.mta_sts_id_format: id present and 1–32 alphanumeric ---
		if (id && ID_RE.test(id)) {
			findings.push({
				id: "infra.mta_sts_id_format",
				checkId: CHECK_ID,
				title: "MTA-STS id is valid",
				severity: "ok",
				detail: `Policy id "${id}" is a valid 1–32 char alphanumeric token.`,
				evidence: primary.raw,
			});
		} else {
			findings.push({
				id: "infra.mta_sts_id_format",
				checkId: CHECK_ID,
				title: id ? "MTA-STS id is malformed" : "MTA-STS id is missing",
				severity: "warning",
				detail: id
					? `Policy id "${id}" must match ^[A-Za-z0-9]{1,32}$ (1–32 alphanumeric chars); senders may ignore the policy. Observed: "${primary.raw}".`
					: `The _mta-sts TXT record has no id= tag, so senders cannot detect when the policy changes. Observed: "${primary.raw}".`,
				remediation: `Set id to a short alphanumeric version stamp, e.g. "v=STSv1; id=20260701120000".`,
			});
		}

		// --- infra.mta_sts_txt: overall roll-up of the TXT record ---
		const txtValid = primary.versionOk && !!id && ID_RE.test(id);
		if (txtValid) {
			findings.push({
				id: "infra.mta_sts_txt",
				checkId: CHECK_ID,
				title: "MTA-STS TXT record present",
				severity: "ok",
				detail: `Found a valid _mta-sts TXT record (id="${id}").`,
				evidence: primary.raw,
			});
		} else {
			findings.push({
				id: "infra.mta_sts_txt",
				checkId: CHECK_ID,
				title: "MTA-STS TXT record is malformed",
				severity: "warning",
				detail: `${txtName} has a record but it does not parse as a valid "v=STSv1; id=<token>". Observed: "${primary.raw}".`,
				remediation: `Publish exactly: "v=STSv1; id=20260701000000" at ${txtName}.`,
			});
		}

		// --- infra.mta_sts_vs_tlsrpt: cross-check that a TLS-RPT endpoint exists to receive failures ---
		const tlsrptName = `_smtp._tls.${ctx.domain}`;
		const tlsrpt = await resolveTxt(tlsrptName);
		if (tlsrpt.error) {
			findings.push({
				id: "infra.mta_sts_vs_tlsrpt",
				checkId: CHECK_ID,
				title: "Could not check TLS-RPT",
				severity: "info",
				detail: `DNS lookup for TXT ${tlsrptName} failed transiently (${tlsrpt.error}), so TLS-RPT presence is unknown this run.`,
				remediation: `Retry the audit to confirm a TLS-RPT record exists alongside MTA-STS.`,
			});
		} else if (tlsrpt.records.some((r) => /v=tlsrptv1/i.test(r))) {
			findings.push({
				id: "infra.mta_sts_vs_tlsrpt",
				checkId: CHECK_ID,
				title: "TLS-RPT reporting present",
				severity: "ok",
				detail:
					"A TLS-RPT record exists to receive MTA-STS/TLS failure reports.",
				evidence: tlsrptName,
			});
		} else {
			findings.push({
				id: "infra.mta_sts_vs_tlsrpt",
				checkId: CHECK_ID,
				title: "MTA-STS present but no TLS-RPT",
				severity: "info",
				detail: `${ctx.domain} publishes MTA-STS but has no _smtp._tls TLS-RPT record, so enforcement/TLS failures are reported to no one.`,
				remediation: `Publish ${tlsrptName} TXT "v=TLSRPTv1; rua=mailto:tlsrpt@${ctx.domain}".`,
			});
		}

		// ── HTTPS policy round — gated on the global feature flag (spec §4/§6, AC 8) ──────────────
		const cfg = readAppConfig().checks.mtaSts;
		const probeEnabled = cfg?.httpsProbeEnabled ?? false;
		if (!probeEnabled) {
			// Flag OFF: the served-policy sub-checks are simply absent — never reported as failing
			// (AC 8). One collapsed `info` note explains what is pending; its id is deliberately NOT a
			// real sub-check id so those stay genuinely absent.
			findings.push({
				id: "infra.mta_sts_policy_pending",
				checkId: CHECK_ID,
				title: "MTA-STS policy-file checks pending",
				severity: "info",
				detail: `A TXT record is published; the HTTPS policy at ${policyUrl} is not fetched because the MTA-STS HTTPS probe is disabled (Settings ▸ Admin). Once enabled it will verify the policy is served (HTTP 200, text/plain, no redirect), the certificate is valid for ${policyHost}, that mode/max_age are sane, that every live MX matches an mx: pattern, and that the id is bumped whenever the policy body changes.`,
				remediation: `Serve the policy at ${policyUrl} with a valid CA cert and "Content-Type: text/plain", e.g.:\n${examplePolicy(ctx.domain)}`,
			});
			return { findings, results };
		}

		// ONE defensive request per domain per audit (spec §3/§6): hard timeout, capped body, no
		// redirect following. A fetch error is a finding, never a crash. The fetch holds a slot of
		// the process-global `http` resource semaphore (pm/run_checks.mdx §3.1 — RDAP, MTA-STS/BIMI
		// policy fetches, unsubscribe probes) so 4+ parallel domains never fan out unbounded HTTPS.
		const timeoutMs = cfg?.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
		const maxBodyBytes = cfg?.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
		const fetched = await withResource("http", () =>
			fetchPolicy(policyHost, timeoutMs, maxBodyBytes, ctx.signal),
		);
		results.policyStatus = fetched.status;
		results.httpsCertOk = fetched.certOk;
		const redirected =
			fetched.status !== null && fetched.status >= 300 && fetched.status < 400;
		results.redirected = fetched.ok ? redirected : null;

		// --- infra.mta_sts_https_cert: chain/expiry/name verdict (when a TLS handshake completed) ---
		if (fetched.certOk === true) {
			findings.push({
				id: "infra.mta_sts_https_cert",
				checkId: CHECK_ID,
				title: "MTA-STS policy host certificate valid",
				severity: "ok",
				detail: `${policyHost} presented a valid, non-expired CA certificate whose name matches ${policyHost}.`,
				evidence: policyUrl,
			});
		} else if (fetched.certOk === false) {
			findings.push({
				id: "infra.mta_sts_https_cert",
				checkId: CHECK_ID,
				title: "MTA-STS policy host certificate invalid",
				severity: "critical",
				detail: `The certificate presented by ${policyHost} is not usable (${fetched.certDetail ?? "validation failed"}). Senders reject the policy over an invalid/expired/name-mismatched certificate, so MTA-STS gives zero protection while appearing configured.`,
				remediation: `Install a valid CA certificate for ${policyHost} (e.g. Let's Encrypt) whose SAN covers ${policyHost}; no wildcard-mismatch.`,
			});
		}

		// --- infra.mta_sts_https_redirect: RFC 8461 forbids following redirects for the policy ---
		if (fetched.ok && redirected) {
			findings.push({
				id: "infra.mta_sts_https_redirect",
				checkId: CHECK_ID,
				title: "MTA-STS policy path returns a redirect",
				severity: "warning",
				detail: `GET ${policyUrl} → HTTP ${fetched.status}. RFC 8461 forbids following redirects for the policy fetch, so senders will not follow it and the policy is unusable.`,
				remediation: `Serve the policy directly at ${policyUrl} with a 200 response — no HTTP→HTTPS or cross-host redirect.`,
			});
		} else if (fetched.ok && fetched.status === 200) {
			findings.push({
				id: "infra.mta_sts_https_redirect",
				checkId: CHECK_ID,
				title: "MTA-STS policy served without redirect",
				severity: "ok",
				detail: `GET ${policyUrl} answered 200 directly (no redirect).`,
				evidence: policyUrl,
			});
		}

		// --- Fetch failed / non-200: the advertised policy is unusable (spec §3 severity mapping) ---
		if (!fetched.ok || fetched.status !== 200 || fetched.body === null) {
			const observed = fetched.ok
				? `HTTP ${fetched.status ?? "?"}`
				: `fetch failed (${fetched.error ?? "unknown error"})`;
			findings.push({
				id: "infra.mta_sts_policy",
				checkId: CHECK_ID,
				title: "MTA-STS policy file not served",
				severity: "critical",
				detail: `_mta-sts TXT = "${primary.raw}" but ${policyUrl} → ${observed}. The advertised policy is unusable — senders ignore it, so the domain gets zero protection while appearing configured.`,
				remediation: `Serve the policy file at ${policyUrl} with "Content-Type: text/plain", e.g.:\n${examplePolicy(ctx.domain)}`,
			});
			findings.push({
				id: "infra.mta_sts_txt_policy_consistency",
				checkId: CHECK_ID,
				title: "MTA-STS TXT advertises a policy that is not served",
				severity: "critical",
				detail: `The _mta-sts TXT record (id="${id ?? "?"}") advertises a policy, but ${policyUrl} → ${observed}. TXT and policy must be published together.`,
				remediation: `Publish both parts together: keep the ${txtName} TXT and serve the matching policy at ${policyUrl}; never leave a TXT id pointing at a missing policy.`,
			});
			return { findings, results };
		}

		// --- 200 OK: parse the policy body ---
		const body = fetched.body;
		const policy = parsePolicy(body);
		const parses = policy.keys.length > 0;
		results.policyFetched = true;
		results.policyRaw = body;
		results.policyHash = policyBodyHash(body);
		results.policyMx = policy.mx.map(normalizeHost);
		const modeLower = policy.modeRaw?.toLowerCase() ?? null;
		const modeValid =
			modeLower === "enforce" ||
			modeLower === "testing" ||
			modeLower === "none";
		results.mode = modeValid
			? (modeLower as "enforce" | "testing" | "none")
			: null;
		const maxAge =
			policy.maxAgeRaw !== null && /^\d+$/.test(policy.maxAgeRaw)
				? Number(policy.maxAgeRaw)
				: null;
		results.maxAge = maxAge;

		// --- infra.mta_sts_policy: fetchable (HTTP 200) and parses ---
		if (parses) {
			findings.push({
				id: "infra.mta_sts_policy",
				checkId: CHECK_ID,
				title: "MTA-STS policy file served",
				severity: "ok",
				detail: `${policyUrl} answered 200 and the body parses as key/value policy lines${fetched.truncated ? ` (body truncated at ${maxBodyBytes} bytes)` : ""}.`,
				evidence: body.trim(),
			});
		} else {
			findings.push({
				id: "infra.mta_sts_policy",
				checkId: CHECK_ID,
				title: "MTA-STS policy file does not parse",
				severity: "critical",
				detail: `${policyUrl} answered 200 but the body contains no "key: value" policy lines, so senders cannot use it. Observed body: "${body.slice(0, 200)}".`,
				remediation: `Serve a plain-text policy at ${policyUrl}, e.g.:\n${examplePolicy(ctx.domain)}`,
			});
		}

		// --- infra.mta_sts_content_type: RFC 8461 recommends text/plain ---
		if (fetched.contentType && /^text\/plain\b/i.test(fetched.contentType)) {
			findings.push({
				id: "infra.mta_sts_content_type",
				checkId: CHECK_ID,
				title: "MTA-STS policy served as text/plain",
				severity: "ok",
				detail: `Content-Type: ${fetched.contentType}.`,
				evidence: fetched.contentType,
			});
		} else {
			findings.push({
				id: "infra.mta_sts_content_type",
				checkId: CHECK_ID,
				title: "MTA-STS policy content type is not text/plain",
				severity: "info",
				detail: `The policy is served with ${fetched.contentType ? `Content-Type: ${fetched.contentType}` : "no Content-Type header"}; RFC 8461 recommends text/plain.`,
				remediation: `Serve the policy file with "Content-Type: text/plain; charset=utf-8".`,
			});
		}

		// --- infra.mta_sts_policy_version: first line must be `version: STSv1` ---
		if (policy.version === "STSv1" && policy.versionFirst) {
			findings.push({
				id: "infra.mta_sts_policy_version",
				checkId: CHECK_ID,
				title: "MTA-STS policy version valid",
				severity: "ok",
				detail: 'The policy body begins with "version: STSv1".',
				evidence: "version: STSv1",
			});
		} else {
			findings.push({
				id: "infra.mta_sts_policy_version",
				checkId: CHECK_ID,
				title: "MTA-STS policy version line missing or incorrect",
				severity: "warning",
				detail: policy.version
					? `The policy declares "version: ${policy.version}"${policy.versionFirst ? "" : " and it is not the first line"} — expected "version: STSv1" as the first policy line.`
					: `The policy body has no "version:" line — expected "version: STSv1" as the first policy line.`,
				remediation: `Add "version: STSv1" as the first line of ${policyUrl}.`,
			});
		}

		// --- infra.mta_sts_mode: enforce / testing / none, compared against the desired target ---
		// Default target is `enforce` (spec §5); the admin-set `off` silences the comparison (§4).
		const desiredMode = ctx.mtaSts?.desiredMode ?? "enforce";
		if (!modeValid) {
			findings.push({
				id: "infra.mta_sts_mode",
				checkId: CHECK_ID,
				title: "MTA-STS policy mode missing or invalid",
				severity: "warning",
				detail: policy.modeRaw
					? `The policy declares "mode: ${policy.modeRaw}" — mode must be one of enforce / testing / none.`
					: `The policy has no "mode:" line — mode must be one of enforce / testing / none.`,
				remediation: `Set "mode: enforce" in ${policyUrl} (after validating in testing).`,
			});
		} else if (results.mode === "enforce") {
			findings.push({
				id: "infra.mta_sts_mode",
				checkId: CHECK_ID,
				title: "MTA-STS mode is enforce",
				severity: "ok",
				detail: `The policy enforces TLS delivery (mode: enforce${maxAge !== null ? `; max_age: ${maxAge}` : ""}${policy.mx.length > 0 ? `; mx: ${policy.mx.join(", ")}` : ""}).`,
				evidence: `mode: enforce`,
			});
		} else if (desiredMode === "off") {
			findings.push({
				id: "infra.mta_sts_mode",
				checkId: CHECK_ID,
				title: `MTA-STS mode is "${results.mode}"`,
				severity: "ok",
				detail: `The policy declares mode: ${results.mode}. The desired-mode comparison is turned off for this domain, so no enforcement target is applied.`,
				evidence: `mode: ${results.mode}`,
			});
		} else if (desiredMode === "testing" && results.mode === "testing") {
			findings.push({
				id: "infra.mta_sts_mode",
				checkId: CHECK_ID,
				title: "MTA-STS mode matches the configured target (testing)",
				severity: "ok",
				detail: `The policy declares mode: testing, which matches this domain's configured target. Move to enforce once TLS-RPT reports look clean.`,
				evidence: `mode: testing`,
			});
		} else {
			findings.push({
				id: "infra.mta_sts_mode",
				checkId: CHECK_ID,
				title: `MTA-STS mode is "${results.mode}"`,
				severity: "warning",
				detail: `The policy declares mode: ${results.mode}${maxAge !== null ? ` (max_age: ${maxAge}${policy.mx.length > 0 ? `; mx: ${policy.mx.join(", ")}` : ""})` : ""} while the desired mode is ${desiredMode}. Senders report but never enforce, so the domain gets no downgrade protection.`,
				remediation: `After validating in testing, change the policy at ${policyUrl} to "mode: enforce".`,
			});
		}

		// --- infra.mta_sts_mx_present: at least one mx: line ---
		if (policy.mx.length > 0) {
			findings.push({
				id: "infra.mta_sts_mx_present",
				checkId: CHECK_ID,
				title: "MTA-STS policy lists MX patterns",
				severity: "ok",
				detail: `The policy lists ${policy.mx.length} mx: pattern(s): ${policy.mx.join(", ")}.`,
				evidence: policy.mx.map((m) => `mx: ${m}`).join("\n"),
			});
		} else {
			findings.push({
				id: "infra.mta_sts_mx_present",
				checkId: CHECK_ID,
				title: "MTA-STS policy has no mx: lines",
				severity: "critical",
				detail: `The policy at ${policyUrl} contains zero mx: lines. In enforce mode this blocks ALL mail — no MX can ever match.`,
				remediation: `Add an "mx:" line per MX host, e.g. "mx: mail.${ctx.domain}".`,
			});
		}

		// --- infra.mta_sts_mx_match: every live MX matches a pattern, no pattern is dead ---
		// Reuse the MX list the run already resolved via infra.mx_routing when published upstream
		// (pm/run_checks.mdx Stage 1); otherwise resolve it here (deduped by the per-run DNS memo).
		const upstreamMx = ctx.upstream?.["infra.mx_routing"] as
			| { hosts?: { host: string; priority: number }[] }
			| undefined;
		let liveMx: string[];
		let liveMxKnown = true;
		if (upstreamMx?.hosts) {
			liveMx = upstreamMx.hosts.map((h) => normalizeHost(h.host));
		} else {
			const mx = await resolveMx(ctx.domain);
			if (mx.error) liveMxKnown = false;
			liveMx = mx.records
				.map((r) => normalizeHost(r.exchange))
				.filter((h) => h !== "" && h !== ".");
		}
		liveMx = [...new Set(liveMx)].filter((h) => h !== "" && h !== ".");
		results.liveMx = liveMx;

		if (policy.mx.length > 0 && liveMxKnown) {
			const patterns = [...new Set(policy.mx.map(normalizeHost))];
			const unmatchedLive = liveMx.filter(
				(h) => !patterns.some((p) => mxPatternMatches(p, h)),
			);
			const deadPatterns = patterns.filter(
				(p) => !liveMx.some((h) => mxPatternMatches(p, h)),
			);
			results.mxMatch = unmatchedLive.length === 0;
			if (unmatchedLive.length > 0) {
				findings.push({
					id: "infra.mta_sts_mx_match",
					checkId: CHECK_ID,
					title: "Live MX host not covered by the MTA-STS policy",
					severity: "critical",
					detail: `Live MX host(s) ${unmatchedLive.join(", ")} match no mx: pattern in the policy (patterns: ${patterns.join(", ")}). In mode: enforce, senders defer/bounce mail to any MX the policy does not list — this blocks legitimate mail after an MX migration.`,
					remediation: `Update the mx: lines in ${policyUrl} to cover every current MX host (${liveMx.join(", ")}), then bump the TXT id.`,
				});
			} else if (deadPatterns.length > 0) {
				findings.push({
					id: "infra.mta_sts_mx_match",
					checkId: CHECK_ID,
					title: "Stale mx: pattern in the MTA-STS policy",
					severity: "warning",
					detail: `Policy pattern(s) ${deadPatterns.join(", ")} match no live MX host (live MX: ${liveMx.length > 0 ? liveMx.join(", ") : "none"}). Stale entries suggest the policy was not updated after a mail-host change.`,
					remediation: `Remove the obsolete mx: pattern(s) from ${policyUrl} so only current MX hosts remain, then bump the TXT id.`,
				});
			} else {
				findings.push({
					id: "infra.mta_sts_mx_match",
					checkId: CHECK_ID,
					title: "MTA-STS mx: patterns cover the live MX set",
					severity: "ok",
					detail:
						liveMx.length > 0
							? `Every live MX host (${liveMx.join(", ")}) matches an mx: pattern, and no pattern is stale.`
							: "No live MX hosts were found to compare (the MX-routing check reports on that separately).",
					evidence: patterns.map((p) => `mx: ${p}`).join("\n"),
				});
			}
		}

		// --- infra.mta_sts_max_age: present, numeric, sane bounds (AC 12) ---
		if (maxAge !== null && maxAge >= MAX_AGE_MIN && maxAge <= MAX_AGE_MAX) {
			findings.push({
				id: "infra.mta_sts_max_age",
				checkId: CHECK_ID,
				title: "MTA-STS max_age is sane",
				severity: "ok",
				detail: `max_age: ${maxAge} seconds (~${Math.round(maxAge / 86_400)} day(s))${maxAge < MAX_AGE_RECOMMENDED ? ` — below the recommended ${MAX_AGE_RECOMMENDED} (one week) but within bounds` : ""}.`,
				evidence: `max_age: ${maxAge}`,
			});
		} else {
			const observed =
				policy.maxAgeRaw === null
					? "the policy has no max_age line"
					: maxAge === null
						? `max_age: ${policy.maxAgeRaw} is not numeric`
						: maxAge < MAX_AGE_MIN
							? `max_age: ${maxAge} is under one day — senders thrash refetching with no real caching`
							: `max_age: ${maxAge} exceeds ~one year — a bad policy would be pinned for far too long`;
			findings.push({
				id: "infra.mta_sts_max_age",
				checkId: CHECK_ID,
				title: "MTA-STS max_age missing or out of bounds",
				severity: "warning",
				detail: `${observed}. Recommended range: ${MAX_AGE_MIN}–${MAX_AGE_MAX} seconds (${MAX_AGE_RECOMMENDED} = one week is a good default).`,
				remediation: `Set "max_age: ${MAX_AGE_RECOMMENDED}" (one week) or higher, up to ~one year, in ${policyUrl}.`,
			});
		}

		// --- infra.mta_sts_id_freshness: the TXT id must change whenever the policy body changes ---
		// Cross-run memory (spec §3 step 5 / AC 13): diff the current (id, policyHash) pair against
		// the previous audit's stored pair from the store.
		const prev = ctx.previousResults?.[CHECK_ID] as
			| Partial<MtaStsResults>
			| undefined;
		if (prev?.policyHash && results.policyHash) {
			const bodyChanged = prev.policyHash !== results.policyHash;
			const idChanged = (prev.txtId ?? null) !== (results.txtId ?? null);
			if (bodyChanged && !idChanged) {
				findings.push({
					id: "infra.mta_sts_id_freshness",
					checkId: CHECK_ID,
					title: "MTA-STS policy changed but the TXT id did not",
					severity: "warning",
					detail: `The served policy body changed since the previous audit (hash ${prev.policyHash.slice(0, 12)}… → ${results.policyHash.slice(0, 12)}…) but the _mta-sts TXT id is still "${results.txtId ?? "?"}". Senders that cached the old policy will keep serving the stale copy until max_age expires.`,
					remediation: `Bump the _mta-sts TXT id every time you edit the policy file, e.g. "v=STSv1; id=${new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14)}".`,
				});
			} else {
				findings.push({
					id: "infra.mta_sts_id_freshness",
					checkId: CHECK_ID,
					title: "MTA-STS id tracks policy changes",
					severity: "ok",
					detail: bodyChanged
						? `The policy body changed and the TXT id was bumped ("${prev.txtId ?? "?"}" → "${results.txtId ?? "?"}") — senders will refetch.`
						: "The policy body is unchanged since the previous audit; the id does not need to change.",
					evidence: `id: ${results.txtId ?? "?"}`,
				});
			}
		}

		// --- infra.mta_sts_txt_policy_consistency: TXT and served policy are internally consistent ---
		if (parses && policy.version === "STSv1" && primary.versionOk) {
			findings.push({
				id: "infra.mta_sts_txt_policy_consistency",
				checkId: CHECK_ID,
				title: "MTA-STS TXT and policy are consistent",
				severity: "ok",
				detail: `The _mta-sts TXT (id="${id ?? "?"}") and the served STSv1 policy are published together and both parse.`,
				evidence: primary.raw,
			});
		} else {
			findings.push({
				id: "infra.mta_sts_txt_policy_consistency",
				checkId: CHECK_ID,
				title: "MTA-STS TXT and policy are inconsistent",
				severity: "critical",
				detail: `The _mta-sts TXT advertises a policy but the served document is not a usable STSv1 policy (${!parses ? "body does not parse" : policy.version !== "STSv1" ? `policy version is "${policy.version ?? "missing"}"` : "TXT record is not valid STSv1"}). Senders cannot use the pair, so the domain gets zero protection.`,
				remediation: `Publish both parts together: a "v=STSv1; id=..." TXT at ${txtName} and a matching "version: STSv1" policy at ${policyUrl}; never leave a TXT id pointing at a mismatched policy.`,
			});
		}

		return { findings, results };
	},
};
