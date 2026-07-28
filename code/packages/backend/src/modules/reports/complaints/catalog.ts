import type {
	ComplaintCode,
	ComplaintVerdict,
	FixRecord,
} from "./complaint.types";

/**
 * The static half of the complaint taxonomy (pm/Email_Complaints.mdx §7): for each code, its slug,
 * its title, its verdict, its baseline severity, and which fixes it maps to. The dynamic half — the
 * plain-English explanation with real volumes interpolated, and the severity escalations of §8.3 —
 * is computed in board.ts.
 *
 * Titles never open with jargon: "Mail signed with your provider's own key", not "DKIM alignment
 * failure (adkim=s)". The jargon belongs in the evidence table and the drill-down.
 */
export interface ComplaintDescriptor {
	code: ComplaintCode;
	key: string;
	title: string;
	verdict: ComplaintVerdict;
	severity: "ok" | "info" | "warning" | "critical";
	fixIds: string[];
}

export const COMPLAINT_CATALOG: Record<ComplaintCode, ComplaintDescriptor> = {
	C00: {
		code: "C00",
		key: "healthy_aligned",
		title: "Fully authenticated mail",
		verdict: "ok",
		severity: "ok",
		fixIds: [],
	},
	C01: {
		code: "C01",
		key: "spoof_rejected",
		title: "Spoofing, rejected",
		verdict: "ok",
		severity: "info",
		fixIds: [],
	},
	C02: {
		code: "C02",
		key: "esp_default_dkim_key",
		title: "Mail signed with your provider's own key",
		verdict: "problem",
		severity: "warning",
		fixIds: ["fix.custom_dkim"],
	},
	C03: {
		code: "C03",
		key: "unauthorized_sender",
		title: "Unrecognized sender, delivered anyway",
		verdict: "problem",
		severity: "critical",
		fixIds: ["fix.authorize_sender", "fix.policy_ramp"],
	},
	C04: {
		code: "C04",
		key: "dkim_permerror",
		title: "A signature names a key you do not publish",
		verdict: "problem",
		severity: "warning",
		fixIds: ["fix.publish_selector"],
	},
	C05: {
		code: "C05",
		key: "spf_only_stream",
		title: "Passing on SPF alone",
		verdict: "watch",
		severity: "info",
		fixIds: ["fix.custom_dkim"],
	},
	C06: {
		code: "C06",
		key: "dkim_only_stream",
		title: "Passing on DKIM alone",
		verdict: "watch",
		severity: "info",
		fixIds: ["fix.brand_return_path"],
	},
	C07: {
		code: "C07",
		key: "forwarded_arc_rescued",
		title: "Forwarded mail, rescued by ARC",
		verdict: "ok",
		severity: "info",
		fixIds: [],
	},
	C08: {
		code: "C08",
		key: "dkim_signature_broken",
		title: "A signature broke in transit",
		verdict: "watch",
		severity: "info",
		fixIds: ["fix.signature_survivability"],
	},
	C09: {
		code: "C09",
		key: "third_party_sender",
		title: "A third-party tool sending as you",
		verdict: "watch",
		severity: "info",
		fixIds: ["fix.authorize_sender"],
	},
	C10: {
		code: "C10",
		key: "receiver_enforced",
		title: "Your own mail was blocked",
		verdict: "problem",
		severity: "critical",
		fixIds: ["fix.authorize_sender"],
	},
	C11: {
		code: "C11",
		key: "policy_inconsistent",
		title: "Receivers disagree about your DMARC record",
		verdict: "problem",
		severity: "warning",
		fixIds: ["fix.single_dmarc_record"],
	},
	C12: {
		code: "C12",
		key: "sampled_out",
		title: "Your policy is only applied to part of your mail",
		verdict: "watch",
		severity: "info",
		fixIds: ["fix.policy_ramp"],
	},
	C13: {
		code: "C13",
		key: "reporter_silence",
		title: "A receiver stopped reporting",
		verdict: "watch",
		severity: "info",
		fixIds: ["fix.report_flow"],
	},
	C14: {
		code: "C14",
		key: "tls_transport",
		title: "Encryption on mail sent to you",
		verdict: "ok",
		severity: "ok",
		fixIds: ["fix.tls_transport"],
	},
	C15: {
		code: "C15",
		key: "report_undecodable",
		title: "A report arrived that we could not read",
		verdict: "problem",
		severity: "warning",
		fixIds: ["fix.ingest_error"],
	},
};

/** RFC 8460 `result-type` → the concrete repair (pm/Email_Complaints.mdx §11.6). */
export const TLS_RESULT_FIXES: Record<string, string> = {
	"starttls-not-supported": "Enable STARTTLS on every MX host.",
	"certificate-host-mismatch":
		"Reissue the MX certificate so its name matches the MX hostname.",
	"certificate-expired": "Renew the MX certificate and automate the renewal.",
	"certificate-not-trusted":
		"Install a certificate chain from a publicly trusted CA.",
	"validation-failure":
		"Install a certificate chain from a publicly trusted CA.",
	"tlsa-invalid": "Re-publish the TLSA record after the key roll.",
	"dnssec-invalid": "Repair the DNSSEC chain covering the TLSA record.",
	"sts-policy-fetch-error":
		"Make https://mta-sts.<domain>/.well-known/mta-sts.txt reachable over HTTPS.",
	"sts-policy-invalid":
		"Fix the MTA-STS policy file syntax and keep its mx: lines in sync with the real MX set.",
	"sts-webpki-invalid":
		"Fix the certificate on the mta-sts policy host so it validates publicly.",
};

/**
 * Reporters we expect to hear from once a domain sends any real volume (pm/Email_Complaints.mdx
 * §7 C13). Silence from one of these is itself a complaint — a broken `rua=` or a full report
 * mailbox looks exactly like "no problems" unless we say otherwise.
 */
export const EXPECTED_REPORTERS = [
	"google.com",
	"yahoo",
	"outlook.com",
	"mimecast",
];

/** A DKIM TXT record template for the Zone C copy-paste block. */
export function dkimRecordTemplate(
	domain: string,
	selector: string,
): FixRecord {
	return {
		name: `${selector}._domainkey.${domain}`,
		type: "TXT",
		value: 'v=DKIM1; k=rsa; p=<paste the public key from your provider console>',
		note: "Your provider generates the key — copy its exact value in place of the placeholder.",
	};
}
