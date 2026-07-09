import { arcCheck } from "./arc/arc.check";
import { bimiCheck } from "./bimi/bimi.check";
import { blacklistCheck } from "./blacklist/blacklist.check";
import { contentScoringCheck } from "./content-scoring/content-scoring.check";
import { daneTlsaCheck } from "./dane-tlsa/dane-tlsa.check";
import { dkimCheck } from "./dkim/dkim.check";
import { dkim2Check } from "./dkim2/dkim2.check";
import { dmarcCheck } from "./dmarc/dmarc.check";
import { dmarcbisCheck } from "./dmarcbis/dmarcbis.check";
import { dmarcReportsCheck } from "./dmarc-reports/dmarc-reports.check";
import { dnsHealthCheck } from "./dns-health/dns-health.check";
import { dnssecCheck } from "./dnssec/dnssec.check";
import { domainReputationCheck } from "./domain-reputation/domain-reputation.check";
import { inboxPlacementCheck } from "./inbox-placement/inbox-placement.check";
import { linkUrlReputationCheck } from "./link-url-reputation/link-url-reputation.check";
import { listUnsubscribeCheck } from "./list-unsubscribe/list-unsubscribe.check";
import { mtaStsCheck } from "./mta-sts/mta-sts.check";
import { mxRoutingCheck } from "./mx-routing/mx-routing.check";
import { reportEmailsCheck } from "./report-emails/report-emails.check";
import { reputationMetricsCheck } from "./reputation-metrics/reputation-metrics.check";
import { reverseDnsCheck } from "./reverse-dns/reverse-dns.check";
import { smtpSecurityCheck } from "./smtp-security/smtp-security.check";
import { spfCheck } from "./spf/spf.check";
import { tlsRptCheck } from "./tls-rpt/tls-rpt.check";
import { tlsTransportCheck } from "./tls-transport/tls-transport.check";
import type { Checker } from "./types";

/**
 * The checker registry. The audit runner iterates this list; adding a new deliverability check is
 * just implementing the `Checker` interface (one file under checks/) and adding it here.
 *
 * Grouped by the six dashboard categories (see pm/checks/overview.mdx): SPF, DKIM, DMARC (+ARC),
 * Blacklists, DNS & Infrastructure, and Spam & Content. Every check's `id` carries its category
 * prefix (e.g. "infra.*", "content.*") so findings roll up into the right dashboard cell.
 */
export const CHECKERS: Checker[] = [
	// SPF
	spfCheck,
	// DKIM (+ DKIM2 companion — the draft-04 signature chain of custody, pm/checks/dkim2.mdx)
	dkimCheck,
	dkim2Check,
	// DMARC (+ ARC companion + DMARCbis conformance companion + ingested rua-report findings)
	dmarcCheck,
	dmarcReportsCheck,
	arcCheck,
	// DMARCbis — the RFC 9989 standards-conformance / tree-walk lens (pm/checks/dmarcbis.mdx)
	dmarcbisCheck,
	// Blacklists
	blacklistCheck,
	// DNS & Infrastructure
	mxRoutingCheck,
	reverseDnsCheck,
	tlsTransportCheck,
	mtaStsCheck,
	tlsRptCheck,
	daneTlsaCheck,
	dnssecCheck,
	dnsHealthCheck,
	domainReputationCheck,
	smtpSecurityCheck,
	// Spam & Content
	bimiCheck,
	contentScoringCheck,
	// Family #7 — the run-time report-email corpus scan (pm/emails.mdx §13): runs BEFORE
	// dmarc.reports / infra.tls_rpt (run-graph.ts) so their §5 findings read a fresh store.
	reportEmailsCheck,
	listUnsubscribeCheck,
	linkUrlReputationCheck,
	reputationMetricsCheck,
	inboxPlacementCheck,
];

export type {
	AuditResult,
	CheckContext,
	Checker,
	Finding,
	Severity,
} from "./types";
