import { arcCheck } from "./arc.check"
import { bimiCheck } from "./bimi.check"
import { blacklistCheck } from "./blacklist.check"
import { contentScoringCheck } from "./content-scoring.check"
import { daneTlsaCheck } from "./dane-tlsa.check"
import { dkimCheck } from "./dkim.check"
import { dmarcCheck } from "./dmarc.check"
import { dnsHealthCheck } from "./dns-health.check"
import { dnssecCheck } from "./dnssec.check"
import { domainReputationCheck } from "./domain-reputation.check"
import { inboxPlacementCheck } from "./inbox-placement.check"
import { linkUrlReputationCheck } from "./link-url-reputation.check"
import { listUnsubscribeCheck } from "./list-unsubscribe.check"
import { mtaStsCheck } from "./mta-sts.check"
import { mxRoutingCheck } from "./mx-routing.check"
import { reputationMetricsCheck } from "./reputation-metrics.check"
import { reverseDnsCheck } from "./reverse-dns.check"
import { smtpSecurityCheck } from "./smtp-security.check"
import { spfCheck } from "./spf.check"
import { tlsRptCheck } from "./tls-rpt.check"
import { tlsTransportCheck } from "./tls-transport.check"
import type { Checker } from "./types"

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
  // DKIM
  dkimCheck,
  // DMARC (+ ARC companion)
  dmarcCheck,
  arcCheck,
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
  listUnsubscribeCheck,
  linkUrlReputationCheck,
  reputationMetricsCheck,
  inboxPlacementCheck,
]

export type { AuditResult, CheckContext, Checker, Finding, Severity } from "./types"
