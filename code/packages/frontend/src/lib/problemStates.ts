import type { ProblemStateId, Severity } from "@/api/types"

/**
 * The problem-state catalog — pm/checks/blacklists.mdx §16 (PS-0…PS-13). Each state's deep-dive
 * page (/blacklists/$domain/state/$psId) explains the concept, shows the diagnose-it-yourself
 * commands, names the tools, and lays out how to progress forward. Content is static; the page
 * injects the domain's live evidence next to it.
 */

export interface ProblemStateInfo {
  id: ProblemStateId
  name: string
  severity: Severity
  trigger: string
  /** The concept, explained to an anxious user in plain words. */
  concept: string
  /** Terminal commands the user can run to verify independently (brew: bind/dig etc.). */
  diagnose: string[]
  tools: string[]
  /** Further health metrics worth testing while in this state. */
  furtherHealth: string[]
  /** The ordered "progress forward" checklist. */
  progress: string[]
}

export const PROBLEM_STATES: Record<ProblemStateId, ProblemStateInfo> = {
  "PS-0": {
    id: "PS-0",
    name: "All clean",
    severity: "ok",
    trigger: "Every enabled zone queried, zero listings, no refusals.",
    concept:
      "The public-blocklist layer says receivers have no reputation-list reason to block you. Stay clean: keep reverse DNS valid, keep SPF/DKIM/DMARC green, and keep the scheduled re-check on so a new listing alerts you within hours.",
    diagnose: ["dig +short 2.0.0.127.zen.spamhaus.org   # liveness probe — expect 127.0.0.2"],
    tools: ["dig (brew: bind)", "the scheduled re-check"],
    furtherHealth: [
      "Enroll in Google Postmaster Tools and Microsoft SNDS so provider-side reputation is observable.",
      "Register at DNSWL (free) for a positive signal.",
    ],
    progress: [
      "Nothing to fix. Review the prevention checklist and keep the 6-hour cadence enabled.",
      "Mark the provider portals as verified once you have checked them.",
    ],
  },
  "PS-1": {
    id: "PS-1",
    name: "High-trust manual listing (SBL/CSS-class)",
    severity: "critical",
    trigger: "Spamhaus SBL/CSS or Barracuda lists a sending IP.",
    concept:
      "A human or high-confidence system decided traffic from this IP is a spam operation or persistent problem. This is not automated collateral — it will not expire quietly, and it devastates placement at major receivers.",
    diagnose: [
      "dig +short <reversed-ip>.zen.spamhaus.org      # expect 127.0.0.2/.3",
      "dig +short TXT <reversed-ip>.zen.spamhaus.org  # the SBL case URL",
      "whois <ip>                                     # netblock owner — is the whole range swept?",
    ],
    tools: ["dig (brew: bind)", "whois", "ipcalc", "check.spamhaus.org lookup"],
    furtherHealth: [
      "Volume/complaint history from ingested DMARC reports.",
      "Open-relay test on the MX (nmap --script smtp-open-relay).",
      "Outbound queue inspection for the flagged traffic.",
    ],
    progress: [
      "Identify and stop the cited operation — the TXT case link says what Spamhaus saw.",
      "Document the fix.",
      "Submit the SBL/Barracuda removal request with that documentation.",
      "Expect human review latency (SBL) or <24h (Barracuda); the scheduled run re-checks automatically.",
    ],
  },
  "PS-2": {
    id: "PS-2",
    name: "Compromised-host listing (XBL/DroneBL-class)",
    severity: "critical",
    trigger: "An exploit/botnet zone lists a sending IP.",
    concept:
      "The IP behaved like malware: botnet callbacks, proxy abuse, or exploit traffic. Something on (or NATed behind) this IP is infected or open. Delisting before cleaning guarantees re-listing.",
    diagnose: [
      "dig +short TXT <reversed-ip>.zen.spamhaus.org   # XBL TXT links detection detail (port, last-seen)",
      "lsof -i -nP | grep -E ':25|:1080|:6667'          # unexpected outbound SMTP/SOCKS/IRC on the host",
      "nmap -p25,465,587 --script smtp-open-relay <ip>  # open relay test",
    ],
    tools: ["dig", "nmap (dns-blacklist, smtp-open-relay scripts)", "host AV/EDR", "provider flow logs"],
    furtherHealth: [
      "Re-scan all exploit-class zones after cleanup.",
      "Watch z.mailspike.net (zero-hour) for recurrence.",
    ],
    progress: [
      "Find the infected machine or service using the TXT's port/timestamp hints.",
      "Clean, patch, and rotate credentials.",
      "Self-delist — XBL allows immediate self-removal once clean; DroneBL via its lookup page.",
      "If it recurs, assume re-infection, not a list error.",
    ],
  },
  "PS-3": {
    id: "PS-3",
    name: "Policy listing — dynamic/consumer IP space (PBL-class)",
    severity: "warning",
    trigger: "PBL or SpamRATS-Dyna say this IP should not send direct-to-MX mail.",
    concept:
      "Not an accusation of spam: the network's owner (or Spamhaus policy) declared this IP range shouldn't emit direct-to-MX mail — typical for home and cloud-dynamic IPs. Receivers reject on it because botnets live in such space.",
    diagnose: [
      "dig +short <reversed-ip>.pbl.spamhaus.org",
      "dig +short -x <ip>          # a generic PTR (ip-…provider.net) confirms policy space",
    ],
    tools: ["dig", "whois / mmdblookup (ASN owner)"],
    furtherHealth: ["The full reverse-DNS (FCrDNS) check.", "A swaks send test through the proper smarthost."],
    progress: [
      "Decide the fork: (a) if this IP shouldn't send mail, route outbound through your provider's smarthost or an ESP — the listing is then correct and harmless.",
      "(b) If this is a legitimate static MTA: get a proper PTR from the provider, then request PBL self-exclusion at check.spamhaus.org (ISP-maintained entries may also need the ISP's own form).",
    ],
  },
  "PS-4": {
    id: "PS-4",
    name: "Sending domain on a domain blocklist (DBL/SURBL/URIBL)",
    severity: "critical",
    trigger: "An RHSBL lists the domain itself.",
    concept:
      "The NAME, not the IP, is listed — every message carrying the domain in From/Return-Path/URLs is suspect no matter which IP sends it. Causes split into: the domain really spams/phishes, or 'abused-legit' (site hacked, open redirect, compromised shortener) — which has a different fix.",
    diagnose: [
      "dig +short <domain>.dbl.spamhaus.org      # 127.0.1.x category (never query an IP at DBL)",
      "dig +short TXT <domain>.dbl.spamhaus.org",
      "dnstwist --registered --format json <domain>   # lookalike confusion",
    ],
    tools: ["dig", "dnstwist", "SURBL/URIBL lookup pages", "Google Search Console (security tab)"],
    furtherHealth: [
      "Body-URL reputation sweep (are other domains you link also listed?).",
      "Check DKIM d= and Return-Path domains individually.",
    ],
    progress: [
      "Abused-legit codes: find and close the compromise (hacked CMS, open redirect), purge injected content, then delist with the fix described.",
      "Bad-domain codes on a domain you legitimately own: contest via the zone's flow with evidence.",
      "Re-audit and watch the domain-side zones for two weeks.",
    ],
  },
  "PS-5": {
    id: "PS-5",
    name: "Trap-driven auto-expiring listing (SCBL/PSBL/WPBL-class)",
    severity: "warning",
    trigger: "A spam-trap list hit; it expires on its own.",
    concept:
      "Mail from this IP hit a spam trap — an address that never opted in. Usually list-hygiene rot (purchased lists, ancient addresses, scraping) rather than infection. These lists forgive: they expire once the traffic stops (SpamCop ~24h, PSBL 2–4 weeks, WPBL ~10 days).",
    diagnose: [
      "dig +short <reversed-ip>.bl.spamcop.net",
      "# SpamCop's lookup page shows report ages — correlate with your send logs",
    ],
    tools: ["dig", "SpamCop bl.shtml lookup", "your ESP's suppression/bounce logs", "ingested DMARC reports"],
    furtherHealth: [
      "Bounce-rate trend and list-acquisition audit.",
      "Confirm no exploit-zone co-listing (trap + exploit together = infection, not hygiene).",
    ],
    progress: [
      "Identify the sending stream that hit the trap.",
      "Remove non-engaged/unverified addresses (or the whole acquired segment).",
      "Either wait out the expiry or self-delist (PSBL is instant).",
      "Recurrence means the hygiene fix didn't take.",
    ],
  },
  "PS-6": {
    id: "PS-6",
    name: "Collateral neighborhood/ASN listing",
    severity: "info",
    trigger: "UCEPROTECT L2/L3, SEM-netbl, or another range listing you didn't cause.",
    concept:
      "A range containing your IP — a /24, an allocation, or the whole ASN — got listed because of NEIGHBORS. You personally may be clean. Impact at major receivers is near zero (Gmail/Microsoft/Yahoo don't use UCEPROTECT L2/L3); small self-hosted receivers occasionally do.",
    diagnose: [
      "dig +short <reversed-ip>.dnsbl-2.uceprotect.net",
      "whois <ip>    # find OrgAbuseEmail — your provider's abuse desk",
    ],
    tools: ["dig", "whois", "ipcalc", "uceprotect.net rblcheck page"],
    furtherHealth: [
      "Confirm your own IP is clean at L1 and all HIGH-tier zones — if yes, this is pure collateral.",
      "Measure actual placement via bounce logs before acting.",
    ],
    progress: [
      "Verify you are clean everywhere that matters (the HIGH-tier matrix).",
      "Forward the evidence to your provider's abuse desk (the whois OrgAbuseEmail contact).",
      "Only if real placement suffers: plan an IP/provider move.",
      "NEVER pay the express-delist — see PS-13.",
    ],
  },
  "PS-7": {
    id: "PS-7",
    name: "rDNS/FCrDNS defect driving listings",
    severity: "warning",
    trigger: "Missing or generic PTR; SpamRATS NoPtr/Dyna and PBL-class listings follow from it.",
    concept:
      "The IP has no PTR, a generic PTR, or a PTR that doesn't confirm forward (FCrDNS). Many receivers reject on this directly, AND it triggers a family of policy listings — one DNS fix clears them all.",
    diagnose: [
      "dig +short -x <ip>                 # empty or 'dynamic-…'/'ip-…' pattern = defect",
      "dig +short A <ptr-value>           # forward-confirm: must include the IP",
      "swaks --server <mx> --quit-after EHLO   # the HELO/banner mismatch a receiver sees",
    ],
    tools: ["dig", "swaks", "your hosting provider's reverse-DNS console/ticket"],
    furtherHealth: ["The full reverse-DNS check.", "HELO-name alignment (SMTP security check)."],
    progress: [
      "Set the PTR to the mail host's FQDN (e.g. mail.example.com) via the IP's owner.",
      "Ensure that FQDN's A record points back at the IP (FCrDNS).",
      "Align the MTA's HELO to the same name.",
      "Then delist SpamRATS (removal requires the PTR already fixed) and PBL if applicable.",
    ],
  },
  "PS-8": {
    id: "PS-8",
    name: "Provider-side block, all public lists clean",
    severity: "warning",
    trigger: "Bounces from Gmail/Microsoft/Yahoo while every public zone is green.",
    concept:
      "The blocking list is PRIVATE — Gmail domain reputation, Microsoft's internal lists, Cloudmark/Proofpoint at carriers. Public-zone cleanliness is necessary but not sufficient. The bounce text (e.g. Microsoft 5.7.606, Gmail 550-5.7.1) names the right escalation channel.",
    diagnose: [
      "# Read the actual bounce (NDR) — the SMTP code maps to the provider and its delist path",
      "# Check postmaster.google.com reputation graphs and SNDS filter verdicts",
    ],
    tools: [
      "Google Postmaster Tools",
      "Microsoft SNDS + sender.office.com",
      "Yahoo Sender Hub",
      "csi.cloudmark.com / ipcheck.proofpoint.com",
    ],
    furtherHealth: [
      "Spam-rate vs Gmail's 0.1%/0.3% thresholds.",
      "DMARC alignment health (bulk-sender rules).",
      "List-Unsubscribe presence.",
    ],
    progress: [
      "Classify the bounce → provider.",
      "Use that provider's channel: sender.office.com for 5.7.606, SNDS for consumer Microsoft, the Gmail escalation form, the Cloudmark reset.",
      "Fix the reputation inputs the portal shows (complaints, volume spikes, auth).",
      "Mark the portal row Verified/Problem in the checklist so it's tracked.",
    ],
  },
  "PS-9": {
    id: "PS-9",
    name: "Queries refused / resolver blocked",
    severity: "info",
    trigger: "Spamhaus 127.255.255.x or URIBL_BLOCKED (127.0.0.1) seen.",
    concept:
      "This is about US, not your domain: the blocklists refused to answer our resolver. Public/open resolvers (8.8.8.8, 1.1.1.1) and heavy users get in-band error codes, not real answers. Results this run are partially blind; nothing here says your domain is unhealthy.",
    diagnose: [
      "dig +short 2.0.0.127.zen.spamhaus.org @8.8.8.8      # demonstrates the refusal code",
      "dig +short 2.0.0.127.zen.spamhaus.org @<your-resolver>   # expect 127.0.0.2",
    ],
    tools: ["dig with explicit @server", "EDH_DNS_RESOLVER setting"],
    furtherHealth: ["Per-zone probe latency (rate-limiting shows as timeouts/127.255.255.255)."],
    progress: [
      "Point the checker at a real recursive resolver (set EDH_DNS_RESOLVER; local unbound/knot-resolver or your ISP's).",
      "For volume: get the free Spamhaus DQS key and Abusix key.",
      "Register the resolver IP with Barracuda.",
      "Re-run — refused zones re-query automatically.",
    ],
  },
  "PS-10": {
    id: "PS-10",
    name: "Dead or wildcarding zone (false listing)",
    severity: "info",
    trigger: "An RFC 5782 probe failed; the zone lists 127.0.0.1 or answers nothing.",
    concept:
      "DNSBLs die, and dying zones sometimes wildcard — answering 'listed' for EVERYTHING (AHBL and SpamCannibal famously did). A hit from such a zone is noise; we exclude it and explain, rather than silently hiding it or raising a false alarm. This does not affect your standing.",
    diagnose: [
      "dig +short 1.0.0.127.<zone>   # an answer = wildcarding",
      "dig +short 2.0.0.127.<zone>   # NXDOMAIN = dead/empty zone",
    ],
    tools: ["dig", "multirbl.valli.org zone pages", "dnsbl.com dead-list registry"],
    furtherHealth: ["None for the domain — this is catalog hygiene."],
    progress: [
      "The zone was auto-excluded for this run.",
      "An operator can retire it permanently in blacklist_zones.yaml, or re-enable after the operator's outage resolves.",
    ],
  },
  "PS-11": {
    id: "PS-11",
    name: "New-domain zero reputation",
    severity: "info",
    trigger: "The domain is very young (ZRD/SEM-FRESH class signals).",
    concept:
      "The domain is simply YOUNG. Spamhaus ZRD lists everything under 24h old by definition; SEM-FRESH tracks fresh registrations; many receivers throttle new domains regardless. Not an accusation — a maturity gate every domain passes through.",
    diagnose: [
      "whois <domain> | grep -i creation",
      "dig +short <domain>.fresh.spameatingmonkey.net",
    ],
    tools: ["whois", "dig"],
    furtherHealth: [
      "Authentication completeness — new domains need perfect SPF/DKIM/DMARC to build reputation fast.",
      "The warm-up volume curve in your send logs.",
    ],
    progress: [
      "Wait out the age gates (ZRD clears at 24h).",
      "Send low, consistent volume to engaged recipients first.",
      "Ensure auth is fully green before scaling volume.",
      "Enroll Postmaster Tools/SNDS on day one so reputation formation is observable.",
    ],
  },
  "PS-12": {
    id: "PS-12",
    name: "No positive reputation established",
    severity: "info",
    trigger: "Not on DNSWL; Sender Score absent or low — but no listings.",
    concept:
      "Nothing is wrong — but nothing vouches for you either: not on DNSWL, no meaningful Sender Score. Positive signals are a buffer against future gray-area filtering. Severity stays informational; this is a nudge, not a problem.",
    diagnose: [
      "dig +short <reversed-ip>.list.dnswl.org       # NXDOMAIN = not registered",
      "dig +short <reversed-ip>.score.senderscore.com # last octet = 0-100 score",
    ],
    tools: ["dig", "dnswl.org self-registration", "senderscore.org"],
    furtherHealth: ["Complaint and bounce trends from ingested reports."],
    progress: [
      "Register the MTA at dnswl.org (free tier, pick the right category).",
      "Keep volume steady so Sender Score materializes.",
      "Done when DNSWL shows trust ≥ 1 and the score is ≥ 70.",
    ],
  },
  "PS-13": {
    id: "PS-13",
    name: "Pay-to-delist trap encountered",
    severity: "info",
    trigger: "The only open listings are on operators that sell 'express' removal.",
    concept:
      "DO NOT PAY. The industry position (RFC 6471) is that payment-for-removal is abusive; these listings auto-expire (7 days–4 weeks) and barely affect placement at major receivers. This state exists to stop you from paying out of panic.",
    diagnose: [
      "# Confirm no HIGH-tier co-listing — if Spamhaus is also red, THAT is the real problem",
      "dig +short <reversed-ip>.dnsbl-1.uceprotect.net",
    ],
    tools: ["dig", "the operator lookup pages", "the HIGH-tier zone matrix"],
    furtherHealth: ["Real placement evidence — ask for actual NDRs naming these lists before caring."],
    progress: [
      "Do not pay — listings auto-expire and funding the practice is discouraged (RFC 6471).",
      "Fix any genuine cause (backscatter → stop bounce-after-accept on the MTA).",
      "Wait for auto-expiry.",
      "If a real correspondent's server uses these lists, hand them the RFC 6471 context.",
    ],
  },
}

export function problemState(id: string): ProblemStateInfo | null {
  return (PROBLEM_STATES as Record<string, ProblemStateInfo>)[id] ?? null
}
