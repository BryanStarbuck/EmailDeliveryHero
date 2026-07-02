import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { Type } from "class-transformer";
import {
	ArrayMaxSize,
	IsArray,
	IsBase64,
	IsBoolean,
	IsIn,
	IsInt,
	IsNumber,
	IsObject,
	IsOptional,
	IsString,
	Max,
	MaxLength,
	Min,
	ValidateNested,
} from "class-validator";
import { CHECK_CATEGORIES, type CheckCategory } from "../settings.types";

/**
 * Settings DTOs (pm/settings.mdx REST contract). Two write surfaces:
 *   - PUT /api/settings        → UpdateUserSettingsDto  (all-users; the caller's own per-user block)
 *   - PUT /api/settings/admin  → UpdateAdminSettingsDto (admin-only global fields; deep-partial)
 * The global ValidationPipe runs with whitelist + forbidNonWhitelisted, so every accepted field
 * must be declared here — an unknown key is a 400, never a silent write.
 */

// ---------------------------------------------------------------------------
// PUT /api/settings — per-user preferences (§4 notifications + §8 appearance)
// ---------------------------------------------------------------------------

export class UserNotificationPrefsDto {
	@ApiPropertyOptional({
		description: "Browser/desktop notification on new problems",
	})
	@IsOptional()
	@IsBoolean()
	desktop?: boolean;

	@ApiPropertyOptional({ description: "Email this user on new problems" })
	@IsOptional()
	@IsBoolean()
	email?: boolean;

	@ApiPropertyOptional({ enum: ["info", "warning", "critical"] })
	@IsOptional()
	@IsIn(["info", "warning", "critical"])
	minSeverity?: "info" | "warning" | "critical";

	@ApiPropertyOptional({ enum: ["immediate", "daily"] })
	@IsOptional()
	@IsIn(["immediate", "daily"])
	mode?: "immediate" | "daily";
}

export class UserAppearanceDto {
	@ApiPropertyOptional({ enum: ["system", "light", "dark"] })
	@IsOptional()
	@IsIn(["system", "light", "dark"])
	theme?: "system" | "light" | "dark";

	@ApiPropertyOptional({ enum: ["comfortable", "compact"] })
	@IsOptional()
	@IsIn(["comfortable", "compact"])
	density?: "comfortable" | "compact";
}

export class UpdateUserSettingsDto {
	@ApiPropertyOptional({ type: UserNotificationPrefsDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => UserNotificationPrefsDto)
	notifications?: UserNotificationPrefsDto;

	@ApiPropertyOptional({ type: UserAppearanceDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => UserAppearanceDto)
	appearance?: UserAppearanceDto;
}

// ---------------------------------------------------------------------------
// PUT /api/settings/admin — admin-only global fields (§2, §3, §4, §5, §6, §7)
// ---------------------------------------------------------------------------

export class ChecksSpfDto {
	@ApiPropertyOptional({
		description: "Max DNS lookups before SPF is flagged (RFC limit is 10)",
	})
	@IsOptional()
	@IsInt()
	@Min(1)
	@Max(100)
	maxLookups?: number;
}

export class ChecksDkimDto {
	@ApiPropertyOptional({
		type: [String],
		description: "Global fallback DKIM selectors",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(50)
	@IsString({ each: true })
	defaultSelectors?: string[];
}

export class ChecksDnsblDto {
	@ApiPropertyOptional({
		type: [String],
		description: "DNSBL zones the Blacklists category queries",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(100)
	@IsString({ each: true })
	zones?: string[];
}

/**
 * Link / URL-reputation admin settings (pm/checks/link_url_reputation.mdx §4/§5 — the "URL
 * Reputation" settings sub-panel): the public URL-shortener domain list matched by
 * `content.url_shortener` (config, not code) and the Google Safe Browsing API key that enables
 * `content.url_safe_browsing` in a future round ("" clears the key = not configured).
 */
export class ChecksContentUrlDto {
	@ApiPropertyOptional({
		type: [String],
		description:
			"Public URL-shortener domains flagged by content.url_shortener (registrable domains)",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(500)
	@IsString({ each: true })
	@MaxLength(253, { each: true })
	shorteners?: string[];

	@ApiPropertyOptional({
		description:
			"Google Safe Browsing API key for content.url_safe_browsing (empty = not configured)",
	})
	@IsOptional()
	@IsString()
	@MaxLength(200)
	safeBrowsingKey?: string;
}

/** Content-scoring admin settings (pm/checks/content_scoring.mdx §4). */
export class ChecksContentDto {
	@ApiPropertyOptional({
		description: "SpamAssassin spam threshold override (default 5.0)",
	})
	@IsOptional()
	@IsNumber()
	@Min(0)
	@Max(100)
	threshold?: number;

	@ApiPropertyOptional({
		description: "Inbox-safe target — totals below it are ok (default 2.0)",
	})
	@IsOptional()
	@IsNumber()
	@Min(0)
	@Max(100)
	safeTarget?: number;

	@ApiPropertyOptional({
		description:
			"Enable SpamAssassin network content tests (URIBL/Razor/Pyzor/DCC; default off)",
	})
	@IsOptional()
	@IsBoolean()
	networkTests?: boolean;

	@ApiPropertyOptional({ type: ChecksContentUrlDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksContentUrlDto)
	url?: ChecksContentUrlDto;
}

/**
 * One recognized Mark Verifying Authority (pm/checks/bimi.mdx §5 — the `bimi_mva` reference table
 * mapped onto `config.yaml → checks.bimi.mvaAllowList`). The future VMC/CMC certificate round
 * matches `issuerDnMatch` against the certificate issuer DN.
 */
export class BimiMvaEntryDto {
	@ApiProperty({ description: "MVA display name, e.g. DigiCert or Entrust" })
	@IsString()
	@MaxLength(100)
	name!: string;

	@ApiProperty({
		description: "Substring matched against the VMC/CMC certificate issuer DN",
	})
	@IsString()
	@MaxLength(500)
	issuerDnMatch!: string;

	@ApiProperty({
		type: [String],
		description:
			'Mark types the MVA may issue: "vmc" (registered trademark) and/or "cmc"',
		example: ["vmc", "cmc"],
	})
	@IsArray()
	@ArrayMaxSize(2)
	@IsIn(["vmc", "cmc"], { each: true })
	markTypes!: ("vmc" | "cmc")[];

	@ApiProperty({ description: "Whether this MVA is currently recognized" })
	@IsBoolean()
	enabled!: boolean;
}

/**
 * BIMI admin settings (pm/checks/bimi.mdx §4/§5): the VMC/CMC issuer allow-list ("VMC allow-list
 * editing — which MVAs are recognized — is an admin-only setting").
 */
export class ChecksBimiDto {
	@ApiPropertyOptional({
		type: [BimiMvaEntryDto],
		description:
			"Recognized Mark Verifying Authorities (replaces the whole list)",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(50)
	@ValidateNested({ each: true })
	@Type(() => BimiMvaEntryDto)
	mvaAllowList?: BimiMvaEntryDto[];
}

/**
 * DANE / TLSA admin settings (pm/checks/dane_tlsa.mdx §4, admin-only): the FUTURE :25 STARTTLS
 * cert-match probe toggle (it opens outbound SMTP connections), its per-MX timeout, and whether
 * the DNSSEC prerequisite must be confirmed via the AD bit from a validating resolver (FUTURE).
 */
export class ChecksDaneDto {
	@ApiPropertyOptional({
		description:
			"Enable the :25 STARTTLS cert-match probe (opens outbound SMTP; default off)",
	})
	@IsOptional()
	@IsBoolean()
	probeEnabled?: boolean;

	@ApiPropertyOptional({
		description: "Per-MX probe timeout in ms (default 10000)",
	})
	@IsOptional()
	@IsInt()
	@Min(500)
	@Max(120000)
	probeTimeoutMs?: number;

	@ApiPropertyOptional({
		description:
			"Require the DNSSEC AD bit from a validating resolver (FUTURE) instead of the first-round DS/DNSKEY observation",
	})
	@IsOptional()
	@IsBoolean()
	requireAdBit?: boolean;
}

/**
 * List-Unsubscribe / one-click admin settings (pm/checks/list_unsubscribe.mdx §4 "Admin-only
 * settings"): the Gmail/Yahoo bulk-sender daily threshold (default 5,000), the endpoint-probe
 * timeout (default 5s), whether the live one-click POST probe is globally permitted at all, and
 * the probe cadence (default 24h — the probe never re-fires more often, §6).
 */
export class ChecksListUnsubDto {
	@ApiPropertyOptional({
		description:
			"Gmail/Yahoo bulk-sender daily message threshold (default 5000)",
	})
	@IsOptional()
	@IsInt()
	@Min(1)
	@Max(10_000_000)
	bulkThresholdPerDay?: number;

	@ApiPropertyOptional({
		description: "One-click endpoint probe timeout in ms (default 5000)",
	})
	@IsOptional()
	@IsInt()
	@Min(500)
	@Max(120000)
	probeTimeoutMs?: number;

	@ApiPropertyOptional({
		description:
			"Globally permit the live one-click POST probe (per-domain probeUnsubEndpoint still required)",
	})
	@IsOptional()
	@IsBoolean()
	probeAllowed?: boolean;

	@ApiPropertyOptional({
		description:
			"Minimum hours between live endpoint probes per domain (default 24)",
	})
	@IsOptional()
	@IsInt()
	@Min(1)
	@Max(24 * 30)
	probeCadenceHours?: number;
}

export class ChecksThresholdsDto {
	@ApiPropertyOptional({ description: "score >= green → green" })
	@IsOptional()
	@IsInt()
	@Min(0)
	@Max(100)
	green?: number;

	@ApiPropertyOptional({
		description: "green > score >= amber → amber; below → red",
	})
	@IsOptional()
	@IsInt()
	@Min(0)
	@Max(100)
	amber?: number;
}

export class ChecksWeightsDto {
	@ApiPropertyOptional()
	@IsOptional()
	@IsInt()
	@Min(0)
	@Max(100)
	critical?: number;

	@ApiPropertyOptional()
	@IsOptional()
	@IsInt()
	@Min(0)
	@Max(100)
	warning?: number;

	@ApiPropertyOptional()
	@IsOptional()
	@IsInt()
	@Min(0)
	@Max(100)
	info?: number;
}

export class ChecksConfigDto {
	@ApiPropertyOptional({
		type: [String],
		description: "Enabled check categories (subset of the six)",
		example: ["spf", "dkim", "dmarc", "dnsbl", "dns_infra"],
	})
	@IsOptional()
	@IsArray()
	@IsIn(CHECK_CATEGORIES as readonly string[], { each: true })
	enabled?: CheckCategory[];

	@ApiPropertyOptional({ type: ChecksSpfDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksSpfDto)
	spf?: ChecksSpfDto;

	@ApiPropertyOptional({ type: ChecksDkimDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksDkimDto)
	dkim?: ChecksDkimDto;

	@ApiPropertyOptional({ type: ChecksDnsblDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksDnsblDto)
	dnsbl?: ChecksDnsblDto;

	@ApiPropertyOptional({ type: ChecksContentDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksContentDto)
	content?: ChecksContentDto;

	@ApiPropertyOptional({ type: ChecksBimiDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksBimiDto)
	bimi?: ChecksBimiDto;

	@ApiPropertyOptional({ type: ChecksDaneDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksDaneDto)
	dane?: ChecksDaneDto;

	@ApiPropertyOptional({ type: ChecksListUnsubDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksListUnsubDto)
	listUnsub?: ChecksListUnsubDto;

	@ApiPropertyOptional({ type: ChecksThresholdsDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksThresholdsDto)
	thresholds?: ChecksThresholdsDto;

	@ApiPropertyOptional({ type: ChecksWeightsDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksWeightsDto)
	weights?: ChecksWeightsDto;
}

export class ScheduleConfigDto {
	@ApiPropertyOptional({ description: "Master switch for scheduled re-audits" })
	@IsOptional()
	@IsBoolean()
	enabled?: boolean;

	@ApiPropertyOptional({
		description: "Cadence (cron), e.g. every 6h",
		example: "0 */6 * * *",
	})
	@IsOptional()
	@IsString()
	@MaxLength(100)
	cadence?: string;
}

export class WebhookConfigDto {
	@ApiPropertyOptional()
	@IsOptional()
	@IsBoolean()
	enabled?: boolean;

	@ApiPropertyOptional({ description: "Slack-compatible incoming-webhook URL" })
	@IsOptional()
	@IsString()
	@MaxLength(2000)
	url?: string;
}

export class SmtpConfigDto {
	@ApiPropertyOptional()
	@IsOptional()
	@IsString()
	@MaxLength(253)
	host?: string;

	@ApiPropertyOptional()
	@IsOptional()
	@IsInt()
	@Min(1)
	@Max(65535)
	port?: number;

	@ApiPropertyOptional()
	@IsOptional()
	@IsString()
	@MaxLength(320)
	from?: string;
}

export class NotificationsChannelsDto {
	@ApiPropertyOptional({ type: WebhookConfigDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => WebhookConfigDto)
	webhook?: WebhookConfigDto;

	@ApiPropertyOptional({ type: SmtpConfigDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => SmtpConfigDto)
	smtp?: SmtpConfigDto;
}

export class StorageConfigDto {
	@ApiPropertyOptional({ description: "Audit-history retention (days)" })
	@IsOptional()
	@IsInt()
	@Min(1)
	@Max(3650)
	retentionDays?: number;
}

export class ToolsConfigDto {
	@ApiPropertyOptional({
		description: "Prefer dig over node:dns/promises when available",
	})
	@IsOptional()
	@IsBoolean()
	preferCli?: boolean;

	@ApiPropertyOptional({
		type: [String],
		description: "Resolver IPs; empty = system default",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(10)
	@IsString({ each: true })
	resolvers?: string[];

	@ApiPropertyOptional({ description: "Per-lookup timeout (ms)" })
	@IsOptional()
	@IsInt()
	@Min(100)
	@Max(120000)
	timeoutMs?: number;

	@ApiPropertyOptional({
		description:
			"Explicit per-tool binary-path overrides (config.yaml → tools.paths), e.g. " +
			'{ "spamassassin": "/opt/homebrew/bin/spamassassin", "spamc": "/opt/homebrew/bin/spamc" } ' +
			"(pm/checks/content_scoring.mdx §4 — the SpamAssassin/spamc binary path; empty value clears)",
		example: { spamassassin: "/opt/homebrew/bin/spamassassin" },
	})
	@IsOptional()
	@IsObject()
	paths?: Record<string, string>;
}

/**
 * One subdomain-takeover fingerprint (pm/checks/dns_health.mdx §5 — the `takeover_fingerprints`
 * reference table mapped onto `config.yaml → dns_health.fingerprints`, admin-editable §4). The
 * dangling-CNAME sub-check matches each CNAME chain's final target against `cname_suffix`;
 * `unclaimed_signature` is stored for the future HTTP "unclaimed endpoint" confirmation probe.
 */
export class TakeoverFingerprintDto {
	@ApiProperty({
		description: 'Provider display name, e.g. "Heroku" or "GitHub Pages"',
	})
	@IsString()
	@MaxLength(100)
	provider!: string;

	@ApiProperty({
		description:
			'Suffix matched against the final CNAME target, e.g. ".herokudns.com"',
	})
	@IsString()
	@MaxLength(253)
	cname_suffix!: string;

	@ApiPropertyOptional({
		description: 'HTTP body marker for the future "unclaimed endpoint" probe',
	})
	@IsOptional()
	@IsString()
	@MaxLength(500)
	unclaimed_signature?: string;

	@ApiProperty({ description: "Whether this fingerprint is currently matched" })
	@IsBoolean()
	enabled!: boolean;
}

/** DNS-health admin settings (pm/checks/dns_health.mdx §4): the takeover-fingerprint list. */
export class DnsHealthSettingsDto {
	@ApiPropertyOptional({
		type: [TakeoverFingerprintDto],
		description:
			"Subdomain-takeover fingerprint list (replaces the whole list)",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(200)
	@ValidateNested({ each: true })
	@Type(() => TakeoverFingerprintDto)
	fingerprints?: TakeoverFingerprintDto[];
}

/**
 * One registrar/TLD abuse-reputation watchlist entry (pm/checks/domain_reputation.mdx §5 — the
 * `registrar_reputation` reference table mapped onto `config.yaml →
 * domain_reputation.registrar_reputation`, admin-editable §4). The `infra.registrar_reputation`
 * and `infra.tld_risk` sub-checks match the audited domain's registrar / TLD against these rows.
 */
export class RegistrarReputationEntryDto {
	@ApiProperty({ enum: ["registrar_iana_id", "registrar_name", "tld"] })
	@IsIn(["registrar_iana_id", "registrar_name", "tld"])
	match_type!: "registrar_iana_id" | "registrar_name" | "tld";

	@ApiProperty({
		description:
			'IANA registrar id, registrar-name substring, or a TLD like "top"',
	})
	@IsString()
	@MaxLength(253)
	match_value!: string;

	@ApiPropertyOptional({
		description: "Why this entry is on the watchlist (shown in the finding)",
	})
	@IsOptional()
	@IsString()
	@MaxLength(300)
	note?: string;
}

/**
 * Domain Registration Reputation admin settings (pm/checks/domain_reputation.mdx §4 "Global admin
 * settings"): the long-TTL RDAP cache / per-run request budget and the curated reference lists
 * (parking-provider nameservers, high-abuse TLDs, registrar abuse-reputation watchlist).
 */
export class DomainReputationSettingsDto {
	@ApiPropertyOptional({
		description:
			"RDAP snapshot cache TTL in hours (default 24 — registration data is stale-tolerant)",
	})
	@IsOptional()
	@IsInt()
	@Min(1)
	@Max(24 * 30)
	cache_ttl_hours?: number;

	@ApiPropertyOptional({
		description:
			"Max RDAP requests per run (default 5 — endpoints rate-limit hard)",
	})
	@IsOptional()
	@IsInt()
	@Min(1)
	@Max(50)
	rdap_request_budget?: number;

	@ApiPropertyOptional({
		type: [String],
		description:
			'Parking-provider nameserver suffixes, e.g. "sedoparking.com" (replaces the whole list)',
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(200)
	@IsString({ each: true })
	parking_nameservers?: string[];

	@ApiPropertyOptional({
		type: [String],
		description:
			'High-abuse TLDs, e.g. "top" (Spamhaus TLD stats; replaces the whole list)',
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(200)
	@IsString({ each: true })
	high_abuse_tlds?: string[];

	@ApiPropertyOptional({
		type: [RegistrarReputationEntryDto],
		description:
			"Registrar/TLD abuse-reputation watchlist (replaces the whole list)",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(200)
	@ValidateNested({ each: true })
	@Type(() => RegistrarReputationEntryDto)
	registrar_reputation?: RegistrarReputationEntryDto[];
}

export class AccessConfigDto {
	@ApiPropertyOptional({
		type: [String],
		description:
			"Allowed Workspace domains (displayed here; enforcement is on the OpenAuthFederated side)",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(20)
	@IsString({ each: true })
	allowedDomains?: string[];
}

/**
 * One seed mailbox (pm/checks/inbox_placement.mdx §5 — the `seed_list_config` reference table
 * mapped onto `config.yaml → seedList.seeds`): the provider it covers, the address the probe is
 * sent to, and how the mailbox is read back (imap/graph/jmap for self-hosted, "service" when the
 * seed service owns the mailbox). Credentials live in the out-of-repo credentials file.
 */
export class SeedMailboxEntryDto {
	@ApiProperty({
		description: 'Provider key, e.g. "gmail" | "outlook" | "yahoo" | "apple"',
	})
	@IsString()
	@MaxLength(100)
	provider!: string;

	@ApiProperty({ description: "The seed mailbox address the probe is sent to" })
	@IsString()
	@MaxLength(320)
	seed_address!: string;

	@ApiProperty({ enum: ["imap", "graph", "jmap", "service"] })
	@IsIn(["imap", "graph", "jmap", "service"])
	read_method!: "imap" | "graph" | "jmap" | "service";

	@ApiProperty({
		description: "Whether this seed is live (counted for coverage / probed)",
	})
	@IsBoolean()
	active!: boolean;
}

/** Overall inbox-rate severity bands (pm/checks/inbox_placement.mdx §4, defaults 80 / 50). */
export class SeedThresholdsDto {
	@ApiPropertyOptional({
		description: "Overall inbox rate below this % → warning (default 80)",
	})
	@IsOptional()
	@IsNumber()
	@Min(0)
	@Max(100)
	warnBelowPct?: number;

	@ApiPropertyOptional({
		description: "Overall inbox rate below this % → critical (default 50)",
	})
	@IsOptional()
	@IsNumber()
	@Min(0)
	@Max(100)
	criticalBelowPct?: number;
}

/**
 * Seed-list inbox-placement admin settings (pm/checks/inbox_placement.mdx §4 "Admin-only
 * settings", §5 `seedList:`, §6 gating): the seed source ("" = not configured — the whole
 * placement family stays dark), the tested providers, the slow dedicated cadence, the inbox-rate
 * bands, the settle-window poll schedule, the monthly test budget, and the seed mailboxes.
 */
export class SeedListSettingsDto {
	@ApiPropertyOptional({
		description:
			'Seed source: "" = not configured; a seed-service name (glockapps/mailtrap/everest/' +
			'mailreach) or "self_hosted". API key / mailbox credentials live in the credentials file.',
	})
	@IsOptional()
	@IsString()
	@MaxLength(100)
	service?: string;

	@ApiPropertyOptional({
		type: [String],
		description: "Providers to test (spec §4 config)",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(50)
	@IsString({ each: true })
	providers?: string[];

	@ApiPropertyOptional({
		enum: ["daily", "weekly"],
		description:
			"The slow dedicated cadence — decoupled from the 6h DNS cadence (spec §6)",
	})
	@IsOptional()
	@IsIn(["daily", "weekly"])
	cadence?: "daily" | "weekly";

	@ApiPropertyOptional({ type: SeedThresholdsDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => SeedThresholdsDto)
	thresholds?: SeedThresholdsDto;

	@ApiPropertyOptional({
		type: [Number],
		description:
			"Read-back poll backoff in minutes before a Missing verdict (default 2/5/10/15)",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(20)
	@IsInt({ each: true })
	@Min(1, { each: true })
	@Max(24 * 60, { each: true })
	settlePollMinutes?: number[];

	@ApiPropertyOptional({
		description:
			"Max probe sends per calendar month — each spends a credit and sends real mail",
	})
	@IsOptional()
	@IsInt()
	@Min(0)
	@Max(10000)
	monthlyBudget?: number;

	@ApiPropertyOptional({
		type: [SeedMailboxEntryDto],
		description:
			"Self-hosted seed mailboxes (replaces the whole list; deduped on seed_address)",
	})
	@IsOptional()
	@IsArray()
	@ArrayMaxSize(500)
	@ValidateNested({ each: true })
	@Type(() => SeedMailboxEntryDto)
	seeds?: SeedMailboxEntryDto[];
}

export class UpdateAdminSettingsDto {
	@ApiPropertyOptional({ type: ChecksConfigDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ChecksConfigDto)
	checks?: ChecksConfigDto;

	@ApiPropertyOptional({ type: ScheduleConfigDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ScheduleConfigDto)
	schedule?: ScheduleConfigDto;

	@ApiPropertyOptional({ type: NotificationsChannelsDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => NotificationsChannelsDto)
	notifications?: NotificationsChannelsDto;

	@ApiPropertyOptional({ type: StorageConfigDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => StorageConfigDto)
	storage?: StorageConfigDto;

	@ApiPropertyOptional({ type: ToolsConfigDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => ToolsConfigDto)
	tools?: ToolsConfigDto;

	@ApiPropertyOptional({ type: AccessConfigDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => AccessConfigDto)
	access?: AccessConfigDto;

	@ApiPropertyOptional({ type: DnsHealthSettingsDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => DnsHealthSettingsDto)
	dns_health?: DnsHealthSettingsDto;

	@ApiPropertyOptional({ type: DomainReputationSettingsDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => DomainReputationSettingsDto)
	domain_reputation?: DomainReputationSettingsDto;

	@ApiPropertyOptional({ type: SeedListSettingsDto })
	@IsOptional()
	@ValidateNested()
	@Type(() => SeedListSettingsDto)
	seedList?: SeedListSettingsDto;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export class ImportArchiveDto {
	@ApiProperty({
		description:
			"Base64-encoded zip previously produced by GET /api/settings/export",
	})
	@IsString()
	@IsBase64()
	archiveBase64!: string;
}

export class ResetDto {
	@ApiProperty({
		enum: ["audit_history", "app"],
		description:
			"audit_history = delete run history only; app = clear the whole state back to defaults",
	})
	@IsIn(["audit_history", "app"])
	scope!: "audit_history" | "app";
}
