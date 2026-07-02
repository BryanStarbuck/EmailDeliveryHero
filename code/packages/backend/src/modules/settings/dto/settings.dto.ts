import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger"
import { Type } from "class-transformer"
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
} from "class-validator"
import { CHECK_CATEGORIES, type CheckCategory } from "../settings.types"

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
  @ApiPropertyOptional({ description: "Browser/desktop notification on new problems" })
  @IsOptional()
  @IsBoolean()
  desktop?: boolean

  @ApiPropertyOptional({ description: "Email this user on new problems" })
  @IsOptional()
  @IsBoolean()
  email?: boolean

  @ApiPropertyOptional({ enum: ["info", "warning", "critical"] })
  @IsOptional()
  @IsIn(["info", "warning", "critical"])
  minSeverity?: "info" | "warning" | "critical"

  @ApiPropertyOptional({ enum: ["immediate", "daily"] })
  @IsOptional()
  @IsIn(["immediate", "daily"])
  mode?: "immediate" | "daily"
}

export class UserAppearanceDto {
  @ApiPropertyOptional({ enum: ["system", "light", "dark"] })
  @IsOptional()
  @IsIn(["system", "light", "dark"])
  theme?: "system" | "light" | "dark"

  @ApiPropertyOptional({ enum: ["comfortable", "compact"] })
  @IsOptional()
  @IsIn(["comfortable", "compact"])
  density?: "comfortable" | "compact"
}

export class UpdateUserSettingsDto {
  @ApiPropertyOptional({ type: UserNotificationPrefsDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => UserNotificationPrefsDto)
  notifications?: UserNotificationPrefsDto

  @ApiPropertyOptional({ type: UserAppearanceDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => UserAppearanceDto)
  appearance?: UserAppearanceDto
}

// ---------------------------------------------------------------------------
// PUT /api/settings/admin — admin-only global fields (§2, §3, §4, §5, §6, §7)
// ---------------------------------------------------------------------------

export class ChecksSpfDto {
  @ApiPropertyOptional({ description: "Max DNS lookups before SPF is flagged (RFC limit is 10)" })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  maxLookups?: number
}

export class ChecksDkimDto {
  @ApiPropertyOptional({ type: [String], description: "Global fallback DKIM selectors" })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(50)
  @IsString({ each: true })
  defaultSelectors?: string[]
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
  zones?: string[]
}

/** Content-scoring admin settings (pm/checks/content_scoring.mdx §4). */
export class ChecksContentDto {
  @ApiPropertyOptional({ description: "SpamAssassin spam threshold override (default 5.0)" })
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(100)
  threshold?: number

  @ApiPropertyOptional({ description: "Inbox-safe target — totals below it are ok (default 2.0)" })
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(100)
  safeTarget?: number

  @ApiPropertyOptional({
    description: "Enable SpamAssassin network content tests (URIBL/Razor/Pyzor/DCC; default off)",
  })
  @IsOptional()
  @IsBoolean()
  networkTests?: boolean
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
  name!: string

  @ApiProperty({ description: "Substring matched against the VMC/CMC certificate issuer DN" })
  @IsString()
  @MaxLength(500)
  issuerDnMatch!: string

  @ApiProperty({
    type: [String],
    description: 'Mark types the MVA may issue: "vmc" (registered trademark) and/or "cmc"',
    example: ["vmc", "cmc"],
  })
  @IsArray()
  @ArrayMaxSize(2)
  @IsIn(["vmc", "cmc"], { each: true })
  markTypes!: ("vmc" | "cmc")[]

  @ApiProperty({ description: "Whether this MVA is currently recognized" })
  @IsBoolean()
  enabled!: boolean
}

/**
 * BIMI admin settings (pm/checks/bimi.mdx §4/§5): the VMC/CMC issuer allow-list ("VMC allow-list
 * editing — which MVAs are recognized — is an admin-only setting").
 */
export class ChecksBimiDto {
  @ApiPropertyOptional({
    type: [BimiMvaEntryDto],
    description: "Recognized Mark Verifying Authorities (replaces the whole list)",
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(50)
  @ValidateNested({ each: true })
  @Type(() => BimiMvaEntryDto)
  mvaAllowList?: BimiMvaEntryDto[]
}

/**
 * DANE / TLSA admin settings (pm/checks/dane_tlsa.mdx §4, admin-only): the FUTURE :25 STARTTLS
 * cert-match probe toggle (it opens outbound SMTP connections), its per-MX timeout, and whether
 * the DNSSEC prerequisite must be confirmed via the AD bit from a validating resolver (FUTURE).
 */
export class ChecksDaneDto {
  @ApiPropertyOptional({
    description: "Enable the :25 STARTTLS cert-match probe (opens outbound SMTP; default off)",
  })
  @IsOptional()
  @IsBoolean()
  probeEnabled?: boolean

  @ApiPropertyOptional({ description: "Per-MX probe timeout in ms (default 10000)" })
  @IsOptional()
  @IsInt()
  @Min(500)
  @Max(120000)
  probeTimeoutMs?: number

  @ApiPropertyOptional({
    description:
      "Require the DNSSEC AD bit from a validating resolver (FUTURE) instead of the first-round DS/DNSKEY observation",
  })
  @IsOptional()
  @IsBoolean()
  requireAdBit?: boolean
}

export class ChecksThresholdsDto {
  @ApiPropertyOptional({ description: "score >= green → green" })
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(100)
  green?: number

  @ApiPropertyOptional({ description: "green > score >= amber → amber; below → red" })
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(100)
  amber?: number
}

export class ChecksWeightsDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(100)
  critical?: number

  @ApiPropertyOptional()
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(100)
  warning?: number

  @ApiPropertyOptional()
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(100)
  info?: number
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
  enabled?: CheckCategory[]

  @ApiPropertyOptional({ type: ChecksSpfDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ChecksSpfDto)
  spf?: ChecksSpfDto

  @ApiPropertyOptional({ type: ChecksDkimDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ChecksDkimDto)
  dkim?: ChecksDkimDto

  @ApiPropertyOptional({ type: ChecksDnsblDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ChecksDnsblDto)
  dnsbl?: ChecksDnsblDto

  @ApiPropertyOptional({ type: ChecksContentDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ChecksContentDto)
  content?: ChecksContentDto

  @ApiPropertyOptional({ type: ChecksBimiDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ChecksBimiDto)
  bimi?: ChecksBimiDto

  @ApiPropertyOptional({ type: ChecksDaneDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ChecksDaneDto)
  dane?: ChecksDaneDto

  @ApiPropertyOptional({ type: ChecksThresholdsDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ChecksThresholdsDto)
  thresholds?: ChecksThresholdsDto

  @ApiPropertyOptional({ type: ChecksWeightsDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ChecksWeightsDto)
  weights?: ChecksWeightsDto
}

export class ScheduleConfigDto {
  @ApiPropertyOptional({ description: "Master switch for scheduled re-audits" })
  @IsOptional()
  @IsBoolean()
  enabled?: boolean

  @ApiPropertyOptional({ description: "Cadence (cron), e.g. every 6h", example: "0 */6 * * *" })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  cadence?: string
}

export class WebhookConfigDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  enabled?: boolean

  @ApiPropertyOptional({ description: "Slack-compatible incoming-webhook URL" })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  url?: string
}

export class SmtpConfigDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(253)
  host?: string

  @ApiPropertyOptional()
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(65535)
  port?: number

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(320)
  from?: string
}

export class NotificationsChannelsDto {
  @ApiPropertyOptional({ type: WebhookConfigDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => WebhookConfigDto)
  webhook?: WebhookConfigDto

  @ApiPropertyOptional({ type: SmtpConfigDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => SmtpConfigDto)
  smtp?: SmtpConfigDto
}

export class StorageConfigDto {
  @ApiPropertyOptional({ description: "Audit-history retention (days)" })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(3650)
  retentionDays?: number
}

export class ToolsConfigDto {
  @ApiPropertyOptional({ description: "Prefer dig over node:dns/promises when available" })
  @IsOptional()
  @IsBoolean()
  preferCli?: boolean

  @ApiPropertyOptional({ type: [String], description: "Resolver IPs; empty = system default" })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(10)
  @IsString({ each: true })
  resolvers?: string[]

  @ApiPropertyOptional({ description: "Per-lookup timeout (ms)" })
  @IsOptional()
  @IsInt()
  @Min(100)
  @Max(120000)
  timeoutMs?: number

  @ApiPropertyOptional({
    description:
      "Explicit per-tool binary-path overrides (config.yaml → tools.paths), e.g. " +
      '{ "spamassassin": "/opt/homebrew/bin/spamassassin", "spamc": "/opt/homebrew/bin/spamc" } ' +
      "(pm/checks/content_scoring.mdx §4 — the SpamAssassin/spamc binary path; empty value clears)",
    example: { spamassassin: "/opt/homebrew/bin/spamassassin" },
  })
  @IsOptional()
  @IsObject()
  paths?: Record<string, string>
}

/**
 * One subdomain-takeover fingerprint (pm/checks/dns_health.mdx §5 — the `takeover_fingerprints`
 * reference table mapped onto `config.yaml → dns_health.fingerprints`, admin-editable §4). The
 * dangling-CNAME sub-check matches each CNAME chain's final target against `cname_suffix`;
 * `unclaimed_signature` is stored for the future HTTP "unclaimed endpoint" confirmation probe.
 */
export class TakeoverFingerprintDto {
  @ApiProperty({ description: 'Provider display name, e.g. "Heroku" or "GitHub Pages"' })
  @IsString()
  @MaxLength(100)
  provider!: string

  @ApiProperty({
    description: 'Suffix matched against the final CNAME target, e.g. ".herokudns.com"',
  })
  @IsString()
  @MaxLength(253)
  cname_suffix!: string

  @ApiPropertyOptional({
    description: 'HTTP body marker for the future "unclaimed endpoint" probe',
  })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  unclaimed_signature?: string

  @ApiProperty({ description: "Whether this fingerprint is currently matched" })
  @IsBoolean()
  enabled!: boolean
}

/** DNS-health admin settings (pm/checks/dns_health.mdx §4): the takeover-fingerprint list. */
export class DnsHealthSettingsDto {
  @ApiPropertyOptional({
    type: [TakeoverFingerprintDto],
    description: "Subdomain-takeover fingerprint list (replaces the whole list)",
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(200)
  @ValidateNested({ each: true })
  @Type(() => TakeoverFingerprintDto)
  fingerprints?: TakeoverFingerprintDto[]
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
  allowedDomains?: string[]
}

export class UpdateAdminSettingsDto {
  @ApiPropertyOptional({ type: ChecksConfigDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ChecksConfigDto)
  checks?: ChecksConfigDto

  @ApiPropertyOptional({ type: ScheduleConfigDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ScheduleConfigDto)
  schedule?: ScheduleConfigDto

  @ApiPropertyOptional({ type: NotificationsChannelsDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => NotificationsChannelsDto)
  notifications?: NotificationsChannelsDto

  @ApiPropertyOptional({ type: StorageConfigDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => StorageConfigDto)
  storage?: StorageConfigDto

  @ApiPropertyOptional({ type: ToolsConfigDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => ToolsConfigDto)
  tools?: ToolsConfigDto

  @ApiPropertyOptional({ type: AccessConfigDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => AccessConfigDto)
  access?: AccessConfigDto

  @ApiPropertyOptional({ type: DnsHealthSettingsDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => DnsHealthSettingsDto)
  dns_health?: DnsHealthSettingsDto
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export class ImportArchiveDto {
  @ApiProperty({
    description: "Base64-encoded zip previously produced by GET /api/settings/export",
  })
  @IsString()
  @IsBase64()
  archiveBase64!: string
}

export class ResetDto {
  @ApiProperty({
    enum: ["audit_history", "app"],
    description:
      "audit_history = delete run history only; app = clear the whole state back to defaults",
  })
  @IsIn(["audit_history", "app"])
  scope!: "audit_history" | "app"
}
