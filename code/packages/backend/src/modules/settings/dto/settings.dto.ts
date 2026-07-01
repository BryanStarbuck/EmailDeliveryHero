import { ApiPropertyOptional, ApiProperty } from "@nestjs/swagger"
import { Type } from "class-transformer"
import {
  ArrayMaxSize,
  IsArray,
  IsBase64,
  IsBoolean,
  IsIn,
  IsInt,
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
  @ApiPropertyOptional({ type: [String], description: "DNSBL zones the Blacklists category queries" })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(100)
  @IsString({ each: true })
  zones?: string[]
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
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export class ImportArchiveDto {
  @ApiProperty({ description: "Base64-encoded zip previously produced by GET /api/settings/export" })
  @IsString()
  @IsBase64()
  archiveBase64!: string
}

export class ResetDto {
  @ApiProperty({
    enum: ["audit_history", "app"],
    description: "audit_history = delete run history only; app = clear the whole state back to defaults",
  })
  @IsIn(["audit_history", "app"])
  scope!: "audit_history" | "app"
}
