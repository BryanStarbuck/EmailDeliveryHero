import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger"
import { Type } from "class-transformer"
import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsInt,
  IsIP,
  IsOptional,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
  ValidateNested,
} from "class-validator"

// A permissive but real domain-name shape: labels of letters/digits/hyphens separated by dots.
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i

// A DKIM selector token (pm/domains.mdx §4.1): letters, digits, and hyphens only.
const SELECTOR_RE = /^[a-z0-9-]{1,63}$/i
const SELECTOR_MSG = "each DKIM selector must contain only letters, digits, and hyphens"
const IP_MSG = "each sending IP must be a valid IPv4 or IPv6 address"

/**
 * One declared forwarder / mailing list the domain sends through (pm/checks/arc.mdx §4 per-domain
 * config — the `arc_forwarders` reference table mapped onto the YAML store).
 */
export class ArcForwarderDto {
  @ApiProperty({ example: "acme-users Google Group" })
  @IsString()
  @MaxLength(200)
  label!: string

  @ApiProperty({ example: "acme-users@googlegroups.com", description: "Probe target that forwards to us" })
  @IsString()
  @MaxLength(320)
  forwardAddress!: string

  @ApiPropertyOptional({ example: "googlegroups.com", description: "Expected ARC signing domain (d=)" })
  @IsOptional()
  @IsString()
  @MaxLength(253)
  @Matches(DOMAIN_RE, { message: "signerDomain must be a valid domain" })
  signerDomain?: string

  @ApiPropertyOptional({ example: "arc-20240605", description: "Expected ARC signing selector (s=)" })
  @IsOptional()
  @IsString()
  @Matches(SELECTOR_RE, { message: "signerSelector must contain only letters, digits, and hyphens" })
  signerSelector?: string

  @ApiPropertyOptional({
    example: "arc-probe@ourdomain.com",
    description: "Where the forwarded copy lands for capture (future swaks probe)",
  })
  @IsOptional()
  @IsString()
  @MaxLength(320)
  probeMailbox?: string
}

/** Per-domain ARC / forwarding configuration (pm/checks/arc.mdx §4 per-domain config inputs). */
export class ArcConfigDto {
  @ApiProperty({ example: true, description: "The domain sends through forwarders / mailing lists" })
  @IsBoolean()
  usesForwarding!: boolean

  @ApiProperty({ type: [ArcForwarderDto] })
  @IsArray()
  @ArrayMaxSize(50)
  @ValidateNested({ each: true })
  @Type(() => ArcForwarderDto)
  forwarders!: ArcForwarderDto[]
}

/**
 * Per-domain BIMI configuration (pm/checks/bimi.mdx §4 per-domain config inputs): optional BIMI
 * selectors beyond `default`, and an optional sample message (headers) whose `BIMI-Selector:`
 * header is compared against the published `_bimi` records.
 */
export class BimiConfigDto {
  @ApiPropertyOptional({
    type: [String],
    example: ["v1"],
    description: "BIMI selectors to audit beyond default (<selector>._bimi.<domain>)",
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  @Matches(SELECTOR_RE, {
    each: true,
    message: "each BIMI selector must contain only letters, digits, and hyphens",
  })
  selectors?: string[]

  @ApiPropertyOptional({
    description: "Sample message (headers suffice) — its BIMI-Selector: header names the selector to verify",
  })
  @IsOptional()
  @IsString()
  @MaxLength(100_000)
  sampleMessage?: string
}

/**
 * Per-domain List-Unsubscribe / one-click configuration (pm/checks/list_unsubscribe.mdx §3/§4
 * per-domain config inputs): the bulk-sender severity escalator and the opt-in endpoint-probe
 * toggle (default off — a live one-click POST may unsubscribe the sampled recipient).
 */
export class ListUnsubConfigDto {
  @ApiPropertyOptional({
    example: false,
    description: "Bulk sender (> 5,000 msgs/day) — escalates missing one-click to critical",
  })
  @IsOptional()
  @IsBoolean()
  isBulkSender?: boolean

  @ApiPropertyOptional({
    example: false,
    description:
      "Opt-in live one-click POST probe of the https unsubscribe endpoint (may unsubscribe the sampled recipient)",
  })
  @IsOptional()
  @IsBoolean()
  probeUnsubEndpoint?: boolean
}

/**
 * Per-domain DNS-health expectations (pm/checks/dns_health.mdx §4 per-domain config inputs — the
 * `dns_health_expectations` table mapped onto the YAML store): extra dangling-scan labels, an
 * optional expected-NS allow-list (drift alerts), and the skip-AXFR-probe toggle.
 */
export class DnsHealthConfigDto {
  @ApiPropertyOptional({
    type: [String],
    example: ["links", "click2"],
    description: "Extra subdomain labels to include in the dangling-CNAME scan",
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(50)
  @IsString({ each: true })
  @Matches(/^[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9])?$/i, {
    each: true,
    message: "each extra label must be a valid DNS label or dotted name",
  })
  extraLabels?: string[]

  @ApiPropertyOptional({
    type: [String],
    example: ["ns1.provider-a.net", "ns1.provider-b.net"],
    description: "Expected NS allow-list; drift against the published NS set is flagged",
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  @Matches(DOMAIN_RE, { each: true, message: "each expected NS must be a valid hostname" })
  expectedNs?: string[]

  @ApiPropertyOptional({ example: false, description: "Skip the (future) AXFR zone-transfer probe" })
  @IsOptional()
  @IsBoolean()
  skipAxfrProbe?: boolean
}

/**
 * Per-domain Domain-Registration-Reputation config (pm/checks/domain_reputation.mdx §4 per-domain
 * config inputs, admin-only): the org brand string(s) for `infra.name_similarity`, the expiry /
 * age warning thresholds (default 30 days each), the "registrant is intentionally public" toggle
 * silencing `infra.registrant_privacy`, and the (future) active cousin-domain scan toggle.
 */
export class DomainReputationConfigDto {
  @ApiPropertyOptional({
    type: [String],
    example: ["example.com"],
    description: "Org brand string(s) compared against the apex for lookalike/cousin detection",
  })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  @MaxLength(253, { each: true })
  brands?: string[]

  @ApiPropertyOptional({ example: 30, description: "Warn when the registration expires in fewer days than this" })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(365)
  expiryWarnDays?: number

  @ApiPropertyOptional({ example: 30, description: "Warn when the registration is younger than this many days" })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(365)
  ageWarnDays?: number

  @ApiPropertyOptional({
    example: false,
    description: "Registrant contact is deliberately public — silences infra.registrant_privacy",
  })
  @IsOptional()
  @IsBoolean()
  registrantPublicIntentional?: boolean

  @ApiPropertyOptional({ example: false, description: "Enable the (future) active cousin-domain scan" })
  @IsOptional()
  @IsBoolean()
  cousinScan?: boolean
}

export class CreateDomainDto {
  @ApiProperty({ example: "whitehatengineering.com" })
  @IsString()
  @MaxLength(253)
  @Matches(DOMAIN_RE, { message: "name must be a valid domain, e.g. example.com" })
  name!: string

  @ApiPropertyOptional({ type: [String], example: ["google"] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  @Matches(SELECTOR_RE, { each: true, message: SELECTOR_MSG })
  dkimSelectors?: string[]

  @ApiPropertyOptional({ type: [String], example: ["203.0.113.10"] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(50)
  @IsString({ each: true })
  @IsIP(undefined, { each: true, message: IP_MSG })
  sendingIps?: string[]

  @ApiPropertyOptional({ example: "Primary marketing domain" })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  label?: string

  @ApiPropertyOptional({ example: true, description: "Include in recurring scheduled checks" })
  @IsOptional()
  @IsBoolean()
  scheduleEnabled?: boolean

  @ApiPropertyOptional({ type: ArcConfigDto, description: "ARC / forwarding config (pm/checks/arc.mdx §4)" })
  @IsOptional()
  @ValidateNested()
  @Type(() => ArcConfigDto)
  arc?: ArcConfigDto

  @ApiPropertyOptional({ type: BimiConfigDto, description: "BIMI config (pm/checks/bimi.mdx §4)" })
  @IsOptional()
  @ValidateNested()
  @Type(() => BimiConfigDto)
  bimi?: BimiConfigDto

  @ApiPropertyOptional({
    type: DnsHealthConfigDto,
    description: "DNS-health expectations (pm/checks/dns_health.mdx §4)",
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => DnsHealthConfigDto)
  dnsHealth?: DnsHealthConfigDto

  @ApiPropertyOptional({
    type: DomainReputationConfigDto,
    description: "Domain-registration-reputation config (pm/checks/domain_reputation.mdx §4)",
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => DomainReputationConfigDto)
  domainReputation?: DomainReputationConfigDto
}

export class UpdateDomainDto {
  @ApiPropertyOptional({ type: [String], example: ["google", "s1"] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(20)
  @IsString({ each: true })
  @Matches(SELECTOR_RE, { each: true, message: SELECTOR_MSG })
  dkimSelectors?: string[]

  @ApiPropertyOptional({ type: [String], example: ["203.0.113.10"] })
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(50)
  @IsString({ each: true })
  @IsIP(undefined, { each: true, message: IP_MSG })
  sendingIps?: string[]

  @ApiPropertyOptional({ example: "Primary marketing domain" })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  label?: string

  @ApiPropertyOptional({ example: true, description: "Include in recurring scheduled checks" })
  @IsOptional()
  @IsBoolean()
  scheduleEnabled?: boolean

  @ApiPropertyOptional({ type: ArcConfigDto, description: "ARC / forwarding config (pm/checks/arc.mdx §4)" })
  @IsOptional()
  @ValidateNested()
  @Type(() => ArcConfigDto)
  arc?: ArcConfigDto

  @ApiPropertyOptional({ type: BimiConfigDto, description: "BIMI config (pm/checks/bimi.mdx §4)" })
  @IsOptional()
  @ValidateNested()
  @Type(() => BimiConfigDto)
  bimi?: BimiConfigDto

  @ApiPropertyOptional({
    type: DnsHealthConfigDto,
    description: "DNS-health expectations (pm/checks/dns_health.mdx §4)",
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => DnsHealthConfigDto)
  dnsHealth?: DnsHealthConfigDto

  @ApiPropertyOptional({
    type: DomainReputationConfigDto,
    description: "Domain-registration-reputation config (pm/checks/domain_reputation.mdx §4)",
  })
  @IsOptional()
  @ValidateNested()
  @Type(() => DomainReputationConfigDto)
  domainReputation?: DomainReputationConfigDto
}
