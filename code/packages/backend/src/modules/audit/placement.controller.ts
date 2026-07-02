import { randomUUID } from "node:crypto"
import { RequireRole } from "@module/auth/roles.decorator"
import { DomainsService } from "@module/domains/domains.service"
import {
  Body,
  ConflictException,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  NotImplementedException,
  Param,
  Post,
} from "@nestjs/common"
import {
  ApiBearerAuth,
  ApiOperation,
  ApiProperty,
  ApiPropertyOptional,
  ApiTags,
} from "@nestjs/swagger"
import { readAppConfig } from "@shared/config-store"
import { Type } from "class-transformer"
import {
  IsArray,
  IsBoolean,
  IsIn,
  IsInt,
  IsISO8601,
  IsOptional,
  IsString,
  MaxLength,
  Min,
  MinLength,
  ValidateNested,
} from "class-validator"
import {
  aggregateOverall,
  type GmailTab,
  type InboxPlacementTest,
  type PlacementFolder,
  trendSeries,
} from "./checks/inbox-placement/placement"
import {
  canSendSeedTest,
  listPlacementTests,
  recordPlacementTest,
  type SeedTestGate,
  seedListConfigured,
  testsSentInMonth,
} from "./checks/inbox-placement/placement-store"

/**
 * The per-domain Inbox Placement API (pm/checks/inbox_placement.mdx §4/§6):
 *
 *   GET  /api/audit/placement/:domainId            — panel status: the seed-test config summary,
 *                                                    budget usage, latest recorded test, and the
 *                                                    trend series the sparkline renders.
 *   POST /api/audit/placement/:domainId/send-test  — the deliberate, admin-gated "Send seed test
 *                                                    now" action. Enforces the spec §6 guard rails
 *                                                    today (configured / debounced / monthly
 *                                                    budget); the actual probe send is the FUTURE
 *                                                    seed-service / self-hosted SMTP integration,
 *                                                    so a fully-allowed send answers 501 rather
 *                                                    than pretending mail went out.
 *   POST /api/audit/placement/:domainId/tests      — record one completed seed test read-back
 *                                                    (the §5 `inbox_placement_tests` envelope +
 *                                                    its per-seed `inbox_placement_results` rows),
 *                                                    e.g. imported from a seed service's results
 *                                                    API/export. The next audit run scores it.
 */

/** One per-seed verdict row (spec §5 `inbox_placement_results`). */
export class SeedResultDto {
  @ApiProperty({ description: "Mailbox provider key", example: "gmail" })
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  provider!: string

  @ApiProperty({ enum: ["inbox", "spam", "promotions", "missing"] })
  @IsIn(["inbox", "spam", "promotions", "missing"])
  folder!: PlacementFolder

  @ApiPropertyOptional({
    enum: ["primary", "promotions", "social", "updates", "forums"],
    nullable: true,
  })
  @IsOptional()
  @IsIn(["primary", "promotions", "social", "updates", "forums"])
  gmailTab?: GmailTab | null

  @ApiPropertyOptional({
    description: "Receiver-observed spf= verdict (null = not parsed)",
    nullable: true,
  })
  @IsOptional()
  @IsBoolean()
  spfPass?: boolean | null

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsBoolean()
  dkimPass?: boolean | null

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsBoolean()
  dmarcPass?: boolean | null

  @ApiPropertyOptional({
    description: "Send → arrival in seconds (null when missing)",
    nullable: true,
  })
  @IsOptional()
  @IsInt()
  @Min(0)
  latencySecs?: number | null

  @ApiPropertyOptional({
    description: "The seed mailbox address (or a privacy hash)",
    nullable: true,
  })
  @IsOptional()
  @IsString()
  @MaxLength(320)
  seedAddress?: string | null

  @ApiPropertyOptional({
    description: "Why a missing seed never arrived: hard 5xx bounce vs accepted-then-dropped",
    enum: ["bounced", "dropped"],
    nullable: true,
  })
  @IsOptional()
  @IsIn(["bounced", "dropped"])
  missingReason?: "bounced" | "dropped" | null
}

/** One completed seed test (spec §5 `inbox_placement_tests` + children). */
export class RecordSeedTestDto {
  @ApiPropertyOptional({
    description:
      "Seed source ('glockapps' | 'mailtrap' | 'self_hosted' | …); defaults to the configured service",
  })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  seedService?: string

  @ApiPropertyOptional({
    description: "The audited campaign sample tested (null = default template)",
    nullable: true,
  })
  @IsOptional()
  @IsString()
  @MaxLength(200)
  sampleId?: string | null

  @ApiPropertyOptional({
    description:
      "The unique per-test tag (plus-address / X-EDH-Test-Id / subject suffix); generated when absent",
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(200)
  testToken?: string

  @ApiProperty({ description: "ISO date-time the probe was sent" })
  @IsISO8601()
  sentAt!: string

  @ApiPropertyOptional({
    description: "ISO date-time read-back completed (null while polling)",
    nullable: true,
  })
  @IsOptional()
  @IsISO8601()
  settledAt?: string | null

  @ApiProperty({
    type: [SeedResultDto],
    description: "One row per seed — folder + receiver auth verdict",
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => SeedResultDto)
  results!: SeedResultDto[]
}

/** Compact latest-test summary for the panel header ("overall inbox 82% · 40 seeds"). */
interface PlacementTestSummary {
  testToken: string
  seedService: string
  sampleId: string | null
  sentAt: string
  settledAt: string | null
  seedCount: number
  deliveredCount: number
  overallInbox: number | null
}

function summarize(test: InboxPlacementTest): PlacementTestSummary {
  const overall = aggregateOverall(test.results)
  return {
    testToken: test.testToken,
    seedService: test.seedService,
    sampleId: test.sampleId,
    sentAt: test.sentAt,
    settledAt: test.settledAt,
    seedCount: overall.seedCount,
    deliveredCount: overall.delivered,
    overallInbox:
      overall.inboxOfDeliveredPct === null
        ? null
        : Math.round(overall.inboxOfDeliveredPct * 100) / 100,
  }
}

@ApiTags("audit")
@ApiBearerAuth()
@Controller("audit/placement")
export class PlacementController {
  constructor(private readonly domains: DomainsService) {}

  @Get(":domainId")
  @ApiOperation({ summary: "Inbox Placement panel status: config, budget, latest test, trend" })
  status(@Param("domainId") domainId: string): {
    configured: boolean
    service: string
    providers: string[]
    cadence: "daily" | "weekly"
    thresholds: { warnBelowPct: number; criticalBelowPct: number }
    settlePollMinutes: number[]
    budget: { monthly: number; usedThisMonth: number }
    seedsConfigured: number
    latestTest: PlacementTestSummary | null
    tests: PlacementTestSummary[]
    trend: ReturnType<typeof trendSeries>
    sendGate: SeedTestGate
  } {
    this.domains.get(domainId) // 404 for unknown domains
    const cfg = readAppConfig().seedList
    const tests = listPlacementTests(domainId)
    return {
      configured: seedListConfigured(cfg),
      service: cfg.service,
      providers: cfg.providers,
      cadence: cfg.cadence,
      thresholds: cfg.thresholds,
      settlePollMinutes: cfg.settlePollMinutes,
      budget: { monthly: cfg.monthlyBudget, usedThisMonth: testsSentInMonth(tests, new Date()) },
      seedsConfigured: cfg.seeds.filter((s) => s.active).length,
      latestTest: tests[0] ? summarize(tests[0]) : null,
      tests: tests.map(summarize),
      // Oldest → newest overall + per-provider inbox rates — the §4 sparkline series.
      trend: trendSeries(tests),
      sendGate: canSendSeedTest(domainId),
    }
  }

  @Post(":domainId/send-test")
  @RequireRole("admin")
  @ApiOperation({
    summary:
      'The confirmed "Send seed test now" action (spends a credit, sends real mail) — admin-only',
  })
  sendTest(@Param("domainId") domainId: string): never {
    this.domains.get(domainId)
    // Guard rails first (spec §6, acceptance criteria #2/#10): configured → debounce → budget.
    const gate = canSendSeedTest(domainId)
    if (gate.reason === "not_configured") throw new ConflictException(gate.detail)
    if (gate.reason === "debounced" || gate.reason === "budget_exhausted") {
      throw new HttpException(gate.detail, HttpStatus.TOO_MANY_REQUESTS)
    }
    // Allowed — but the probe send itself (seed-service API fan-out, or self-hosted SMTP +
    // IMAP/Graph/JMAP read-back) is the FUTURE integration (spec §7: every sub-check is ⏳).
    // Never pretend mail went out: answer 501 with the concrete next step.
    throw new NotImplementedException(
      "The send-probe capability ships with the seed-service integration. Until it does, record a " +
        "completed seed test read-back via POST /api/audit/placement/:domainId/tests (e.g. exported " +
        "from your seed service's results API); the next audit run scores it.",
    )
  }

  @Post(":domainId/tests")
  @RequireRole("admin")
  @ApiOperation({
    summary:
      "Record one completed seed-test read-back (the test envelope + per-seed folder/auth rows)",
  })
  record(
    @Param("domainId") domainId: string,
    @Body() body: RecordSeedTestDto,
  ): { test: PlacementTestSummary } {
    this.domains.get(domainId)
    const cfg = readAppConfig().seedList
    if (!seedListConfigured(cfg)) {
      throw new ConflictException(
        "Seed-list integration not configured — set config.yaml → seedList.service before recording seed tests.",
      )
    }
    const test: InboxPlacementTest = {
      id: randomUUID(),
      seedService: body.seedService?.trim() || cfg.service,
      sampleId: body.sampleId ?? null,
      // Belt-and-suspenders token (spec §3): generated here when the import omits one.
      testToken: body.testToken?.trim() || `edh-${randomUUID().slice(0, 8)}`,
      sentAt: new Date(body.sentAt).toISOString(),
      settledAt: body.settledAt ? new Date(body.settledAt).toISOString() : null,
      seedCount: body.results.length,
      deliveredCount: body.results.filter((r) => r.folder !== "missing").length,
      overallInbox: null, // recomputed at scoring time — idempotent (spec §3)
      results: body.results.map((r) => ({
        provider: r.provider,
        folder: r.folder,
        gmailTab: r.gmailTab ?? null,
        spfPass: r.spfPass ?? null,
        dkimPass: r.dkimPass ?? null,
        dmarcPass: r.dmarcPass ?? null,
        latencySecs: r.latencySecs ?? null,
        seedAddress: r.seedAddress ?? null,
        missingReason: r.missingReason ?? null,
      })),
    }
    return { test: summarize(recordPlacementTest(domainId, test)) }
  }
}
