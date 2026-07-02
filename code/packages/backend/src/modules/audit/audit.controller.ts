import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  NotFoundException,
  Param,
  Post,
  Query,
} from "@nestjs/common"
import {
  ApiBearerAuth,
  ApiOperation,
  ApiProperty,
  ApiPropertyOptional,
  ApiTags,
} from "@nestjs/swagger"
import { IsInt, IsOptional, IsString, Max, MaxLength, Min, MinLength } from "class-validator"
import { AuditService, type SpotCheckResult } from "./audit.service"
import { type GeneratedTlsaRecord, generateTlsa311 } from "./checks/dane-tlsa/tlsa-generator"
import type { DkimDiscoveryOutcome } from "./checks/dkim/dkim.check"
import type { AuditResult } from "./checks/types"

/**
 * POST /api/audit/tlsa-record body (pm/checks/dane_tlsa.mdx §4): the DANE subsection's one-click
 * generator — given a pasted PEM certificate it emits the exact `3 1 1` (DANE-EE / SPKI /
 * SHA-256) record to publish at `_25._tcp.<mx-host>`. The probed-cert input path is FUTURE.
 */
export class GenerateTlsaDto {
  @ApiProperty({ description: "The MX hostname the record is for, e.g. mail.example.com" })
  @IsString()
  @MinLength(1)
  @MaxLength(253)
  mxHost!: string

  @ApiProperty({ description: "The MX's TLS certificate as PEM (-----BEGIN CERTIFICATE----- …)" })
  @IsString()
  @MinLength(1)
  @MaxLength(65536)
  pem!: string

  @ApiPropertyOptional({ description: "Record TTL in seconds (default 3600)" })
  @IsOptional()
  @IsInt()
  @Min(0)
  @Max(604800)
  ttl?: number
}

@ApiTags("audit")
@ApiBearerAuth()
@Controller("audit")
export class AuditController {
  constructor(private readonly audit: AuditService) {}

  @Get("results")
  @ApiOperation({ summary: "Latest audit result for every monitored domain (dashboard)" })
  latestAll(): AuditResult[] {
    return this.audit.latestAll()
  }

  @Get("results/:domainId")
  @ApiOperation({ summary: "Latest audit result for one domain" })
  latest(@Param("domainId") domainId: string): AuditResult {
    const result = this.audit.latest(domainId)
    if (!result) throw new NotFoundException(`No audit yet for domain ${domainId}`)
    return result
  }

  @Get("runs")
  @ApiOperation({ summary: "Run history, newest first (dashboard Runs table)" })
  runs(@Query("domainId") domainId?: string): AuditResult[] {
    return this.audit.listRuns(domainId)
  }

  @Get("runs/:runId")
  @ApiOperation({ summary: "One run in full (the run report)" })
  getRun(@Param("runId") runId: string): AuditResult {
    const run = this.audit.getRun(runId)
    if (!run) throw new NotFoundException(`No run ${runId}`)
    return run
  }

  @Delete("runs/:runId")
  @ApiOperation({ summary: "Remove one run from the history" })
  async deleteRun(@Param("runId") runId: string): Promise<{ ok: true }> {
    await this.audit.deleteRun(runId)
    return { ok: true }
  }

  @Post("run/:domainId")
  @ApiOperation({ summary: "Run a fresh deliverability audit for one domain" })
  run(@Param("domainId") domainId: string): Promise<AuditResult> {
    // Trigger #1/#2 (pm/run_checks.mdx §1): the UI's per-domain fan-out and row buttons.
    return this.audit.runForDomain(domainId, "manual")
  }

  @Post("run/:domainId/blacklists")
  @ApiOperation({
    summary:
      "Category-scoped re-run: execute only the Blacklists category and write a new run file with run.scope: blacklists (pm/checks/blacklists.mdx §21 / AC 26)",
  })
  runBlacklists(@Param("domainId") domainId: string): Promise<AuditResult> {
    return this.audit.runBlacklistsForDomain(domainId, "manual")
  }

  @Post("run/:domainId/checks/dkim")
  @ApiOperation({
    summary:
      "Category-scoped re-run: execute only the DKIM checker and persist a new run whose other five categories are carried forward unchanged (pm/checks/dkim.mdx §7.7 — 'Run DKIM now')",
  })
  runDkim(@Param("domainId") domainId: string): Promise<AuditResult> {
    return this.audit.runDkimForDomain(domainId, "manual")
  }

  @Post("spot-check/:domainId/:checkKey")
  @ApiOperation({
    summary:
      "Re-run one DNS & Infrastructure family checker live (pm/checks/dns.mdx §6.2 — the ⟳ spot-check / 'run this check now'); never persisted",
  })
  async spotCheck(
    @Param("domainId") domainId: string,
    @Param("checkKey") checkKey: string,
  ): Promise<SpotCheckResult> {
    try {
      return await this.audit.spotCheck(domainId, checkKey)
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      if (message.startsWith("Unknown DNS & Infrastructure check")) {
        throw new BadRequestException(message)
      }
      throw err
    }
  }

  @Post("dkim-discovery/:domainId")
  @ApiOperation({
    summary:
      "Probe the MX-guided common-DKIM-selector wordlist for one domain and return the hits for one-click import (pm/checks/dkim.mdx §6.2 item 6 — 'Run discovery now'); never persisted",
  })
  dkimDiscovery(@Param("domainId") domainId: string): Promise<DkimDiscoveryOutcome> {
    return this.audit.dkimDiscovery(domainId)
  }

  @Post("tlsa-record")
  @ApiOperation({
    summary:
      "Generate the `3 1 1` TLSA record for an MX host from a pasted PEM certificate (pm/checks/dane_tlsa.mdx §4 — the DANE subsection's one-click generator)",
  })
  generateTlsaRecord(@Body() body: GenerateTlsaDto): GeneratedTlsaRecord {
    try {
      return generateTlsa311(body.pem, body.mxHost, body.ttl)
    } catch (err) {
      throw new BadRequestException(err instanceof Error ? err.message : String(err))
    }
  }

  @Post("run")
  @ApiOperation({ summary: "Run a fresh audit for every monitored domain" })
  runAll(): Promise<AuditResult[]> {
    // Trigger #5 (pm/run_checks.mdx §1): programmatic audit-all, one response. Deprecated for the
    // UI — the dashboard fans out per-domain requests instead (pm/progress_ui.mdx §4.1).
    return this.audit.runForAll("api")
  }
}
