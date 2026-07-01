import { Controller, Get, NotFoundException, Param, Post } from "@nestjs/common"
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger"
import { AuditService } from "./audit.service"
import type { AuditResult } from "./checks/types"

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

  @Post("run/:domainId")
  @ApiOperation({ summary: "Run a fresh deliverability audit for one domain" })
  run(@Param("domainId") domainId: string): Promise<AuditResult> {
    return this.audit.runForDomain(domainId)
  }

  @Post("run")
  @ApiOperation({ summary: "Run a fresh audit for every monitored domain" })
  runAll(): Promise<AuditResult[]> {
    return this.audit.runForAll()
  }
}
