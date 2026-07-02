import { DomainsService } from "@module/domains/domains.service"
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  NotFoundException,
  Param,
  Post,
  Put,
} from "@nestjs/common"
import { ApiBearerAuth, ApiOperation, ApiProperty, ApiTags } from "@nestjs/swagger"
import { IsString, MaxLength, MinLength } from "class-validator"
import { AuditService } from "./audit.service"
import {
  type ContentSampleRecord,
  getActiveSample,
  listSamples,
  MAX_SAMPLE_BYTES,
  readSampleRaw,
  saveSample,
} from "./checks/content-scoring/sample-store"
import type { AuditResult } from "./checks/types"

/** Upload/paste body: the raw RFC 5322 source of a representative message (.eml). */
export class ContentSampleUploadDto {
  @ApiProperty({
    description: "Raw RFC 5322 message source (headers + body) — the .eml contents",
    example: "From: noreply@shop.example.com\r\nSubject: Q3 SALE\r\n\r\nHello…",
  })
  @IsString()
  @MinLength(1)
  @MaxLength(MAX_SAMPLE_BYTES)
  raw!: string
}

/** The snake_case API row for one stored sample (pm/checks/content_scoring.mdx §5). */
export interface ContentSampleView {
  id: string
  domain_id: string
  uploaded_at: string
  from_header: string | null
  subject: string | null
  active: boolean
  byte_size: number
  /** Where the .eml lives in the file store (shown on the Sample-message panel, §4). */
  raw_path: string | null
}

function toView(s: ContentSampleRecord): ContentSampleView {
  return {
    id: s.id,
    domain_id: s.domainId,
    uploaded_at: s.uploadedAt,
    from_header: s.fromHeader,
    subject: s.subject,
    active: s.active,
    byte_size: s.byteSize,
    raw_path: s.rawPath,
  }
}

/**
 * The per-domain sample-message API (pm/checks/content_scoring.mdx §4 "Sample message" panel):
 * upload/paste the raw .eml that content scoring grades, read it back, and trigger the dedicated
 * Re-score action that re-runs just the content checker without a full re-audit (§6).
 */
@ApiTags("audit")
@ApiBearerAuth()
@Controller("audit/content-sample")
export class ContentSampleController {
  constructor(
    private readonly audit: AuditService,
    private readonly domains: DomainsService,
  ) {}

  @Get(":domainId")
  @ApiOperation({ summary: "The domain's active sample message + upload history" })
  get(@Param("domainId") domainId: string): {
    sample: ContentSampleView | null
    history: ContentSampleView[]
  } {
    this.domains.get(domainId) // 404 for unknown domains
    const active = getActiveSample(domainId)
    return {
      sample: active ? toView(active) : null,
      history: listSamples(domainId).map(toView),
    }
  }

  @Put(":domainId")
  @ApiOperation({ summary: "Upload/paste a new sample .eml (becomes the active scored sample)" })
  upload(
    @Param("domainId") domainId: string,
    @Body() body: ContentSampleUploadDto,
  ): { sample: ContentSampleView } {
    this.domains.get(domainId)
    try {
      return { sample: toView(saveSample(domainId, body.raw)) }
    } catch (err) {
      throw new BadRequestException(err instanceof Error ? err.message : String(err))
    }
  }

  @Get(":domainId/raw")
  @ApiOperation({ summary: "The active sample's raw RFC 5322 source (View raw .eml)" })
  raw(@Param("domainId") domainId: string): { raw: string } {
    this.domains.get(domainId)
    const active = getActiveSample(domainId)
    if (!active) throw new NotFoundException(`No sample message for domain ${domainId}`)
    const raw = readSampleRaw(active)
    if (raw === null) throw new NotFoundException("The stored sample file is missing")
    return { raw }
  }

  @Post(":domainId/rescore")
  @ApiOperation({ summary: "Re-score just the content check (no full re-audit)" })
  rescore(@Param("domainId") domainId: string): Promise<AuditResult> {
    return this.audit.rescoreContent(domainId)
  }
}
