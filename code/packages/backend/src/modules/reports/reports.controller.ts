import { Controller, Get, Param, Post } from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import type { IngestSummary } from "./report.types";
import type { DomainReportsView, ReportsService } from "./reports.service";

/**
 * The report-email ingestion API (pm/emails.mdx §7.1/§10):
 *
 *   GET  /api/domains/:id/reports         — the per-domain Reports view (aggregates + findings)
 *   POST /api/domains/:id/reports/ingest  — "Ingest now": on-demand mailbox/drop-folder scan
 *
 * Reports route by the payload's own policy domain, so one ingest pass serves every monitored
 * domain — the :id on the ingest route scopes the RESPONSE view, not the scan.
 */
@ApiTags("reports")
@ApiBearerAuth()
@Controller("domains/:id/reports")
export class ReportsController {
	constructor(private readonly reports: ReportsService) {}

	@Get()
  @ApiOperation({ summary: "Ingested DMARC-aggregate / TLS-RPT report view for one domain" })
  view(@Param("id") id: string): DomainReportsView {
    return this.reports.view(id)
  }

	@Post("ingest")
  @ApiOperation({ summary: "Ingest now — scan the report drop folder / mailbox on demand" })
  async ingest(
    @Param("id") id: string,
  ): Promise<{ summary: IngestSummary; view: DomainReportsView }> {
    const summary = await this.reports.ingest()
    return { summary, view: this.reports.view(id) }
  }
}
