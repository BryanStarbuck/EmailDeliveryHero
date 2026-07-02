import { DomainsModule } from "@module/domains/domains.module"
import { Module } from "@nestjs/common"
import { ReportsController } from "./reports.controller"
import { ReportsService } from "./reports.service"

/**
 * Report-email ingestion (pm/emails.mdx) — DMARC aggregate (rua) XML + TLS-RPT JSON reports:
 * the drop-folder/mailbox poller, the on-demand ingest endpoint, and the per-domain Reports view.
 * The derived findings themselves surface through the audit engine (checks/dmarc-reports and
 * checks/tls-rpt read the same report store), so they roll into the six locked dashboard
 * categories with no special path.
 */
@Module({
  imports: [DomainsModule],
  controllers: [ReportsController],
  providers: [ReportsService],
  exports: [ReportsService],
})
export class ReportsModule {}
