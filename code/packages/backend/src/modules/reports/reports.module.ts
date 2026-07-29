import { DomainsModule } from "@module/domains/domains.module";
import { Module } from "@nestjs/common";
import {
	ComplaintsController,
	ComplaintsService,
	FleetComplaintsController,
	RunComplaintsController,
} from "./complaints.controller";
import { ReportsController } from "./reports.controller";
import { ReportsService } from "./reports.service";

/**
 * Report-email ingestion (pm/emails.mdx) — DMARC aggregate (rua) XML + TLS-RPT JSON reports:
 * the drop-folder/mailbox poller, the on-demand ingest endpoint, and the per-domain Reports view.
 * The derived findings themselves surface through the audit engine (checks/dmarc-reports and
 * checks/tls-rpt read the same report store), so they roll into the six locked dashboard
 * categories with no special path.
 */
@Module({
	imports: [DomainsModule],
	// ComplaintsController is registered AFTER ReportsController: both live under
	// /domains/:id/…, and Nest matches in declaration order.
	// RunComplaintsController owns /domains/:id/runs/:runId/complaints — a distinct path, so its
	// order relative to ComplaintsController does not matter, but it is listed alongside it.
	// FleetComplaintsController owns the flat /complaints path (the left bar's fleet view) — no
	// overlap with the /domains/:id/… controllers, so declaration order is immaterial for it.
	controllers: [
		ReportsController,
		ComplaintsController,
		RunComplaintsController,
		FleetComplaintsController,
	],
	providers: [ReportsService, ComplaintsService],
	exports: [ReportsService, ComplaintsService],
})
export class ReportsModule {}
