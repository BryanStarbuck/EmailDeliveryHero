import { DomainsModule } from "@module/domains/domains.module";
import { Module } from "@nestjs/common";
import { AuditController } from "./audit.controller";
import { AuditService } from "./audit.service";
import { ContentSampleController } from "./content-sample.controller";
import { PlacementController } from "./placement.controller";

// Periodic re-audits live in the scheduler module (pm/settings.mdx §3.3): SchedulerService arms
// the in-process timer from config.yaml's schedule: block. The old EDH_PERIODIC_AUDIT_MINUTES
// env interval (AuditSchedulerService) is retired — two in-process schedulers would double-fire.
@Module({
	imports: [DomainsModule],
	controllers: [AuditController, ContentSampleController, PlacementController],
	providers: [AuditService],
	exports: [AuditService],
})
export class AuditModule {}
