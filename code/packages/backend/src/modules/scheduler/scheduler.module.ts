import { AuditModule } from "@module/audit/audit.module"
import { DomainsModule } from "@module/domains/domains.module"
import { Module } from "@nestjs/common"
import { SchedulerController } from "./scheduler.controller"
import { SchedulerService } from "./scheduler.service"

@Module({
  imports: [AuditModule, DomainsModule],
  controllers: [SchedulerController],
  providers: [SchedulerService],
  // Exported for the settings module: admin writes that include a `schedule` patch delegate here
  // so the in-process timer re-arms on save (pm/settings.mdx §3.3).
  exports: [SchedulerService],
})
export class SchedulerModule {}
