import { AuditModule } from "@module/audit/audit.module"
import { DomainsModule } from "@module/domains/domains.module"
import { Module } from "@nestjs/common"
import { SchedulerController } from "./scheduler.controller"
import { SchedulerService } from "./scheduler.service"

@Module({
  imports: [AuditModule, DomainsModule],
  controllers: [SchedulerController],
  providers: [SchedulerService],
})
export class SchedulerModule {}
