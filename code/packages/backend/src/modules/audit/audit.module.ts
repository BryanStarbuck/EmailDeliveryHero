import { Module } from "@nestjs/common"
import { DomainsModule } from "@module/domains/domains.module"
import { AuditController } from "./audit.controller"
import { AuditSchedulerService } from "./audit-scheduler.service"
import { AuditService } from "./audit.service"

@Module({
  imports: [DomainsModule],
  controllers: [AuditController],
  providers: [AuditService, AuditSchedulerService],
  exports: [AuditService],
})
export class AuditModule {}
