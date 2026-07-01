import { DomainsModule } from "@module/domains/domains.module"
import { Module } from "@nestjs/common"
import { AuditController } from "./audit.controller"
import { AuditService } from "./audit.service"
import { AuditSchedulerService } from "./audit-scheduler.service"

@Module({
  imports: [DomainsModule],
  controllers: [AuditController],
  providers: [AuditService, AuditSchedulerService],
  exports: [AuditService],
})
export class AuditModule {}
