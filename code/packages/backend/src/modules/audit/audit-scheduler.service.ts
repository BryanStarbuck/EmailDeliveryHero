import { Injectable, type OnModuleDestroy, type OnModuleInit } from "@nestjs/common"
import { logError, logInfo } from "@shared/logging"
import { AuditService } from "./audit.service"

/**
 * Periodic re-audits. When EDH_PERIODIC_AUDIT_MINUTES is set to a positive number, every monitored
 * domain is re-audited on that interval so newly-introduced problems (a record that got deleted, a
 * fresh blacklist listing) surface without anyone clicking "Run". Off by default; a single-instance
 * localhost app only needs a plain interval, not a job queue.
 */
@Injectable()
export class AuditSchedulerService implements OnModuleInit, OnModuleDestroy {
  private timer: NodeJS.Timeout | null = null

  constructor(private readonly audit: AuditService) {}

  onModuleInit(): void {
    const minutes = Number(process.env.EDH_PERIODIC_AUDIT_MINUTES ?? "0")
    if (!Number.isFinite(minutes) || minutes <= 0) {
      logInfo("Periodic audits disabled (set EDH_PERIODIC_AUDIT_MINUTES to enable)", "AuditScheduler")
      return
    }
    const intervalMs = minutes * 60 * 1000
    logInfo(`Periodic audits enabled: every ${minutes} minute(s)`, "AuditScheduler")
    this.timer = setInterval(() => {
      this.audit
        .runForAll()
        .catch((err) => logError("Periodic audit run failed", err, "AuditScheduler"))
    }, intervalMs)
    // Don't keep the event loop alive solely for the timer.
    this.timer.unref?.()
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer)
  }
}
