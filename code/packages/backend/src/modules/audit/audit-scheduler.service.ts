import { Injectable, type OnModuleDestroy, type OnModuleInit } from "@nestjs/common"
import { readAppConfig } from "@shared/config-store"
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
      logInfo(
        "Periodic audits disabled (set EDH_PERIODIC_AUDIT_MINUTES to enable)",
        "AuditScheduler",
      )
      return
    }
    const intervalMs = minutes * 60 * 1000
    logInfo(`Periodic audits enabled: every ${minutes} minute(s)`, "AuditScheduler")
    this.timer = setInterval(() => {
      // The master on/off switch (config.yaml → schedule.enabled, pm/storage.mdx §3/§5): a domain
      // runs on schedule only when this global flag AND its own scheduleEnabled are both true (the
      // per-domain half is filtered inside runForAll("scheduled")).
      if (!readAppConfig().schedule.enabled) {
        logInfo("Scheduled check run skipped (schedule.enabled is off)", "AuditScheduler")
        return
      }
      // runForAll("scheduled") writes the "Scheduled check run started (<n> domain(s))" line with
      // the domain count; the finish line is logged here (pm/errors.mdx §4).
      this.audit
        .runForAll("scheduled")
        .then(() => logInfo("Scheduled check run finished", "AuditScheduler"))
        .catch((err) => logError("Scheduled check run failed", err, "AuditScheduler"))
    }, intervalMs)
    // Don't keep the event loop alive solely for the timer.
    this.timer.unref?.()
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer)
  }
}
