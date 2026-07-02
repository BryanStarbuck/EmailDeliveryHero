import { Body, Controller, Get, Post, Put } from "@nestjs/common"
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger"
import type {
  OsArtifactPreview,
  RunTrigger,
  ScheduleConfig,
  SchedulerRunOutcome,
  SchedulerStatus,
} from "./schedule.types"
import { SchedulerService } from "./scheduler.service"

/**
 * The scheduled-checks API (pm/scheduled_checks.mdx §"API"): status + config for the dashboard
 * toggle and the configuration page, POST /run for the OS-level artifacts (launchd/cron/systemd/
 * schtasks) and the dashboard "Run checks" button, and the os/ trio that previews/installs/removes
 * the native schedule. Auth follows the app-wide "identify, don't gate" model — the OS artifacts
 * call POST /run with no token, which proceeds as the `default` user.
 */
@ApiTags("scheduler")
@ApiBearerAuth()
@Controller("scheduler")
export class SchedulerController {
  constructor(private readonly scheduler: SchedulerService) {}

  @Get()
  @ApiOperation({ summary: "Scheduler status: enabled, runner, nextRunAt, lastRunAt, OS install" })
  status(): SchedulerStatus {
    return this.scheduler.status()
  }

  @Get("config")
  @ApiOperation({ summary: "Read the persisted schedule: block (backs the config page)" })
  getConfig(): ScheduleConfig {
    return this.scheduler.getConfig()
  }

  @Put("config")
  @ApiOperation({ summary: "Merge + persist the schedule: block; re-arms the active runner" })
  updateConfig(@Body() patch: Record<string, unknown>): Promise<ScheduleConfig> {
    return this.scheduler.updateConfig(patch ?? {})
  }

  @Post("run")
  @ApiOperation({
    summary:
      "Trigger a scheduled audit now. Honors the master switch (skips when scheduling is off) " +
      "and dedupes double-fires unless the body carries force: true (pm/settings.mdx §3.3).",
  })
  run(@Body() body?: { trigger?: string; force?: boolean }): Promise<SchedulerRunOutcome> {
    const trigger: RunTrigger = body?.trigger === "os" ? "os" : "manual"
    return this.scheduler.runNow(trigger, body?.force === true)
  }

  @Get("os/preview")
  @ApiOperation({ summary: "The rendered native schedule artifact for the detected OS" })
  preview(): OsArtifactPreview {
    return this.scheduler.preview()
  }

  @Post("os/install")
  @ApiOperation({ summary: "Write + load the native OS schedule; marks os.installed" })
  install(): Promise<ScheduleConfig> {
    return this.scheduler.install()
  }

  @Post("os/uninstall")
  @ApiOperation({ summary: "Unload + remove the native OS schedule" })
  uninstall(): Promise<ScheduleConfig> {
    return this.scheduler.uninstall()
  }
}
