import { RequireRole } from "@module/auth/roles.decorator";
import {
	Body,
	Controller,
	ForbiddenException,
	Get,
	Headers,
	Post,
	Put,
} from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import type {
	OsArtifactPreview,
	RunTrigger,
	ScheduleConfig,
	SchedulerRunOutcome,
	SchedulerStatus,
} from "./schedule.types";
import { SchedulerService } from "./scheduler.service";

/**
 * The scheduled-checks API (pm/scheduled_checks.mdx §"API"): status + config for the dashboard
 * toggle and the configuration page, POST /run for the OS-level artifacts (launchd/cron/systemd/
 * schtasks) and the dashboard "Run checks" button, and the os/ trio that previews/installs/removes
 * the native schedule. Reads (status, config, os/preview) and POST /run stay open — the OS artifacts
 * call POST /run with no token, which proceeds as the `default` user. The state-changing routes that
 * write config or install/remove a native OS scheduler entry are admin-gated (@RequireRole("admin"))
 * so an anonymous caller cannot rewrite the schedule or register/unregister a LaunchAgent
 * (security audit finding #2).
 */
@ApiTags("scheduler")
@ApiBearerAuth()
@Controller("scheduler")
export class SchedulerController {
	constructor(private readonly scheduler: SchedulerService) {}

	@Get()
	@ApiOperation({
		summary:
			"Scheduler status: enabled, runner, nextRunAt, lastRunAt, OS install",
	})
	status(): SchedulerStatus {
		return this.scheduler.status();
	}

	@Get("config")
	@ApiOperation({
		summary: "Read the persisted schedule: block (backs the config page)",
	})
	getConfig(): ScheduleConfig {
		return this.scheduler.getConfig();
	}

	@Put("config")
  @RequireRole("admin")
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
  run(
    @Headers("x-requested-with") requestedWith: string | undefined,
    @Headers("x-edh-trigger") edhTrigger: string | undefined,
    @Body() body?: { trigger?: string; force?: boolean },
  ): Promise<SchedulerRunOutcome> {
    // This route stays open (the OS scheduler calls it with no auth token), so it must not be a
    // CORS-"simple" request a hostile page could fire cross-origin without a preflight (security
    // audit finding #9). Require a custom header that only same-origin app callers (X-Requested-With,
    // set by the axios client) or the OS trigger scripts (X-EDH-Trigger) send — a cross-origin
    // browser fetch cannot set either without triggering a (CORS-blocked) preflight.
    if (!requestedWith && !edhTrigger) {
      throw new ForbiddenException(
        "Missing required X-Requested-With or X-EDH-Trigger header",
      )
    }
    const trigger: RunTrigger = body?.trigger === "os" ? "os" : "manual"
    return this.scheduler.runNow(trigger, body?.force === true)
  }

	@Get("os/preview")
	@ApiOperation({
		summary: "The rendered native schedule artifact for the detected OS",
	})
	preview(): OsArtifactPreview {
		return this.scheduler.preview();
	}

	@Post("os/install")
	@RequireRole("admin")
	@ApiOperation({
		summary: "Write + load the native OS schedule; marks os.installed",
	})
	install(): Promise<ScheduleConfig> {
		return this.scheduler.install();
	}

	@Post("os/uninstall")
	@RequireRole("admin")
	@ApiOperation({ summary: "Unload + remove the native OS schedule" })
	uninstall(): Promise<ScheduleConfig> {
		return this.scheduler.uninstall();
	}
}
