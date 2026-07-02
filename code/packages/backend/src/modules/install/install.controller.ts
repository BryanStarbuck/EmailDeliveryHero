import {
	BadRequestException,
	Body,
	Controller,
	Get,
	NotFoundException,
	Param,
	Post,
	Query,
	Sse,
} from "@nestjs/common";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { map, type Observable } from "rxjs";
import { catalogEntry, type ToolManager, type ToolStatus } from "./catalog";
import type { InstallService } from "./install.service";
import type {
	InstallJobAccepted,
	InstallJobStatus,
	PreflightResult,
} from "./install.types";

function asManager(v: unknown): ToolManager | "all" {
	return v === "brew" || v === "npm" ? v : "all";
}

/**
 * The Install API (pm/install_brew.mdx §7.1, pm/install_npm.mdx §6). All signed-in (usable by the
 * `default` user — installing local CLI tools on your own machine is the app's core job). The
 * `tools:install` permission hook is the single-decorator way to lock this down if a deployment
 * wants to.
 */
@ApiTags("install")
@ApiBearerAuth()
@Controller("install")
export class InstallController {
	constructor(private readonly install: InstallService) {}

	@Get("catalog")
  @ApiOperation({
    summary: "The tool catalog (brew/npm/all) with live installed status merged in.",
  })
  catalog(@Query("manager") manager?: string): ToolStatus[] {
    return this.install.catalog(asManager(manager))
  }

	@Get("preflight")
	@ApiOperation({
		summary:
			"Scope-aware missing / optional / installed split for a pending run.",
	})
	preflight(
		@Query("manager") manager?: string,
		@Query("scope") scope?: string,
	): PreflightResult {
		return this.install.preflight(asManager(manager), scope);
	}

	@Post("detect")
  @ApiOperation({ summary: "Force a fresh detection (Re-detect)." })
  detect(@Query("manager") manager?: string): ToolStatus[] {
    return this.install.detect(asManager(manager))
  }

	@Post("run")
  @ApiOperation({ summary: "Install the selected ids serially; returns a jobId to stream/poll." })
  run(@Body() body: { ids?: unknown }): InstallJobAccepted {
    const ids = Array.isArray(body?.ids)
      ? body.ids.filter((x): x is string => typeof x === "string")
      : []
    if (ids.length === 0) throw new BadRequestException("ids must be a non-empty string array")
    // Every id must be a known, auto-installable catalog entry (§12).
    for (const id of ids) {
      const entry = catalogEntry(id)
      if (!entry) throw new BadRequestException(`unknown tool id: ${id}`)
    }
    return this.install.start(ids)
  }

	@Get("run/:jobId")
  @ApiOperation({ summary: "Coarse job status + settled summary (poll fallback for the stream)." })
  jobStatus(@Param("jobId") jobId: string): InstallJobStatus {
    const status = this.install.status(jobId)
    if (!status) throw new NotFoundException("unknown jobId")
    return status
  }

	@Sse("run/:jobId/stream")
  @ApiOperation({
    summary: "SSE stream of per-row install output (missing→installing→done/failed).",
  })
  jobStream(@Param("jobId") jobId: string): Observable<{ data: string }> {
    const subject = this.install.stream(jobId)
    if (!subject) throw new NotFoundException("unknown jobId")
    return subject.pipe(map((event) => ({ data: JSON.stringify(event) })))
  }
}
