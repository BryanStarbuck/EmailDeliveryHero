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
import { RequireRole } from "@module/auth/roles.decorator";
import { ApiBearerAuth, ApiOperation, ApiTags } from "@nestjs/swagger";
import { map, type Observable } from "rxjs";
import { catalogEntry, type ToolManager, type ToolStatus } from "./catalog";
import { InstallService } from "./install.service";
import type {
	InstallJobAccepted,
	InstallJobStatus,
	PreflightResult,
} from "./install.types";

function asManager(v: unknown): ToolManager | "all" {
	return v === "brew" || v === "npm" ? v : "all";
}

/**
 * The Install API (pm/install_brew.mdx §7.1, pm/install_npm.mdx §6).
 *
 * Split gate. Installing host CLI tools runs package-manager processes (brew/npm/pipx) — with
 * maintainer post-install scripts — as the service account, so the routes that ACTUALLY install or
 * shell out stay admin-gated (@RequireRole("admin")), which is what closes the unauthenticated
 * remote-install surface (security audit finding #1).
 *
 * The read-only routes (catalog / preflight / job status / job stream) are OPEN. They only report
 * which tools are already present, and `GET /preflight` sits on the critical path of every run:
 * gating the whole controller meant the logged-out `default` user could not start a check at all,
 * which contradicts pm/security.mdx §6 and AC 1. Never rely on the UI hiding the page — the
 * backend is authoritative.
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
	@RequireRole("admin")
  @ApiOperation({ summary: "Force a fresh detection (Re-detect)." })
  detect(@Query("manager") manager?: string): ToolStatus[] {
    return this.install.detect(asManager(manager))
  }

	@Post("run")
	@RequireRole("admin")
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
