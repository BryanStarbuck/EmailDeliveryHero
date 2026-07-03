import {
	BadRequestException,
	Body,
	Controller,
	Get,
	NotFoundException,
	Param,
	Patch,
	Post,
} from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import {
	IsArray,
	IsBoolean,
	IsIn,
	IsNumber,
	IsOptional,
	IsString,
	Max,
	Min,
} from "class-validator";
import type {
	BlacklistHistoryEntry,
	BlacklistRunResults,
	BlocklistZone,
	PortalUserState,
	ProviderPortal,
} from "../audit/checks/blacklist/blacklist-types";
import {
	type LiveRecheckResult,
	liveRecheck,
	RecheckInputError,
} from "../audit/checks/blacklist/recheck";
import {
	applyPortalStates,
	listBlacklistDomains,
	readBlacklistHistory,
	readLatestBlacklistRun,
	writePortalState,
} from "../audit/checks/blacklist/store";
import {
	type BlacklistRegistry,
	isDeadZone,
	loadRegistry,
	loadZones,
	PROVIDER_PORTALS,
	saveZoneOverride,
} from "../audit/checks/blacklist/zones";
import { DomainsService } from "../domains/domains.service";

/** The effective registry view served to the §17 dashboard and the Blocklist Zones admin panel. */
export interface BlacklistRegistryInfo {
	compiled: string;
	/** Every entry in the checked-in registry, including web-only and disabled lists. */
	lists_total: number;
	/** The effective queryable catalog (registry defaults ⊕ operator overrides, dead zones excluded). */
	zones: BlocklistZone[];
	dead_zones: BlacklistRegistry["dead_zones"];
	aggregators: BlacklistRegistry["aggregators"];
}

/**
 * The Blacklists technology API (pm/checks/blacklists.mdx §13). Serves the per-run
 * test_results.yaml documents the checker persists (latest + history) and the per-domain
 * provider-portal checklist state. Domains are keyed by domain NAME (what the checker knows),
 * not the internal domain id.
 */

export class UpdatePortalStateDto {
	@IsString()
	@IsIn(["unverified", "verified_clean", "problem_reported"])
	state!: PortalUserState;
}

/** Operator-editable zone fields (the §4 admin "Blocklist Zones" panel writes overrides). */
export class UpdateZoneDto {
	@IsOptional()
	@IsBoolean()
	enabled?: boolean;

	@IsOptional()
	@IsNumber()
	@Min(0)
	@Max(1)
	weight?: number;

	/** Scope the override to one row of a type:both zone; omitted = both its ip and domain rows. */
	@IsOptional()
	@IsString()
	@IsIn(["ip", "domain"])
	kind?: "ip" | "domain";
}

/** Body of the §21.3 live recheck (AC 27): optional zone-host and target scoping. */
export class RecheckDto {
	@IsOptional()
	@IsArray()
	@IsString({ each: true })
	zones?: string[];

	@IsOptional()
	@IsArray()
	@IsString({ each: true })
	targets?: string[];
}

@ApiTags("blacklists")
@Controller("blacklists")
export class BlacklistsController {
	constructor(private readonly domains: DomainsService) {}

	/**
	 * The store keys blacklist runs by domain NAME; the spec's routes carry `:domainId`. Accept
	 * either — a monitored-domain id resolves to its name, anything else passes through as a name.
	 */
	private resolveDomainName(param: string): string {
		return this.domains.list().find((d) => d.id === param)?.name ?? param;
	}
	@Get("zones")
	@ApiOperation({
		summary:
			"The effective blocklist registry — checked-in blacklists.yaml merged with operator overrides",
	})
	zones(): BlacklistRegistryInfo {
		const reg = loadRegistry();
		return {
			compiled: reg.compiled,
			lists_total: reg.blacklists.length,
			zones: loadZones(),
			dead_zones: reg.dead_zones,
			aggregators: reg.aggregators,
		};
	}

	@Patch("zones/:zone")
	@ApiOperation({
		summary:
			"Update one zone's operator override (enabled/weight) — writes <stateDir>/blacklist_zones.yaml, never the checked-in registry",
	})
	updateZone(
		@Param("zone") zone: string,
		@Body() body: UpdateZoneDto,
	): BlacklistRegistryInfo {
		if (isDeadZone(zone)) {
			throw new BadRequestException(
				`Zone "${zone}" is on the dead_zones registry (pm/checks/blacklists.mdx §9.5) and can never be enabled.`,
			);
		}
		try {
			saveZoneOverride(zone, {
				...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
				...(body.weight !== undefined ? { weight: body.weight } : {}),
				...(body.kind !== undefined ? { kind: body.kind } : {}),
			});
		} catch (err) {
			if (err instanceof Error && err.message.startsWith("unknown zone")) {
				throw new NotFoundException(`Unknown blocklist zone: ${zone}`);
			}
			throw err;
		}
		return this.zones();
	}

	@Get("results")
	@ApiOperation({
		summary: "Latest blacklist run for every domain that has one",
	})
	latestAll(): BlacklistRunResults[] {
		const runs: BlacklistRunResults[] = [];
		for (const domain of listBlacklistDomains()) {
			const run = readLatestBlacklistRun(domain);
			if (run) runs.push(run);
		}
		return runs.sort((a, b) => a.domain.localeCompare(b.domain));
	}

	@Get("results/:domain")
  @ApiOperation({ summary: "Latest blacklist run for one domain" })
  latest(@Param("domain") domain: string): BlacklistRunResults {
    const run = readLatestBlacklistRun(domain)
    if (!run) throw new NotFoundException(`No blacklist run recorded for ${domain}`)
    return run
  }

	@Get("results/:domain/history")
  @ApiOperation({ summary: "Per-run summary history (powers the sparkline)" })
  history(@Param("domain") domain: string): BlacklistHistoryEntry[] {
    return readBlacklistHistory(domain)
  }

	@Post(":domainId/recheck")
	@ApiOperation({
		summary:
			"Live recheck (pm/checks/blacklists.mdx §21.3 / AC 27): re-query selected zones/targets ephemerally — pinned resolver, 5 s timeout, concurrency 8, refusal codes → inconclusive — WITHOUT writing a run file",
	})
	async recheck(
		@Param("domainId") domainId: string,
		@Body() body: RecheckDto,
	): Promise<LiveRecheckResult> {
		try {
			return await liveRecheck(this.resolveDomainName(domainId), {
				...(body.zones ? { zones: body.zones } : {}),
				...(body.targets ? { targets: body.targets } : {}),
			});
		} catch (err) {
			if (err instanceof RecheckInputError)
				throw new BadRequestException(err.message);
			throw err;
		}
	}

	@Patch(":domain/portals/:provider")
	@ApiOperation({ summary: "Set the user's provider-portal checklist state" })
	async setPortalState(
		@Param("domain") domain: string,
		@Param("provider") provider: string,
		@Body() body: UpdatePortalStateDto,
	): Promise<ProviderPortal[]> {
		if (!PROVIDER_PORTALS.some((p) => p.provider === provider)) {
			throw new NotFoundException(`Unknown provider portal: ${provider}`);
		}
		const states = await writePortalState(domain, provider, body.state);
		return applyPortalStates(PROVIDER_PORTALS, states);
	}
}
