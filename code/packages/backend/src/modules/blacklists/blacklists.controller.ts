import { Body, Controller, Get, NotFoundException, Param, Patch } from "@nestjs/common"
import { ApiOperation, ApiTags } from "@nestjs/swagger"
import { IsIn, IsString } from "class-validator"
import type {
  BlacklistHistoryEntry,
  BlacklistRunResults,
  PortalUserState,
  ProviderPortal,
} from "../audit/checks/blacklist/blacklist-types"
import {
  applyPortalStates,
  listBlacklistDomainIds,
  readBlacklistHistory,
  readLatestBlacklistRun,
  writePortalState,
} from "../audit/checks/blacklist/store"
import {
  loadRegistry,
  loadZones,
  PROVIDER_PORTALS,
  type BlacklistRegistry,
} from "../audit/checks/blacklist/zones"
import type { BlocklistZone } from "../audit/checks/blacklist/blacklist-types"

/** The effective registry view served to the §17 dashboard and the Blocklist Zones admin panel. */
export interface BlacklistRegistryInfo {
  compiled: string
  /** Every entry in the checked-in registry, including web-only and disabled lists. */
  lists_total: number
  /** The effective queryable catalog (registry defaults ⊕ operator overrides, dead zones excluded). */
  zones: BlocklistZone[]
  dead_zones: BlacklistRegistry["dead_zones"]
  aggregators: BlacklistRegistry["aggregators"]
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
  state!: PortalUserState
}

@ApiTags("blacklists")
@Controller("blacklists")
export class BlacklistsController {
  @Get("zones")
  @ApiOperation({
    summary:
      "The effective blocklist registry — checked-in blacklists.yaml merged with operator overrides",
  })
  zones(): BlacklistRegistryInfo {
    const reg = loadRegistry()
    return {
      compiled: reg.compiled,
      lists_total: reg.blacklists.length,
      zones: loadZones(),
      dead_zones: reg.dead_zones,
      aggregators: reg.aggregators,
    }
  }

  @Get("results")
  @ApiOperation({ summary: "Latest blacklist run for every domain that has one" })
  latestAll(): BlacklistRunResults[] {
    const runs: BlacklistRunResults[] = []
    for (const domain of listBlacklistDomainIds()) {
      const run = readLatestBlacklistRun(domain)
      if (run) runs.push(run)
    }
    return runs.sort((a, b) => a.domain.localeCompare(b.domain))
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

  @Patch(":domain/portals/:provider")
  @ApiOperation({ summary: "Set the user's provider-portal checklist state" })
  setPortalState(
    @Param("domain") domain: string,
    @Param("provider") provider: string,
    @Body() body: UpdatePortalStateDto,
  ): ProviderPortal[] {
    if (!PROVIDER_PORTALS.some((p) => p.provider === provider)) {
      throw new NotFoundException(`Unknown provider portal: ${provider}`)
    }
    const states = writePortalState(domain, provider, body.state)
    return applyPortalStates(PROVIDER_PORTALS, states)
  }
}
