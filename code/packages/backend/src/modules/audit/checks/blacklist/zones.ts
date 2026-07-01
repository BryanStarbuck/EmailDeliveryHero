import { readFileSync } from "node:fs"
import { join } from "node:path"
import { resolveStateDir } from "@shared/state-dir"
import { readYaml } from "@shared/yaml-store"
import { parse } from "yaml"
import type { Severity } from "../types"
import type { BlocklistZone, CodeMeaning, ProviderPortal, ZoneKind } from "./blacklist-types"

/**
 * Loader over the checked-in blocklist registry (pm/checks/blacklists.mdx §18) —
 * src/modules/blacklists/registry/blacklists.yaml is the single source of truth for every zone,
 * dead zone, aggregator, and provider portal. This module holds NO catalog rows of its own: it
 * reads, validates, and freezes the registry at first use, and a malformed registry throws loudly
 * (a silently-empty catalog would report every domain "clean"). Operators still override/extend via
 * <stateDir>/blacklist_zones.yaml (same row shape, merged by `zone`) — no code change needed.
 */

// ---------------------------------------------------------------------------------------------
// Registry file shapes (the YAML contract of §18.1)
// ---------------------------------------------------------------------------------------------

export type RegistryAccessCost = "free" | "registration" | "paid"
export type RegistryQueryMethod = "dnsbl" | "rhsbl" | "web_only"
export type RegistryType = ZoneKind | "both"

export interface RegistryEntry {
  name: string
  url: string
  type: RegistryType
  description: string
  zone?: string
  query?: {
    method: RegistryQueryMethod
    record_types?: string[]
    rfc5782_probe?: boolean
    key_template?: string
  }
  return_codes?: Record<string, CodeMeaning>
  bitmask?: Record<string, CodeMeaning>
  refusal_codes?: string[]
  tier: "high" | "medium" | "low"
  weight: number
  severity: Severity
  enabled: boolean
  lookup_url: string
  delist_url: string
  auto_expires?: string
  paid_delist_offered?: boolean
  positive?: boolean
  /** Reputation feed consumed by the positive-reputation probes, not the listing sweep. */
  advisory?: boolean
  access?: { cost: RegistryAccessCost; notes?: string; dqs_zone?: string }
  status?: { alive: boolean; died?: string | number; reason?: string }
  notes?: string
}

export interface RegistryDeadZone {
  zone: string
  name: string
  died?: string | number
  reason?: string
}

export interface RegistryAggregator {
  name: string
  url: string
  description: string
}

export interface BlacklistRegistry {
  registry_version: number
  compiled: string
  sources: string[]
  blacklists: RegistryEntry[]
  dead_zones: RegistryDeadZone[]
  aggregators: RegistryAggregator[]
  provider_portals: Array<Omit<ProviderPortal, "user_state"> & { description?: string }>
}

// ---------------------------------------------------------------------------------------------
// Load + validate (once, at first import — boot fails loudly on a bad registry)
// ---------------------------------------------------------------------------------------------

/** Resolves in both src (ts-jest) and dist (nest build copies registry assets — see nest-cli.json). */
export function registryPath(): string {
  return join(__dirname, "..", "..", "..", "blacklists", "registry", "blacklists.yaml")
}

const SEVERITIES: Severity[] = ["ok", "info", "warning", "critical"]
const TIERS = ["high", "medium", "low"]
const TYPES = ["ip", "domain", "both"]

function fail(entry: string, problem: string): never {
  throw new Error(`blacklists.yaml registry invalid — entry "${entry}": ${problem}`)
}

function validateCodes(entry: string, field: string, codes?: Record<string, CodeMeaning>): void {
  if (codes === undefined) return
  for (const [code, meaning] of Object.entries(codes)) {
    if (!meaning || typeof meaning.label !== "string") fail(entry, `${field}["${code}"] needs a label`)
    if (!SEVERITIES.includes(meaning.severity)) {
      fail(entry, `${field}["${code}"] has invalid severity "${meaning.severity}"`)
    }
  }
}

function validateRegistry(reg: BlacklistRegistry): BlacklistRegistry {
  if (!reg || reg.registry_version !== 1) {
    throw new Error("blacklists.yaml registry invalid — registry_version must be 1")
  }
  if (!Array.isArray(reg.blacklists) || reg.blacklists.length === 0) {
    throw new Error("blacklists.yaml registry invalid — blacklists list is missing or empty")
  }
  const deadZones = reg.dead_zones ?? []
  const seen = new Set<string>()
  for (const e of reg.blacklists) {
    const id = e?.name ?? "(unnamed)"
    for (const req of ["name", "url", "type", "description", "lookup_url", "delist_url"] as const) {
      if (typeof e?.[req] !== "string" || e[req].length === 0) fail(id, `missing required field "${req}"`)
    }
    if (!TYPES.includes(e.type)) fail(id, `invalid type "${e.type}"`)
    if (!TIERS.includes(e.tier)) fail(id, `invalid tier "${e.tier}"`)
    if (!SEVERITIES.includes(e.severity)) fail(id, `invalid severity "${e.severity}"`)
    if (typeof e.weight !== "number" || e.weight < 0 || e.weight > 1) fail(id, "weight must be 0..1")
    if (typeof e.enabled !== "boolean") fail(id, "enabled must be boolean")
    if (e.query?.method !== "web_only" && typeof e.zone !== "string") {
      fail(id, "a DNS-queryable entry needs a zone (or query.method: web_only)")
    }
    if (e.zone) {
      if (seen.has(e.zone)) fail(id, `duplicate zone "${e.zone}"`)
      seen.add(e.zone)
      if (deadZoneMatch(e.zone, deadZones)) fail(id, `zone "${e.zone}" is on the dead_zones registry`)
    }
    validateCodes(id, "return_codes", e.return_codes)
    validateCodes(id, "bitmask", e.bitmask)
  }
  for (const d of deadZones) {
    if (typeof d?.zone !== "string" || typeof d?.name !== "string") {
      throw new Error("blacklists.yaml registry invalid — dead_zones entries need zone + name")
    }
  }
  for (const p of reg.provider_portals ?? []) {
    if (!p?.provider || !p?.name || !p?.check_url || !p?.delist_url) {
      throw new Error("blacklists.yaml registry invalid — provider_portals entries need provider/name/check_url/delist_url")
    }
  }
  return reg
}

function deadZoneMatch(zone: string, dead: RegistryDeadZone[]): boolean {
  const z = zone.toLowerCase()
  return dead.some((d) => z === d.zone || z.endsWith(`.${d.zone}`))
}

let cached: BlacklistRegistry | null = null

/** The parsed + validated checked-in registry (loaded once; throws on a malformed file). */
export function loadRegistry(): BlacklistRegistry {
  if (!cached) {
    cached = validateRegistry(parse(readFileSync(registryPath(), "utf8")) as BlacklistRegistry)
  }
  return cached
}

// ---------------------------------------------------------------------------------------------
// Registry entry → engine BlocklistZone rows
// ---------------------------------------------------------------------------------------------

function toZones(e: RegistryEntry): BlocklistZone[] {
  if (!e.zone || e.query?.method === "web_only" || e.advisory) return []
  const kinds: ZoneKind[] = e.type === "both" ? ["ip", "domain"] : [e.type]
  return kinds.map((kind) => ({
    zone: e.zone as string,
    name: e.name,
    kind,
    tier: e.tier,
    weight: e.weight,
    lookup_url: e.lookup_url,
    delist_url: e.delist_url,
    enabled: e.enabled,
    severity: e.severity,
    ...(e.return_codes ? { codes: e.return_codes } : {}),
    ...(e.bitmask ? { bitmask: e.bitmask } : {}),
    ...(e.access?.cost === "registration" ? { requires_registration: true } : {}),
    ...(e.access?.cost === "paid" ? { is_paid: true } : {}),
    ...(e.paid_delist_offered ? { paid_delist_offered: true } : {}),
    ...(e.auto_expires ? { auto_expires: e.auto_expires } : {}),
    ...(e.positive ? { positive: true } : {}),
    ...(e.notes ?? e.access?.notes ? { notes: e.notes ?? e.access?.notes } : {}),
  }))
}

/** The default zone catalog — every DNS-queryable registry row as an engine BlocklistZone. */
export const DEFAULT_ZONES: BlocklistZone[] = loadRegistry().blacklists.flatMap(toZones)

/**
 * The dead-zone registry (§9.5) from the registry's dead_zones block. Hard-blocked: the engine
 * refuses to query these even if an operator override adds them. Suffix match so all 18 SORBS
 * sub-zones are covered by one entry.
 */
export const DEAD_ZONE_SUFFIXES: string[] = loadRegistry().dead_zones.map((d) => d.zone)

export function isDeadZone(zone: string): boolean {
  return deadZoneMatch(zone, loadRegistry().dead_zones)
}

/** Provider reputation portals (§9.7) — the "invisible blacklists" with no DNS zone. */
export const PROVIDER_PORTALS: Array<Omit<ProviderPortal, "user_state">> =
  loadRegistry().provider_portals.map(({ provider, name, check_url, delist_url }) => ({
    provider,
    name,
    check_url,
    delist_url,
  }))

// ---------------------------------------------------------------------------------------------
// Effective catalog (registry defaults ⊕ operator overrides, dead zones excluded last)
// ---------------------------------------------------------------------------------------------

/** Path of the operator override file (admin "Blocklist Zones" panel writes here). */
export function zonesOverridePath(): string {
  return join(resolveStateDir(), "blacklist_zones.yaml")
}

/**
 * The effective zone catalog: registry defaults merged with <stateDir>/blacklist_zones.yaml
 * overrides (matched by `zone`; unknown zones are appended), with dead zones hard-excluded last.
 */
export function loadZones(): BlocklistZone[] {
  const overrides = readYaml<Partial<BlocklistZone>[]>(zonesOverridePath(), [])
  const byKey = new Map<string, BlocklistZone>(
    DEFAULT_ZONES.map((z) => [`${z.zone}|${z.kind}`, { ...z }]),
  )
  for (const raw of overrides) {
    if (!raw || typeof raw.zone !== "string") continue
    // Merge into every existing row for the zone (a type:both zone has an ip AND a domain row),
    // unless the override names a kind — then only that row.
    const targets = [...byKey.values()].filter(
      (z) => z.zone === raw.zone && (raw.kind === undefined || z.kind === raw.kind),
    )
    if (targets.length > 0) {
      for (const t of targets) byKey.set(`${t.zone}|${t.kind}`, { ...t, ...raw, kind: t.kind })
    } else if (raw.name && raw.kind && raw.lookup_url && raw.delist_url) {
      const defaults = {
        tier: "low" as const,
        weight: 0.2,
        enabled: true,
        severity: "warning" as const,
      }
      byKey.set(`${raw.zone}|${raw.kind}`, { ...defaults, ...(raw as BlocklistZone) })
    }
  }
  return [...byKey.values()].filter((z) => !isDeadZone(z.zone))
}
