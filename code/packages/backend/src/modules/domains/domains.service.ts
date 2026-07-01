import { randomUUID } from "node:crypto"
import { existsSync } from "node:fs"
import { join } from "node:path"
import { ConflictException, Injectable, NotFoundException } from "@nestjs/common"
import { readJson } from "@shared/json-store"
import { logInfo } from "@shared/logging"
import { resolveStateDir } from "@shared/state-dir"
import { readYaml, writeYaml } from "@shared/yaml-store"
import type { MonitoredDomain } from "./domain.types"
import type { CreateDomainDto, UpdateDomainDto } from "./dto/domain.dto"

/**
 * The monitored-domain store. Persists the full list as a single human-readable YAML file
 * (domains.yaml) under the state dir; there is no database. All reads/writes go through the atomic
 * yaml-store helpers. A one-time migration reads a legacy domains.json if present.
 */
@Injectable()
export class DomainsService {
  private readonly dir = resolveStateDir()
  private readonly file = join(this.dir, "domains.yaml")
  private readonly legacyFile = join(this.dir, "domains.json")

  private load(): MonitoredDomain[] {
    // Prefer the YAML store; fall back to (and adopt) a legacy JSON store from an earlier install.
    if (!existsSync(this.file) && existsSync(this.legacyFile)) {
      const legacy = asRows(readJson<unknown>(this.legacyFile, []))
      if (legacy.length > 0) {
        writeYaml(this.file, legacy)
        logInfo(
          `Migrated ${legacy.length} domain(s) from domains.json to domains.yaml`,
          "DomainsService",
        )
      }
      return legacy
    }
    // domains.yaml is operator-editable, so a hand-edit could leave a non-array at the root; asRows
    // coerces anything that isn't a list back to an empty list rather than throwing on .map().
    return asRows(readYaml<unknown>(this.file, []))
  }

  private save(domains: MonitoredDomain[]): void {
    writeYaml(this.file, domains)
  }

  list(): MonitoredDomain[] {
    return this.load().sort((a, b) => a.name.localeCompare(b.name))
  }

  get(id: string): MonitoredDomain {
    const found = this.load().find((d) => d.id === id)
    if (!found) throw new NotFoundException(`Domain ${id} not found`)
    return found
  }

  create(dto: CreateDomainDto, addedBy: string): MonitoredDomain {
    const domains = this.load()
    const name = dto.name.trim().toLowerCase()
    if (domains.some((d) => d.name === name)) {
      throw new ConflictException(`Domain ${name} is already monitored`)
    }
    const now = new Date().toISOString()
    const domain: MonitoredDomain = {
      id: randomUUID(),
      name,
      label: (dto.label ?? "").trim(),
      dkimSelectors: normalizeList(dto.dkimSelectors),
      sendingIps: normalizeList(dto.sendingIps),
      // Default a new domain onto the recurring schedule (pm/domains.mdx §4.1).
      scheduleEnabled: dto.scheduleEnabled ?? true,
      addedBy,
      createdAt: now,
      updatedAt: now,
    }
    domains.push(domain)
    this.save(domains)
    logInfo(`Added monitored domain ${name} (by ${addedBy})`, "DomainsService")
    return domain
  }

  update(id: string, dto: UpdateDomainDto): MonitoredDomain {
    const domains = this.load()
    const idx = domains.findIndex((d) => d.id === id)
    if (idx < 0) throw new NotFoundException(`Domain ${id} not found`)
    const current = domains[idx]
    const updated: MonitoredDomain = {
      ...current,
      dkimSelectors: dto.dkimSelectors ? normalizeList(dto.dkimSelectors) : current.dkimSelectors,
      sendingIps: dto.sendingIps ? normalizeList(dto.sendingIps) : current.sendingIps,
      label: dto.label !== undefined ? dto.label.trim() : current.label,
      scheduleEnabled:
        dto.scheduleEnabled !== undefined ? dto.scheduleEnabled : current.scheduleEnabled,
      updatedAt: new Date().toISOString(),
    }
    domains[idx] = updated
    this.save(domains)
    return updated
  }

  remove(id: string): void {
    const domains = this.load()
    const next = domains.filter((d) => d.id !== id)
    if (next.length === domains.length) throw new NotFoundException(`Domain ${id} not found`)
    this.save(next)
    logInfo(`Removed monitored domain ${id}`, "DomainsService")
  }
}

/** Trim, lower-case, drop blanks, de-dup a string list. */
function normalizeList(list: string[] | undefined): string[] {
  if (!list) return []
  return [...new Set(list.map((s) => s.trim().toLowerCase()).filter(Boolean))]
}

/**
 * Coerce a parsed store into a clean domain array: drop anything that isn't a list (a hand-edited
 * YAML root that became a mapping/scalar) or an object element, then backfill missing fields.
 */
function asRows(parsed: unknown): MonitoredDomain[] {
  if (!Array.isArray(parsed)) return []
  return parsed
    .filter((d): d is MonitoredDomain => typeof d === "object" && d !== null)
    .map(withDefaults)
}

/**
 * Backfill fields that older records (pre-label / pre-schedule) may lack, so a store written by an
 * earlier version reads cleanly. Defaults match create(): scheduleEnabled on, empty label.
 */
function withDefaults(d: MonitoredDomain): MonitoredDomain {
  return {
    ...d,
    label: d.label ?? "",
    scheduleEnabled: d.scheduleEnabled ?? true,
  }
}
