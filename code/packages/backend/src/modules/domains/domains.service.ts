import { randomUUID } from "node:crypto"
import { join } from "node:path"
import { ConflictException, Injectable, NotFoundException } from "@nestjs/common"
import { readJson, writeJson } from "@shared/json-store"
import { logInfo } from "@shared/logging"
import { resolveStateDir } from "@shared/state-dir"
import type { CreateDomainDto, UpdateDomainDto } from "./dto/domain.dto"
import type { MonitoredDomain } from "./domain.types"

/**
 * The monitored-domain store. First round persists the full list as a single JSON file under the
 * state dir; there is no database. All reads/writes go through the atomic json-store helpers.
 */
@Injectable()
export class DomainsService {
  private readonly file = join(resolveStateDir(), "domains.json")

  private load(): MonitoredDomain[] {
    return readJson<MonitoredDomain[]>(this.file, [])
  }

  private save(domains: MonitoredDomain[]): void {
    writeJson(this.file, domains)
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
      dkimSelectors: normalizeList(dto.dkimSelectors),
      sendingIps: normalizeList(dto.sendingIps),
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
