import { randomUUID } from "node:crypto"
import { existsSync } from "node:fs"
import { join } from "node:path"
import { ConflictException, Injectable, NotFoundException } from "@nestjs/common"
import { readJson } from "@shared/json-store"
import { logInfo } from "@shared/logging"
import { resolveStateDir } from "@shared/state-dir"
import { readYaml, writeYaml } from "@shared/yaml-store"
import type {
  ArcConfig,
  BimiDomainConfig,
  DaneDomainConfig,
  DnsHealthConfig,
  DomainReputationConfig,
  LinkUrlDomainConfig,
  MxRoutingConfig,
} from "../audit/checks/types"
import type { MonitoredDomain } from "./domain.types"
import type {
  ArcConfigDto,
  BimiConfigDto,
  CreateDomainDto,
  DaneConfigDto,
  DnsHealthConfigDto,
  DomainReputationConfigDto,
  LinkUrlConfigDto,
  MxRoutingConfigDto,
  UpdateDomainDto,
} from "./dto/domain.dto"

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

  /**
   * Listeners invoked after a domain is removed. Removing a domain also removes its audit history
   * under the state dir (pm/domains.mdx §4.2); the audit store registers here so this service never
   * has to depend on it (it already depends on us).
   */
  private readonly removeListeners: ((domainId: string) => void | Promise<void>)[] = []

  /** Register a callback that runs whenever a monitored domain is removed. */
  onRemoved(listener: (domainId: string) => void | Promise<void>): void {
    this.removeListeners.push(listener)
  }

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
      ...(dto.arc ? { arc: normalizeArc(dto.arc) } : {}),
      ...(dto.bimi ? { bimi: normalizeBimi(dto.bimi) } : {}),
      ...(dto.dnsHealth ? { dnsHealth: normalizeDnsHealth(dto.dnsHealth) } : {}),
      ...(dto.mx ? { mx: normalizeMx(dto.mx) } : {}),
      ...(dto.domainReputation
        ? { domainReputation: normalizeDomainReputation(dto.domainReputation) }
        : {}),
      ...(dto.dane ? { dane: normalizeDane(dto.dane) } : {}),
      ...(dto.linkUrl ? { linkUrl: normalizeLinkUrl(dto.linkUrl) } : {}),
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
      arc: dto.arc !== undefined ? normalizeArc(dto.arc) : current.arc,
      bimi: dto.bimi !== undefined ? normalizeBimi(dto.bimi) : current.bimi,
      dnsHealth:
        dto.dnsHealth !== undefined ? normalizeDnsHealth(dto.dnsHealth) : current.dnsHealth,
      mx: dto.mx !== undefined ? normalizeMx(dto.mx) : current.mx,
      domainReputation:
        dto.domainReputation !== undefined
          ? normalizeDomainReputation(dto.domainReputation)
          : current.domainReputation,
      dane: dto.dane !== undefined ? normalizeDane(dto.dane) : current.dane,
      linkUrl: dto.linkUrl !== undefined ? normalizeLinkUrl(dto.linkUrl) : current.linkUrl,
      updatedAt: new Date().toISOString(),
    }
    domains[idx] = updated
    this.save(domains)
    return updated
  }

  async remove(id: string): Promise<void> {
    const domains = this.load()
    const next = domains.filter((d) => d.id !== id)
    if (next.length === domains.length) throw new NotFoundException(`Domain ${id} not found`)
    this.save(next)
    logInfo(`Removed monitored domain ${id}`, "DomainsService")
    // Cascade: let registered stores (the audit history) drop everything they hold for this domain.
    for (const listener of this.removeListeners) await listener(id)
  }
}

/** Trim, lower-case, drop blanks, de-dup a string list. */
function normalizeList(list: string[] | undefined): string[] {
  if (!list) return []
  return [...new Set(list.map((s) => s.trim().toLowerCase()).filter(Boolean))]
}

/**
 * Normalize the operator-entered BIMI config (pm/checks/bimi.mdx §4): trim/lower-case/de-dup the
 * selector list (dropping the implicit "default", which is always audited), trim the sample
 * message, and collapse an entirely-empty config to undefined so domains.yaml stays clean.
 */
function normalizeBimi(bimi: BimiConfigDto): BimiDomainConfig | undefined {
  const selectors = normalizeList(bimi.selectors).filter((s) => s !== "default")
  const sampleMessage = (bimi.sampleMessage ?? "").trim()
  if (selectors.length === 0 && sampleMessage === "") return undefined
  return { selectors, ...(sampleMessage ? { sampleMessage } : {}) }
}

/**
 * Normalize the operator-entered ARC / forwarding config (pm/checks/arc.mdx §4): trim every field,
 * lower-case DNS names, drop forwarder rows missing their required label/address, and strip empty
 * optional fields so domains.yaml stays clean.
 */
function normalizeArc(arc: ArcConfigDto): ArcConfig {
  const forwarders = (arc.forwarders ?? [])
    .map((f) => ({
      label: f.label.trim(),
      forwardAddress: f.forwardAddress.trim(),
      ...(f.signerDomain?.trim() ? { signerDomain: f.signerDomain.trim().toLowerCase() } : {}),
      ...(f.signerSelector?.trim() ? { signerSelector: f.signerSelector.trim() } : {}),
      ...(f.probeMailbox?.trim() ? { probeMailbox: f.probeMailbox.trim() } : {}),
    }))
    .filter((f) => f.label !== "" && f.forwardAddress !== "")
  return { usesForwarding: arc.usesForwarding, forwarders }
}

/**
 * Normalize the operator-entered domain-registration-reputation config
 * (pm/checks/domain_reputation.mdx §4): trim/lower-case/de-dup the brand strings, clamp absent
 * threshold overrides away, and collapse an entirely-default config to undefined so domains.yaml
 * stays clean.
 */
function normalizeDomainReputation(
  dto: DomainReputationConfigDto,
): DomainReputationConfig | undefined {
  const brands = normalizeList(dto.brands)
  const config: DomainReputationConfig = {
    brands,
    ...(dto.expiryWarnDays !== undefined ? { expiryWarnDays: dto.expiryWarnDays } : {}),
    ...(dto.ageWarnDays !== undefined ? { ageWarnDays: dto.ageWarnDays } : {}),
    ...(dto.registrantPublicIntentional !== undefined
      ? { registrantPublicIntentional: dto.registrantPublicIntentional }
      : {}),
    ...(dto.cousinScan !== undefined ? { cousinScan: dto.cousinScan } : {}),
  }
  const allDefault =
    brands.length === 0 &&
    dto.expiryWarnDays === undefined &&
    dto.ageWarnDays === undefined &&
    !dto.registrantPublicIntentional &&
    !dto.cousinScan
  return allDefault ? undefined : config
}

/**
 * Normalize the operator-entered DNS-health expectations (pm/checks/dns_health.mdx §4): trim /
 * lower-case / de-dup both name lists and collapse an entirely-default config to undefined so
 * domains.yaml stays clean.
 */
function normalizeDnsHealth(cfg: DnsHealthConfigDto): DnsHealthConfig | undefined {
  const extraLabels = normalizeList(cfg.extraLabels).map((l) => l.replace(/\.$/, ""))
  const expectedNs = normalizeList(cfg.expectedNs).map((n) => n.replace(/\.$/, ""))
  const skipAxfrProbe = cfg.skipAxfrProbe ?? false
  if (extraLabels.length === 0 && expectedNs.length === 0 && !skipAxfrProbe) return undefined
  return { extraLabels, expectedNs, skipAxfrProbe }
}

/**
 * Normalize the operator-entered mail-routing expectations (pm/checks/mx_routing.mdx §4 — the
 * `mx_expectations` shape of §5): trim / lower-case / de-dup the expected-MX host list (stripping
 * trailing dots), default receivesMail to TRUE (the schema default) and skipSmtpProbe to FALSE,
 * and collapse an entirely-default config to undefined so domains.yaml stays clean.
 */
function normalizeMx(cfg: MxRoutingConfigDto): MxRoutingConfig | undefined {
  const receivesMail = cfg.receivesMail ?? true
  const expectedHosts = normalizeList(cfg.expectedHosts).map((h) => h.replace(/\.$/, ""))
  const skipSmtpProbe = cfg.skipSmtpProbe ?? false
  if (receivesMail && expectedHosts.length === 0 && !skipSmtpProbe) return undefined
  return { receivesMail, expectedHosts, skipSmtpProbe }
}

/**
 * Normalize the operator-entered DANE config (pm/checks/dane_tlsa.mdx §4): lower-case the pinned
 * next-cert SPKI digest and collapse an empty config to undefined so domains.yaml stays clean.
 */
function normalizeDane(cfg: DaneConfigDto): DaneDomainConfig | undefined {
  const expectedNextSpki = (cfg.expectedNextSpki ?? "").trim().toLowerCase()
  if (expectedNextSpki === "") return undefined
  return { expectedNextSpki }
}

/**
 * Normalize the operator-entered Link / URL-reputation config (pm/checks/link_url_reputation.mdx
 * §4): trim / lower-case / de-dup the aligned link-domain allow-list and collapse an empty config
 * to undefined so domains.yaml stays clean.
 */
function normalizeLinkUrl(cfg: LinkUrlConfigDto): LinkUrlDomainConfig | undefined {
  const allowedDomains = normalizeList(cfg.allowedDomains).map((d) => d.replace(/\.$/, ""))
  if (allowedDomains.length === 0) return undefined
  return { allowedDomains }
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
