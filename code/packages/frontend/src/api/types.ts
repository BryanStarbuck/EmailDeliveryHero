/** Shared API types — mirror the backend DTOs (packages/backend/src/modules/*). */

export type Severity = "ok" | "info" | "warning" | "critical"

export interface MonitoredDomain {
  id: string
  name: string
  dkimSelectors: string[]
  sendingIps: string[]
  addedBy: string
  createdAt: string
  updatedAt: string
}

export interface Finding {
  id: string
  checkId: string
  title: string
  severity: Severity
  detail: string
  remediation?: string
  evidence?: string
}

export interface AuditResult {
  domainId: string
  domain: string
  ranAt: string
  score: number
  status: Severity
  findings: Finding[]
  counts: Record<Severity, number>
}
