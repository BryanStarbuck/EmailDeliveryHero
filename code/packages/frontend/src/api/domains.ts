import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"
import type { ArcConfig, BimiDomainConfig, DnsHealthConfig, MonitoredDomain } from "./types"

export interface CreateDomainInput {
  name: string
  label?: string
  dkimSelectors?: string[]
  sendingIps?: string[]
  scheduleEnabled?: boolean
  /** ARC / forwarding config (pm/checks/arc.mdx §4 per-domain config inputs). */
  arc?: ArcConfig
  /** BIMI config (pm/checks/bimi.mdx §4 per-domain config inputs). */
  bimi?: BimiDomainConfig
  /** DNS-health expectations (pm/checks/dns_health.mdx §4 per-domain config inputs). */
  dnsHealth?: DnsHealthConfig
}

export interface UpdateDomainInput {
  label?: string
  dkimSelectors?: string[]
  sendingIps?: string[]
  scheduleEnabled?: boolean
  /** ARC / forwarding config (pm/checks/arc.mdx §4 per-domain config inputs). */
  arc?: ArcConfig
  /** BIMI config (pm/checks/bimi.mdx §4 per-domain config inputs). */
  bimi?: BimiDomainConfig
  /** DNS-health expectations (pm/checks/dns_health.mdx §4 per-domain config inputs). */
  dnsHealth?: DnsHealthConfig
}

const KEY = ["domains"] as const

export function useDomains() {
  return useQuery({
    queryKey: KEY,
    queryFn: async () => (await api.get<MonitoredDomain[]>("/domains")).data,
  })
}

export function useCreateDomain() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (input: CreateDomainInput) =>
      (await api.post<MonitoredDomain>("/domains", input)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useUpdateDomain() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, input }: { id: string; input: UpdateDomainInput }) =>
      (await api.patch<MonitoredDomain>(`/domains/${id}`, input)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useDeleteDomain() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/domains/${id}`)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}
