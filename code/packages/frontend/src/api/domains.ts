import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "./axios"
import type { MonitoredDomain } from "./types"

export interface CreateDomainInput {
  name: string
  dkimSelectors?: string[]
  sendingIps?: string[]
}

export interface UpdateDomainInput {
  dkimSelectors?: string[]
  sendingIps?: string[]
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
