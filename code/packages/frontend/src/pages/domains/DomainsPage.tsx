import { Trash2 } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { type CreateDomainInput, useCreateDomain, useDeleteDomain, useDomains } from "@/api/domains"

/**
 * Manage the monitored-domain list: add a domain (with optional DKIM selectors and sending IPs) and
 * remove one. The audit engine reads this list.
 */
export function DomainsPage() {
  const { data: domains } = useDomains()
  const create = useCreateDomain()
  const del = useDeleteDomain()

  const [name, setName] = useState("")
  const [selectors, setSelectors] = useState("")
  const [ips, setIps] = useState("")

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const input: CreateDomainInput = {
      name: name.trim(),
      dkimSelectors: splitList(selectors),
      sendingIps: splitList(ips),
    }
    create.mutate(input, {
      onSuccess: () => {
        setName("")
        setSelectors("")
        setIps("")
        toast.success(`Now monitoring ${input.name}`)
      },
      onError: (err) => toast.error(errMsg(err, "Could not add domain")),
    })
  }

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-1 text-2xl font-bold">Domains</h1>
      <p className="mb-6 text-sm text-[var(--edh-muted)]">
        The email-sending domains you monitor for deliverability.
      </p>

      <form
        onSubmit={onSubmit}
        className="mb-8 grid gap-3 rounded-lg border border-[var(--edh-border)] bg-white p-4 sm:grid-cols-2"
      >
        <label className="text-sm sm:col-span-2">
          <span className="mb-1 block font-medium">Domain</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            placeholder="whitehatengineering.com"
            className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2"
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">DKIM selectors (comma-separated)</span>
          <input
            value={selectors}
            onChange={(e) => setSelectors(e.target.value)}
            placeholder="google, s1"
            className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2"
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Sending IPs (comma-separated)</span>
          <input
            value={ips}
            onChange={(e) => setIps(e.target.value)}
            placeholder="203.0.113.10"
            className="w-full rounded-md border border-[var(--edh-border)] px-3 py-2"
          />
        </label>
        <div className="sm:col-span-2">
          <button
            type="submit"
            disabled={create.isPending}
            className="rounded-md bg-[var(--edh-primary)] px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            {create.isPending ? "Adding…" : "Add domain"}
          </button>
        </div>
      </form>

      <div className="overflow-hidden rounded-lg border border-[var(--edh-border)] bg-white">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-left text-xs uppercase text-[var(--edh-muted)]">
            <tr>
              <th className="px-4 py-2">Domain</th>
              <th className="px-4 py-2">DKIM selectors</th>
              <th className="px-4 py-2">Sending IPs</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {(domains ?? []).map((d) => (
              <tr key={d.id} className="border-t border-[var(--edh-border)]">
                <td className="px-4 py-3 font-medium">{d.name}</td>
                <td className="px-4 py-3 text-slate-600">{d.dkimSelectors.join(", ") || "—"}</td>
                <td className="px-4 py-3 text-slate-600">{d.sendingIps.join(", ") || "—"}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    type="button"
                    onClick={() =>
                      del.mutate(d.id, {
                        onSuccess: () => toast.success(`Removed ${d.name}`),
                        onError: (err) => toast.error(errMsg(err, "Could not remove domain")),
                      })
                    }
                    className="inline-flex items-center gap-1 text-red-600 hover:underline"
                  >
                    <Trash2 className="h-4 w-4" /> Remove
                  </button>
                </td>
              </tr>
            ))}
            {(domains ?? []).length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-[var(--edh-muted)]">
                  No domains yet — add one above.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function splitList(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
}

function errMsg(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string | string[] } } }
  const m = e?.response?.data?.message
  if (Array.isArray(m)) return m.join(", ")
  return m ?? fallback
}
