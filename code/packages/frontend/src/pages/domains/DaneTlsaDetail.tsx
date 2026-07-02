import { Link } from "@tanstack/react-router"
import { Loader2 } from "lucide-react"
import { useState } from "react"
import { useGenerateTlsaRecord } from "@/api/audit"
import type { DaneHostResult } from "@/api/types"
import { CopyFixButton } from "@/components/CopyFixButton"
import { cn } from "@/lib/utils"

/**
 * The DANE-specific interior of the dane-tlsa check-detail explainer page
 * (pm/checks/dane_tlsa.mdx §9.2/§9.3/§9.5): the per-MX triage matrix
 * (DNSSEC | TLSA | Params | Cert match | Rollover), the raw + parsed breakdown per MX host with
 * per-field verdict chips, the pending-probe rendering rules (certMatch/starttlsOffered are
 * PENDING, never failures, while the :25 probe is off — AC9/AC16), the PS-07 story link, and the
 * `3 1 1` generator panel (paste a PEM → the exact publishable record, AC18). Everything renders
 * from the run file's `results["infra.dane_tlsa"]` rows — never re-queried at render time.
 */

/** ✓ / ✗ / ⚠ / ⓘ / pending verdict chip (spec §9.3). */
function Chip({
  tone,
  children,
}: {
  tone: "ok" | "bad" | "warn" | "info" | "pending"
  children: React.ReactNode
}) {
  const tones: Record<string, string> = {
    ok: "bg-emerald-50 text-emerald-700 border-emerald-200",
    bad: "bg-red-50 text-red-700 border-red-200",
    warn: "bg-amber-50 text-amber-700 border-amber-200",
    info: "bg-slate-50 text-slate-600 border-slate-200",
    pending: "bg-sky-50 text-sky-700 border-sky-200",
  }
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px]",
        tones[tone],
      )}
    >
      {children}
    </span>
  )
}

const NOT_CAPTURED = "not captured this run"

/** One parsed-pane row: field label, observed value, verdict chip (spec §9.3 table). */
function FieldRow({
  label,
  value,
  chip,
}: {
  label: string
  value: React.ReactNode
  chip?: React.ReactNode
}) {
  return (
    <tr className="border-b border-slate-100 last:border-0">
      <td className="whitespace-nowrap py-1 pr-3 align-top text-xs font-medium text-slate-500">
        {label}
      </td>
      <td className="break-all py-1 pr-3 font-mono text-xs text-slate-700">{value}</td>
      <td className="py-1 text-right align-top">{chip}</td>
    </tr>
  )
}

const USAGE_NAMES: Record<number, string> = {
  0: "PKIX-TA",
  1: "PKIX-EE",
  2: "DANE-TA",
  3: "DANE-EE",
}

function usageChip(usage: number) {
  if (usage === 3) return <Chip tone="ok">✓ 3 {USAGE_NAMES[3]}</Chip>
  if (usage === 2) return <Chip tone="info">ⓘ 2 {USAGE_NAMES[2]}</Chip>
  return (
    <Chip tone="bad">
      ✗ {usage} {USAGE_NAMES[usage] ?? "unknown"} — unusable for SMTP
    </Chip>
  )
}

function digestChip(mtype: number, data: string) {
  const hexOk = /^[0-9a-f]*$/.test(data)
  const bad =
    !hexOk ||
    (mtype === 1 && data.length !== 64) ||
    (mtype === 2 && data.length !== 128) ||
    (data.length === 0 && mtype !== 0)
  return bad ? <Chip tone="bad">✗ malformed</Chip> : <Chip tone="ok">✓ {data.length} hex</Chip>
}

function ttlChip(ttl: number | null) {
  if (ttl === null) return <Chip tone="info">ⓘ {NOT_CAPTURED}</Chip>
  if (ttl === 0) return <Chip tone="warn">⚠ 0 — caching defeated</Chip>
  if (ttl > 86400) return <Chip tone="warn">⚠ &gt;24h</Chip>
  if (ttl > 3600) return <Chip tone="info">ⓘ &gt;1h</Chip>
  return <Chip tone="ok">✓ ≤1h</Chip>
}

/** The §9.8 pending-probe explanation, rendered once under the parsed panes. */
const PENDING_LINE =
  "The live :25 STARTTLS probe is opt-in (admin settings, smtp25 semaphore) — the DNS-side audit above is complete without it."

export function DaneTlsaDetail({
  hosts,
  domainId,
  runId,
}: {
  hosts: DaneHostResult[]
  domainId: string
  runId?: string
}) {
  const sorted = [...hosts].sort(
    (a, b) => (a.mxPreference ?? Number.MAX_SAFE_INTEGER) - (b.mxPreference ?? Number.MAX_SAFE_INTEGER),
  )
  const anyPending = sorted.some((h) => h.certMatch === null || h.starttlsOffered === null)

  return (
    <div className="space-y-6">
      {sorted.length === 0 ? (
        <p className="text-sm text-slate-600">No MX hosts — nothing to pin.</p>
      ) : (
        <>
          {/* The per-MX matrix (spec §4/§9.2 item 1) — the fastest multi-host triage surface. */}
          <div className="overflow-x-auto rounded-md border border-[var(--edh-border)]">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--edh-border)] bg-slate-50 text-left text-xs uppercase text-slate-500">
                  <th className="px-2 py-1.5">MX host (prio)</th>
                  <th className="px-2 py-1.5">DNSSEC</th>
                  <th className="px-2 py-1.5">TLSA</th>
                  <th className="px-2 py-1.5">Params</th>
                  <th className="px-2 py-1.5">Cert match</th>
                  <th className="px-2 py-1.5">Rollover</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((h) => (
                  <tr key={h.mxHost} className="border-b border-slate-100 last:border-0">
                    <td className="px-2 py-1.5 font-mono text-xs">
                      {h.mxHost}
                      {h.mxPreference !== null ? ` (${h.mxPreference})` : ""}
                    </td>
                    <td className="px-2 py-1.5">
                      {h.dnssecSigned ? (
                        <Chip tone="ok">✓ {h.rrsigObserved ? "RRSIG" : "DS/DNSKEY"}</Chip>
                      ) : h.tlsaPresent ? (
                        <Chip tone="bad">✗ unsigned</Chip>
                      ) : (
                        <Chip tone="warn">⚠ unsigned</Chip>
                      )}
                    </td>
                    <td className="px-2 py-1.5">
                      {h.probeError ? (
                        <Chip tone="bad">✗ {h.probeError}</Chip>
                      ) : h.tlsaPresent ? (
                        <Chip tone="ok">present ({h.tlsaRecords.length})</Chip>
                      ) : (
                        <Chip tone="warn">—</Chip>
                      )}
                    </td>
                    <td className="px-2 py-1.5">
                      {h.paramsOk === null ? (
                        <Chip tone="info">—</Chip>
                      ) : h.recommended311 ? (
                        <Chip tone="ok">3 1 1</Chip>
                      ) : h.paramsOk ? (
                        <Chip tone="info">usable</Chip>
                      ) : (
                        <Chip tone="bad">✗ unusable</Chip>
                      )}
                    </td>
                    <td className="px-2 py-1.5">
                      {h.certMatch === null ? (
                        <Chip tone="pending">pending</Chip>
                      ) : h.certMatch ? (
                        <Chip tone="ok">✓</Chip>
                      ) : (
                        <Chip tone="bad">✗</Chip>
                      )}
                    </td>
                    <td className="px-2 py-1.5">
                      {h.rolloverReady ? (
                        <Chip tone="ok">✓ ≥2</Chip>
                      ) : (
                        <Chip tone="warn">⚠ ({h.tlsaRecords.length})</Chip>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Raw + parsed breakdown per MX host, priority order (spec §9.3). */}
          {sorted.map((h) => (
            <div key={h.mxHost} className="rounded-md border border-[var(--edh-border)] p-3">
              <div className="mb-2 flex items-center justify-between">
                <h3 className="font-mono text-sm font-semibold">{h.mxHost}</h3>
                {(h.rawAnswer?.length ?? 0) > 0 && (
                  <CopyFixButton text={(h.rawAnswer ?? []).join("\n")} label="Copy RRset" />
                )}
              </div>

              {/* Raw pane: the observed TLSA RRset exactly as answered + the CNAME chain. */}
              <pre className="mb-3 overflow-x-auto rounded bg-slate-900 p-2 font-mono text-xs leading-relaxed text-slate-100">
                {h.rawAnswer === undefined
                  ? NOT_CAPTURED
                  : h.rawAnswer.length === 0
                    ? h.probeError
                      ? `; lookup failed: ${h.probeError}`
                      : `; no TLSA records at ${h.tlsaName ?? `_25._tcp.${h.mxHost}`}`
                    : h.rawAnswer.join("\n")}
                {h.cnameChain && h.cnameChain.length > 1
                  ? `\n; CNAME chain: ${h.cnameChain.join(" -> ")}`
                  : ""}
              </pre>

              {/* Parsed pane: per-field verdict chips (spec §9.3 table). */}
              <table className="w-full">
                <tbody>
                  <FieldRow
                    label="TLSA owner name"
                    value={h.tlsaName ?? NOT_CAPTURED}
                    chip={
                      h.tlsaName ? (
                        <Chip tone="ok">✓ canonical</Chip>
                      ) : (
                        <Chip tone="info">ⓘ {NOT_CAPTURED}</Chip>
                      )
                    }
                  />
                  <FieldRow
                    label="Zone DNSSEC"
                    value={
                      h.dnssecSigned
                        ? h.rrsigObserved
                          ? "signed (RRSIG at the TLSA name)"
                          : "signed (DS/DNSKEY at the apex)"
                        : "unsigned (no DS/DNSKEY observed)"
                    }
                    chip={
                      h.dnssecSigned ? (
                        <Chip tone="ok">✓ signed</Chip>
                      ) : h.tlsaPresent ? (
                        <Chip tone="bad">✗ TLSA on unsigned</Chip>
                      ) : (
                        <Chip tone="warn">⚠ unsigned, no TLSA</Chip>
                      )
                    }
                  />
                  <FieldRow
                    label="TLSA present"
                    value={`${h.tlsaRecords.length} record(s)`}
                    chip={
                      h.tlsaPresent ? <Chip tone="ok">✓</Chip> : <Chip tone="warn">⚠ absent</Chip>
                    }
                  />
                  {h.tlsaRecords.map((r, i) => (
                    <FieldRow
                      key={`${r.usage}-${r.selector}-${r.mtype}-${r.data}`}
                      label={`record ${i} — ${r.usage} ${r.selector} ${r.mtype}`}
                      value={`${r.data.slice(0, 16)}… (${r.data.length} hex, TTL ${r.ttl ?? "?"})`}
                      chip={
                        <span className="inline-flex flex-wrap justify-end gap-1">
                          {usageChip(r.usage)}
                          {r.selector === 1 ? (
                            <Chip tone="ok">✓ SPKI</Chip>
                          ) : (
                            <Chip tone="info">ⓘ full cert</Chip>
                          )}
                          {r.mtype === 1 ? (
                            <Chip tone="ok">✓ SHA-256</Chip>
                          ) : (
                            <Chip tone="info">ⓘ mtype {r.mtype}</Chip>
                          )}
                          {digestChip(r.mtype, r.data)}
                          {ttlChip(r.ttl)}
                        </span>
                      }
                    />
                  ))}
                  <FieldRow
                    label="Rollover staged"
                    value={h.rolloverReady ? "≥2 records (current + next)" : "single record"}
                    chip={
                      h.rolloverReady ? (
                        <Chip tone="ok">✓</Chip>
                      ) : (
                        <Chip tone="warn">⚠ single record</Chip>
                      )
                    }
                  />
                  <FieldRow
                    label="Cert match"
                    value={h.certMatch === null ? "awaiting the :25 probe" : String(h.certMatch)}
                    chip={
                      h.certMatch === null ? (
                        <Chip tone="pending">pending</Chip>
                      ) : h.certMatch ? (
                        <Chip tone="ok">✓</Chip>
                      ) : (
                        <Chip tone="bad">✗</Chip>
                      )
                    }
                  />
                  <FieldRow
                    label="STARTTLS offered"
                    value={
                      h.starttlsOffered === null
                        ? "awaiting the :25 probe"
                        : String(h.starttlsOffered)
                    }
                    chip={
                      h.starttlsOffered === null ? (
                        <Chip tone="pending">pending</Chip>
                      ) : h.starttlsOffered ? (
                        <Chip tone="ok">✓</Chip>
                      ) : (
                        <Chip tone="bad">✗</Chip>
                      )
                    }
                  />
                  {h.probeError && (
                    <FieldRow
                      label="Lookup error"
                      value={h.probeError}
                      chip={
                        h.probeError === "SERVFAIL" && h.dnssecSigned ? (
                          <Chip tone="bad">✗ SERVFAIL on signed zone</Chip>
                        ) : (
                          <Chip tone="info">ⓘ transient</Chip>
                        )
                      }
                    />
                  )}
                </tbody>
              </table>
            </div>
          ))}

          {anyPending && <p className="text-xs text-[var(--edh-muted)]">{PENDING_LINE}</p>}
        </>
      )}

      {/* Story link (spec §10 / AC22): findings → the PS-07 "DANE gap" drill-down, run-qualified. */}
      <p className="text-sm">
        <Link
          to="/domains/$id/dns/$problemId"
          params={{ id: domainId, problemId: "PS-07" }}
          search={runId ? { run: runId } : {}}
          className="font-medium text-[var(--edh-primary)] underline underline-offset-2"
        >
          Read the full story: PS-07 — DANE gap ›
        </Link>
      </p>

      <TlsaGeneratorPanel defaultMxHost={sorted[0]?.mxHost ?? ""} />
    </div>
  )
}

/** Best-effort extraction of the backend's user-readable 400 message (AC18). */
function errorMessage(err: unknown): string {
  const resp = (err as { response?: { data?: { message?: string | string[] } } })?.response
  const msg = resp?.data?.message
  if (Array.isArray(msg)) return msg.join("; ")
  if (typeof msg === "string") return msg
  return err instanceof Error ? err.message : "The generator request failed."
}

/**
 * The `3 1 1` generator panel (spec §9.5 / AC18): paste a PEM certificate + confirm the MX host →
 * the backend's `generateTlsa311` returns the owner name, the SPKI SHA-256, the complete
 * zone-file line (copy button), and the cert subject/notAfter so the user confirms they pasted
 * the right (and unexpired) certificate. A parse failure renders the 400 message inline.
 */
export function TlsaGeneratorPanel({ defaultMxHost }: { defaultMxHost: string }) {
  const [mxHost, setMxHost] = useState(defaultMxHost)
  const [pem, setPem] = useState("")
  const gen = useGenerateTlsaRecord()

  return (
    <div className="rounded-md border border-[var(--edh-border)] p-3">
      <h3 className="text-sm font-semibold">Generate a 3 1 1 TLSA record</h3>
      <p className="mt-1 text-xs text-[var(--edh-muted)]">
        Paste the MX host's TLS certificate (PEM) and confirm the hostname — the app computes the
        SPKI SHA-256 digest and the exact zone-file line to publish.
      </p>
      <div className="mt-2 space-y-2">
        <input
          type="text"
          value={mxHost}
          onChange={(e) => setMxHost(e.target.value)}
          placeholder="mail.example.com"
          className="w-full rounded-md border border-[var(--edh-border)] px-2 py-1.5 font-mono text-xs"
          aria-label="MX hostname"
        />
        <textarea
          value={pem}
          onChange={(e) => setPem(e.target.value)}
          placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"}
          rows={5}
          className="w-full rounded-md border border-[var(--edh-border)] px-2 py-1.5 font-mono text-xs"
          aria-label="PEM certificate"
        />
        <button
          type="button"
          onClick={() => gen.mutate({ mxHost, pem })}
          disabled={gen.isPending || mxHost.trim() === "" || pem.trim() === ""}
          className="inline-flex items-center gap-2 rounded-md bg-[var(--edh-primary)] px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
        >
          {gen.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
          Generate record
        </button>
      </div>

      {gen.isError && <p className="mt-2 text-sm text-red-600">{errorMessage(gen.error)}</p>}

      {gen.data && (
        <div className="mt-3 space-y-1 rounded bg-slate-50 p-2">
          <div className="flex items-start justify-between gap-2">
            <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs text-slate-800">
              {gen.data.record}
            </pre>
            <CopyFixButton text={gen.data.record} label="Copy record" />
          </div>
          <p className="text-xs text-[var(--edh-muted)]">
            owner <span className="font-mono">{gen.data.recordName}</span> · SPKI SHA-256{" "}
            <span className="font-mono">{gen.data.spkiSha256.slice(0, 16)}…</span>
          </p>
          <p className="text-xs text-[var(--edh-muted)]">
            cert subject <span className="font-mono">{gen.data.subject}</span> · valid to{" "}
            {gen.data.validTo}
          </p>
        </div>
      )}
    </div>
  )
}
