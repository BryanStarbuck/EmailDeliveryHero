import { useUser } from "@auth/react"
import { useParams } from "@tanstack/react-router"

/**
 * Settings. First round is intentionally thin: an Account panel (identity from the
 * OpenAuthFederated session), a read-only Scheduling note, and an Admin placeholder. The settings
 * left bar (Sidebar variant="settings") drives navigation between these sections.
 */
export function SettingsPage() {
  const { user } = useUser()
  const params = useParams({ strict: false }) as { section?: string }
  const section = params.section ?? "account"

  const email =
    user?.primaryEmailAddress?.emailAddress ?? user?.emailAddresses?.[0]?.emailAddress ?? "—"
  const name = user?.fullName ?? "—"

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="mb-6 text-2xl font-bold">Settings</h1>

      {section === "account" && (
        <Panel title="Account">
          <Row label="Name" value={name} />
          <Row label="Email" value={email} />
          <p className="mt-3 text-sm text-[var(--edh-muted)]">
            Identity is provided by OpenAuthFederated (Google Workspace SSO). There is no password to
            manage here.
          </p>
        </Panel>
      )}

      {section === "scheduling" && (
        <Panel title="Scheduling">
          <p className="text-sm text-slate-600">
            Periodic re-audits run on the backend when <code>EDH_PERIODIC_AUDIT_MINUTES</code> is set
            to a positive number of minutes. When enabled, every monitored domain is re-checked on
            that interval so newly-introduced problems surface automatically.
          </p>
        </Panel>
      )}

      {section === "admin" && (
        <Panel title="Admin">
          <p className="text-sm text-slate-600">
            Admin-only configuration. Visible because your OpenAuthFederated token carries the{" "}
            <code>role:admin</code> claim.
          </p>
        </Panel>
      )}
    </div>
  )
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-[var(--edh-border)] bg-white p-5">
      <h2 className="mb-3 font-semibold">{title}</h2>
      {children}
    </section>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between border-b border-[var(--edh-border)] py-2 text-sm last:border-0">
      <span className="text-[var(--edh-muted)]">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  )
}
