import { useAuth } from "@auth/react"
import { Navigate } from "@tanstack/react-router"
import { type ReactNode, useEffect } from "react"
import { logger } from "@/lib/logger"

function FullPageSpinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex min-h-screen items-center justify-center text-sm text-[var(--edh-muted)]">
      {label}
    </div>
  )
}

/**
 * Keep retrying the session load when the auth backend is unreachable, so a server restart or a
 * network blip does NOT bounce an already-signed-in user to /sign-in.
 */
function Reconnecting({ reload }: { reload: () => Promise<boolean> }) {
  useEffect(() => {
    const id = setInterval(() => void reload().catch(() => {}), 2000)
    return () => clearInterval(id)
  }, [reload])
  return <FullPageSpinner label="Reconnecting…" />
}

/**
 * Route protection (UX gating only — the backend is authoritative). Bounces to /sign-in ONLY when
 * the auth backend authoritatively reports no active session; while it is unreachable it shows a
 * reconnecting state and retries.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { isLoaded, isSignedIn, loadState, reloadSession } = useAuth()
  if (!isLoaded) return <FullPageSpinner />
  if (isSignedIn) return <>{children}</>
  if (loadState === "failed" || loadState === "degraded") {
    return <Reconnecting reload={reloadSession} />
  }
  logger.info("RequireAuth: no active session, redirecting to /sign-in")
  return <Navigate to="/sign-in" />
}
