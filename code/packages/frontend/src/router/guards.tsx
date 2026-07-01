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
 * The app gate for OPTIONAL login (pm/security.mdx §3.4). Login is NOT required: the app renders for
 * everyone. This never redirects to /sign-in — it only waits for the auth SDK to load (so we know
 * whether there's a session before painting the account slot), and shows a reconnecting state if the
 * auth backend is unreachable (so a blip never disturbs a signed-in user). Logged-out users fall
 * through and use the app as the `default` user; the account slot offers a "Sign in" button.
 */
export function AppReady({ children }: { children: ReactNode }) {
  const { isLoaded, loadState, reloadSession } = useAuth()
  if (!isLoaded) {
    if (loadState === "failed" || loadState === "degraded") {
      return <Reconnecting reload={reloadSession} />
    }
    return <FullPageSpinner />
  }
  return <>{children}</>
}

/**
 * Hard auth gate for the FEW places that genuinely require a signed-in user (e.g. an admin-only
 * route). Bounces to /sign-in only when the backend authoritatively reports no session; retries
 * while the backend is unreachable. Ordinary pages use <AppReady> instead and stay open logged out.
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
