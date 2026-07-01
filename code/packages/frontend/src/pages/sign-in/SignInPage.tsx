import { SignIn, useAuth } from "@auth/react"
import { Navigate } from "@tanstack/react-router"

/**
 * The login page — the OpenAuthFederated drop-in component. No password field: it renders the
 * "global login(s)" for the company Google Workspace domain(s). Federation only.
 *
 * If the visitor already has an active session, send them to the dashboard instead of the form.
 */
export function SignInPage() {
  const { isLoaded, isSignedIn } = useAuth()
  if (isLoaded && isSignedIn) return <Navigate to="/" />
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-100 p-4">
      <div className="mb-6 text-center">
        <h1 className="text-2xl font-bold text-[var(--edh-primary)]">EmailDeliveryHero</h1>
        <p className="mt-1 text-sm text-[var(--edh-muted)]">
          Audit email deliverability — spam filters, blacklists, and the fixes to apply.
        </p>
      </div>
      <SignIn
        routing="path"
        path="/sign-in"
        fallbackRedirectUrl="/"
        appearance={{ variables: { colorPrimary: "#0f766e" } }}
      />
    </div>
  )
}
