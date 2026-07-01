import { SignIn, useAuth } from "@auth/react"
import { useQuery } from "@tanstack/react-query"
import { Navigate } from "@tanstack/react-router"
import { api } from "@/api/axios"

interface AuthConfig {
  googleConfigured: boolean
  credentialsFilePresent: boolean
  redirectUri: string
}

/**
 * Login is OPTIONAL (pm/security.mdx): a missing credentials file disables only sign-in, never the
 * app (§4.3). Before rendering the Google button we ask the backend whether the OAuth client is
 * actually configured; when it is not, we surface the remediation instead of bouncing the user into
 * a broken Google redirect.
 */
function useAuthConfig() {
  return useQuery({
    queryKey: ["auth-config"],
    queryFn: async () => (await api.get<AuthConfig>("/health/auth-config")).data,
    staleTime: 60_000,
  })
}

/** The §4.3 remediation, shown in place of the sign-in form when Google OAuth is unconfigured. */
function SignInUnavailable({ config }: { config: AuthConfig }) {
  return (
    <div className="max-w-lg rounded-lg border border-[var(--edh-border)] bg-white p-5 text-sm">
      <h2 className="mb-2 font-semibold">Sign-in is not configured yet</h2>
      <p className="mb-3 text-slate-600">
        The app is fully usable without signing in — you are using it as the <code>default</code>{" "}
        user. To enable Google Workspace sign-in, the server needs a Google OAuth client:
      </p>
      <ol className="list-decimal space-y-2 pl-5 text-slate-600">
        <li>
          Set <code>GOOGLE_CLIENT_ID</code> / <code>GOOGLE_CLIENT_SECRET</code> in the backend
          environment, <em>or</em> add them under the <code>email_delivery_hero.google</code> key in{" "}
          <code>~/.credentials/email_delivery_hero.json</code>
          {config.credentialsFilePresent
            ? " (the file exists but has no Google client id/secret)."
            : " (the file does not exist yet)."}
        </li>
        <li>
          Register this exact redirect URI on the Google Cloud OAuth client:{" "}
          <code className="break-all">{config.redirectUri}</code>
        </li>
        <li>Restart the backend, then return here.</li>
      </ol>
    </div>
  )
}

/**
 * The login page — the OpenAuthFederated drop-in component. No password field: it renders the
 * "global login(s)" for the company Google Workspace domain(s). Federation only.
 *
 * If the visitor already has an active session, send them to the dashboard instead of the form.
 */
export function SignInPage() {
  const { isLoaded, isSignedIn } = useAuth()
  const { data: authConfig } = useAuthConfig()
  if (isLoaded && isSignedIn) return <Navigate to="/" />
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-slate-100 p-4">
      <div className="mb-6 text-center">
        <h1 className="text-2xl font-bold text-[var(--edh-primary)]">EmailDeliveryHero</h1>
        <p className="mt-1 text-sm text-[var(--edh-muted)]">
          Audit email deliverability — spam filters, blacklists, and the fixes to apply.
        </p>
      </div>
      {authConfig && !authConfig.googleConfigured ? (
        <SignInUnavailable config={authConfig} />
      ) : (
        <SignIn
          routing="path"
          path="/sign-in"
          fallbackRedirectUrl="/"
          appearance={{ variables: { colorPrimary: "#0f766e" } }}
        />
      )}
    </div>
  )
}
