import { FederatedProvider } from "@auth/react"
import { QueryClientProvider } from "@tanstack/react-query"
import { RouterProvider } from "@tanstack/react-router"
import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { AuthBridge } from "@/api/AuthBridge"
import { queryClient } from "@/api/queryClient"
import { installGlobalErrorHandlers } from "@/lib/logger"
import { router } from "@/router"
import { ScanProgressProvider } from "@/scan/ScanProgressContext"
import "@/index.css"

// Forward uncaught errors / unhandled rejections to the backend fault trail (pm/errors.mdx §3).
installGlobalErrorHandlers()

const env = import.meta.env

// The in-process embedded auth server the NestJS backend mounts at /api/v1 (see backend main.ts),
// so real Google Workspace sign-in works locally with no separate auth server. @auth/react appends
// /v1 to this base, so "/api" → "/api/v1/...".
const apiBase = env.VITE_AUTH_FRONTEND_API ?? "/api"

const allowedDomains = (env.VITE_AUTH_ALLOWED_DOMAINS ?? "whitehatengineering.com,act3ai.com")
  .split(",")
  .map((d) => d.trim())
  .filter(Boolean)

const rootElement = document.getElementById("root")
if (!rootElement) throw new Error("Root element #root not found")

createRoot(rootElement).render(
  <StrictMode>
    <FederatedProvider
      publishableKey={env.VITE_AUTH_PUBLISHABLE_KEY}
      frontendApi={apiBase}
      signInUrl={env.VITE_AUTH_SIGN_IN_URL ?? "/sign-in"}
      afterSignOutUrl="/"
      allowedDomains={allowedDomains}
    >
      {/* Registers useAuth().getToken/reloadSession for the axios layer. */}
      <AuthBridge />
      <QueryClientProvider client={queryClient}>
        <ScanProgressProvider>
          <RouterProvider router={router} />
        </ScanProgressProvider>
      </QueryClientProvider>
    </FederatedProvider>
  </StrictMode>,
)
