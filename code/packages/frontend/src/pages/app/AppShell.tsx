import { Outlet, useLocation } from "@tanstack/react-router"
import { Sidebar, type SidebarVariant } from "@/components/layout/Sidebar"
import { AppReady } from "@/router/guards"

/**
 * App layout: a left bar (variant chosen by area) beside the routed content. Login is OPTIONAL
 * (pm/security.mdx) — the shell is wrapped in <AppReady>, which renders for everyone (signed in or
 * logged out as the `default` user) and never forces a sign-in. Settings are reachable logged out;
 * the account slot at the bottom of the bar offers a "Sign in" button.
 */
function variantFor(pathname: string): SidebarVariant {
  return pathname.startsWith("/settings") ? "settings" : "app"
}

export function AppShell() {
  const variant = useLocation({ select: (l) => variantFor(l.pathname) })
  return (
    <AppReady>
      <div className="flex h-screen">
        <Sidebar variant={variant} />
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </AppReady>
  )
}
