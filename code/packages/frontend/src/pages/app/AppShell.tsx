import { Outlet, useLocation } from "@tanstack/react-router"
import { Sidebar, type SidebarVariant } from "@/components/layout/Sidebar"
import { RequireAuth } from "@/router/guards"

/**
 * Authenticated app layout: a left bar (variant chosen by area) beside the routed content. The
 * whole shell is wrapped in <RequireAuth>, so no page renders without a signed-in session.
 */
function variantFor(pathname: string): SidebarVariant {
  return pathname.startsWith("/settings") ? "settings" : "app"
}

export function AppShell() {
  const variant = useLocation({ select: (l) => variantFor(l.pathname) })
  return (
    <RequireAuth>
      <div className="flex h-screen">
        <Sidebar variant={variant} />
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </RequireAuth>
  )
}
