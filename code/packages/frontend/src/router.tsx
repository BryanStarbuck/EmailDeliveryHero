import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router"
import { Toaster } from "sonner"
import { AppShell } from "@/pages/app/AppShell"
import { DashboardPage } from "@/pages/app/DashboardPage"
import { AuditsPage } from "@/pages/audits/AuditsPage"
import { BlacklistsPage } from "@/pages/blacklists/BlacklistsPage"
import { DomainsPage } from "@/pages/domains/DomainsPage"
import { RunDetailPage } from "@/pages/domains/RunDetailPage"
import { SettingsPage } from "@/pages/settings/SettingsPage"
import { SignInPage } from "@/pages/sign-in/SignInPage"
import { SsoCallbackPage } from "@/pages/sso-callback/SsoCallbackPage"

/**
 * Code-based TanStack Router. Auth is enforced inside <AppShell> (which wraps content in
 * <RequireAuth>). The sign-in and SSO-callback routes are public; everything under the app layout
 * requires an active session. Static paths outrank any future dynamic routes.
 */
const rootRoute = createRootRoute({
  component: () => (
    <>
      <Outlet />
      <Toaster richColors position="top-right" />
    </>
  ),
})

const signInRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sign-in",
  component: SignInPage,
})
const ssoCallbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sso-callback",
  component: SsoCallbackPage,
})

// Pathless layout route: renders the authenticated shell (left bar + <Outlet/>).
const appLayoutRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  component: AppShell,
})

const dashboardRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/",
  component: DashboardPage,
})
const domainsRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains",
  component: DomainsPage,
})
const runDetailRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains/$id",
  component: RunDetailPage,
})
const auditsRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/audits",
  component: AuditsPage,
})
const blacklistsRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/blacklists",
  component: BlacklistsPage,
})
const settingsIndexRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/settings",
  component: SettingsPage,
})
const settingsSectionRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/settings/$section",
  component: SettingsPage,
})

const routeTree = rootRoute.addChildren([
  signInRoute,
  ssoCallbackRoute,
  appLayoutRoute.addChildren([
    dashboardRoute,
    domainsRoute,
    runDetailRoute,
    auditsRoute,
    blacklistsRoute,
    settingsIndexRoute,
    settingsSectionRoute,
  ]),
])

export const router = createRouter({ routeTree })

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router
  }
}
