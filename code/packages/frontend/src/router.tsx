import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router"
import type { CSSProperties } from "react"
import { Toaster } from "sonner"
import { ScanProgressDock } from "@/components/ScanProgressDock"
import { AppShell } from "@/pages/app/AppShell"
import { DashboardPage } from "@/pages/app/DashboardPage"
import { AuditsPage } from "@/pages/audits/AuditsPage"
import { BlacklistDomainPage } from "@/pages/blacklists/BlacklistDomainPage"
import { BlacklistStatePage } from "@/pages/blacklists/BlacklistStatePage"
import { BlacklistsPage } from "@/pages/blacklists/BlacklistsPage"
import { DkimPage } from "@/pages/domains/DkimPage"
import { DkimProblemPage } from "@/pages/domains/DkimProblemPage"
import { DmarcPage } from "@/pages/domains/DmarcPage"
import { DmarcProblemPage } from "@/pages/domains/DmarcProblemPage"
import { DnsPage } from "@/pages/domains/DnsPage"
import { DnsProblemPage } from "@/pages/domains/DnsProblemPage"
import { DomainsPage } from "@/pages/domains/DomainsPage"
import { RunDetailPage } from "@/pages/domains/RunDetailPage"
import { SpfPage } from "@/pages/domains/SpfPage"
import { SpfProblemPage } from "@/pages/domains/SpfProblemPage"
import { ReportsPage } from "@/pages/reports/ReportsPage"
import { SettingsPage } from "@/pages/settings/SettingsPage"
import { SignInPage } from "@/pages/sign-in/SignInPage"
import { SsoCallbackPage } from "@/pages/sso-callback/SsoCallbackPage"

/**
 * Code-based TanStack Router. Login is OPTIONAL (pm/security.mdx §1/§3.4): <AppShell> wraps content
 * in <AppReady>, which renders for everyone — signed in or logged out as the `default` user — and
 * never forces a sign-in. The sign-in and SSO-callback routes are public; the few genuinely
 * admin-only surfaces opt in with <RequireAuth>. Static paths outrank any future dynamic routes.
 */
const rootRoute = createRootRoute({
  component: () => (
    <>
      <Outlet />
      {/* Live per-domain scan cards, bottom-left, above the toast stack (pm/progress_ui.mdx §3). */}
      <ScanProgressDock />
      {/*
        Toasts (pm/progress_ui.mdx §2): bottom-left, ~2× size, and pushed past the 256px left bar so
        one never sits over the nav. `!left-[272px]` beats sonner's inline `left`; `--width` + the
        toastOptions enlarge the card.
      */}
      <Toaster
        richColors
        position="bottom-left"
        className="!left-[272px]"
        style={{ "--width": "440px" } as CSSProperties}
        toastOptions={{ className: "text-base", style: { padding: "1rem 1.25rem" } }}
      />
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
// A specific historical run's report (pm/dashboard.mdx §4.2 — the Runs table's row click).
const runReportRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains/$id/runs/$runId",
  component: RunDetailPage,
})
// The per-technology full pages (pm/checks/*.mdx §6.2) and their problem-state drill-downs.
const dmarcRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains/$id/dmarc",
  component: DmarcPage,
})
const dmarcProblemRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains/$id/dmarc/$problemId",
  component: DmarcProblemPage,
})
// The DNS & Infrastructure full page (pm/checks/dns.mdx §6.2) and its problem drill-downs.
const dnsRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains/$id/dns",
  component: DnsPage,
})
const dnsProblemRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains/$id/dns/$problemId",
  component: DnsProblemPage,
})
const dkimRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains/$id/dkim",
  component: DkimPage,
})
const dkimProblemRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains/$id/dkim/$problemId",
  component: DkimProblemPage,
})
const spfRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains/$id/spf",
  component: SpfPage,
})
const spfProblemRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/domains/$id/spf/$problemId",
  component: SpfProblemPage,
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
// The Blacklists technology full page and its problem-state deep dives (pm/checks/blacklists.mdx §13/§16).
const blacklistDomainRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/blacklists/$domain",
  component: BlacklistDomainPage,
})
const blacklistStateRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/blacklists/$domain/state/$psId",
  component: BlacklistStatePage,
})
// The report library (pm/reports.mdx) — the left bar's Reports item lands here.
const reportsRoute = createRoute({
  getParentRoute: () => appLayoutRoute,
  path: "/reports",
  component: ReportsPage,
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
    runReportRoute,
    dmarcRoute,
    dmarcProblemRoute,
    dnsRoute,
    dnsProblemRoute,
    dkimRoute,
    dkimProblemRoute,
    spfRoute,
    spfProblemRoute,
    auditsRoute,
    blacklistsRoute,
    blacklistDomainRoute,
    blacklistStateRoute,
    reportsRoute,
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
