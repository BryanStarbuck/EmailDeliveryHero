import {
	createRootRoute,
	createRoute,
	createRouter,
	Outlet,
} from "@tanstack/react-router";
import type { CSSProperties } from "react";
import { Toaster } from "sonner";
import { ScanProgressDock } from "@/components/ScanProgressDock";
import { AppShell } from "@/pages/app/AppShell";
import { DashboardPage } from "@/pages/app/DashboardPage";
import { AuditsPage } from "@/pages/audits/AuditsPage";
import { BlacklistDomainPage } from "@/pages/blacklists/BlacklistDomainPage";
import { BlacklistStatePage } from "@/pages/blacklists/BlacklistStatePage";
import { BlacklistsPage } from "@/pages/blacklists/BlacklistsPage";
import { DnssecExpiryPage } from "@/pages/dnssec/DnssecExpiryPage";
import { DnssecPage } from "@/pages/dnssec/DnssecPage";
import { BlacklistTargetPage } from "@/pages/blacklists/BlacklistTargetPage";
import { BlacklistZonePage } from "@/pages/blacklists/BlacklistZonePage";
import { ContentScoringPage } from "@/pages/domains/ContentScoringPage";
import { DkimPage } from "@/pages/domains/DkimPage";
import { DkimProblemPage } from "@/pages/domains/DkimProblemPage";
import { DmarcCheckPage } from "@/pages/domains/DmarcCheckPage";
import { DmarcPage } from "@/pages/domains/DmarcPage";
import { DmarcProblemPage } from "@/pages/domains/DmarcProblemPage";
import { DnsCheckPage } from "@/pages/domains/DnsCheckPage";
import { DnsPage } from "@/pages/domains/DnsPage";
import { DnsProblemPage } from "@/pages/domains/DnsProblemPage";
import { DomainReportsPage } from "@/pages/domains/DomainReportsPage";
import { DomainsPage } from "@/pages/domains/DomainsPage";
import { RunDetailPage } from "@/pages/domains/RunDetailPage";
import { SpfPage } from "@/pages/domains/SpfPage";
import { SpfProblemPage } from "@/pages/domains/SpfProblemPage";
import { InstallPage } from "@/pages/install/InstallPage";
import { ReportsPage } from "@/pages/reports/ReportsPage";
import { ScheduledChecksPage } from "@/pages/scheduler/ScheduledChecksPage";
import { SettingsPage } from "@/pages/settings/SettingsPage";
import { SignInPage } from "@/pages/sign-in/SignInPage";
import { SsoCallbackPage } from "@/pages/sso-callback/SsoCallbackPage";

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
				toastOptions={{
					className: "text-base",
					style: { padding: "1rem 1.25rem" },
				}}
			/>
		</>
	),
});

const signInRoute = createRoute({
	getParentRoute: () => rootRoute,
	path: "/sign-in",
	component: SignInPage,
});
const ssoCallbackRoute = createRoute({
	getParentRoute: () => rootRoute,
	path: "/sso-callback",
	component: SsoCallbackPage,
});

// Pathless layout route: renders the authenticated shell (left bar + <Outlet/>).
const appLayoutRoute = createRoute({
	getParentRoute: () => rootRoute,
	id: "app",
	component: AppShell,
});

const dashboardRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/",
	component: DashboardPage,
	// `?resume=<intent>` is the one-shot replay token the Install page lands us back with after a
	// diverted run finishes installing (pm/install_brew.mdx §8.3). DashboardPage reads it, fires the
	// run once, and clears it so a later refresh doesn't re-trigger.
	validateSearch: (search: Record<string, unknown>): { resume?: string } => ({
		...(typeof search.resume === "string" && search.resume
			? { resume: search.resume }
			: {}),
	}),
});
const domainsRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains",
	component: DomainsPage,
	// `?edit=<domainId>` opens that domain's editor on arrival — the dashboard row-menu's
	// "Edit domain" action (pm/dashboard.mdx §4.3). `?new` opens the Add-domain form over the
	// list (pm/domains.mdx §1 — the /domains/new "`?new` side panel" form).
	validateSearch: (
		search: Record<string, unknown>,
	): { edit?: string; new?: boolean } => ({
		...(typeof search.edit === "string" && search.edit
			? { edit: search.edit }
			: {}),
		...("new" in search && search.new !== undefined && search.new !== false
			? { new: true }
			: {}),
	}),
});
const runDetailRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id",
	component: RunDetailPage,
});
// A specific historical run's report (pm/dashboard.mdx §4.2 — the Runs table's row click).
const runReportRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId",
	component: RunDetailPage,
});
// The per-technology full pages (pm/checks/*.mdx §6.2) and their problem-state drill-downs.
// DMARC is run-scoped (pm/checks/dmarc.mdx §6.2): the canonical route carries :runId and the
// bare /dmarc path is the newest-run alias (same page, resolved to the domain's latest run).
const dmarcRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/dmarc",
	component: DmarcPage,
});
// The DMARC sub-test explainer pages (pm/checks/dmarc.mdx §6.3/§6.4): the LOCKED shared route
// pattern /domains/:id/runs/:runId/dmarc/check/:checkKey (+ newest alias). The literal `check`
// segment keeps the pattern disjoint from the problem-state drill-down; these static routes are
// registered ahead of the `:problemId` param routes.
const dmarcCheckRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/dmarc/check/$checkKey",
	component: DmarcCheckPage,
});
const runDmarcCheckRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/dmarc/check/$checkKey",
	component: DmarcCheckPage,
});
const dmarcProblemRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/dmarc/$problemId",
	component: DmarcProblemPage,
});
const runDmarcRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/dmarc",
	component: DmarcPage,
});
const runDmarcProblemRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/dmarc/$problemId",
	component: DmarcProblemPage,
});
// The DNS & Infrastructure category run page (pm/checks/dns.mdx §6.2): run-scoped at
// /domains/:id/runs/:runId/dns, with the newest-run alias /domains/:id/dns, plus the
// problem-state drill-downs at /domains/:id/dns/:problemId.
const dnsRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/dns",
	component: DnsPage,
});
const dnsRunRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/dns",
	component: DnsPage,
});
// The run-scoped check-detail explainer page — one per test family (pm/checks/dns.mdx §6.2
// item 6/8): what it is, current state, what it means, how to fix it, run-this-check-now.
const dnsCheckRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/dns/check/$checkKey",
	component: DnsCheckPage,
});
// Newest-run alias of the explainer (pm/checks/dane_tlsa.mdx §9 / AC13): the static `check`
// segment outranks the `:problemId` drill-down route below.
const dnsCheckAliasRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/dns/check/$checkKey",
	component: DnsCheckPage,
});
const dnsProblemRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/dns/$problemId",
	component: DnsProblemPage,
	// `?run=<runId>` scopes the drill-down's live data to the run being viewed (pm/checks/dns.mdx §7).
	validateSearch: (search: Record<string, unknown>): { run?: string } => ({
		...(typeof search.run === "string" && search.run
			? { run: search.run }
			: {}),
	}),
});
const dkimRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/dkim",
	component: DkimPage,
});
const dkimProblemRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/dkim/$problemId",
	component: DkimProblemPage,
});
// Run-scoped DKIM category page + drill-downs (pm/checks/dkim.mdx §6.2): everything rendered comes
// from that specific run; /domains/$id/dkim above stays the newest-run alias of the same page.
const dkimRunRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/dkim",
	component: DkimPage,
});
const dkimRunProblemRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/dkim/$problemId",
	component: DkimProblemPage,
});
const spfRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/spf",
	component: SpfPage,
});
// Run-scoped SPF category page (pm/use_cases/view_one_category_run.mdx AC1 — the locked route
// pattern /domains/:id/runs/:runId/<slug>); /domains/$id/spf above stays the newest-run alias of
// the same page, matching dkim/dmarc/dns/blacklists.
const spfRunRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/spf",
	component: SpfPage,
});
const spfProblemRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/spf/$problemId",
	component: SpfProblemPage,
});
// The Content-scoring full page (pm/checks/content_scoring.mdx §4): score gauge, fired-rule rows,
// and the Sample-message upload panel with the Re-score action.
const contentScoringRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/content",
	component: ContentScoringPage,
});
const auditsRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/audits",
	component: AuditsPage,
});
const blacklistsRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/blacklists",
	component: BlacklistsPage,
});
// DNSSEC fleet boards (pm/checks/dnssec.mdx §19). Static "/dnssec/expiry" is registered before the
// bare "/dnssec" so the more specific path wins the match.
const dnssecExpiryRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/dnssec/expiry",
	component: DnssecExpiryPage,
});
const dnssecRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/dnssec",
	component: DnssecPage,
});
// The Blacklists technology full page and its problem-state deep dives (pm/checks/blacklists.mdx §13/§16).
// The run-scoped page (pm/checks/blacklists.mdx §13.2): /domains/$id/runs/$runId/blacklists with the
// newest-run alias /domains/$id/blacklists; /blacklists/$domain is the left-bar redirect shorthand.
const domainBlacklistsRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/blacklists",
	component: BlacklistDomainPage,
});
const runBlacklistsRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/blacklists",
	component: BlacklistDomainPage,
});
const blacklistDomainRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/blacklists/$domain",
	component: BlacklistDomainPage,
});
// Legacy shorthand — BlacklistStatePage redirects it into the newest-run alias (AC 25).
const blacklistStateRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/blacklists/$domain/state/$psId",
	component: BlacklistStatePage,
});
// The problem-state deep-dive routes (pm/checks/blacklists.mdx §20.5 / AC 25): run-scoped
// canonical /domains/$id/runs/$runId/blacklists/state/$psId with the newest-run alias.
const runBlacklistStateRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/blacklists/state/$psId",
	component: BlacklistStatePage,
});
const domainBlacklistStateRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/blacklists/state/$psId",
	component: BlacklistStatePage,
});
// The zone/target explainer pages (pm/checks/blacklists.mdx §20.3/§20.4, AC 23/24): run-scoped
// canonical routes with newest-run aliases.
const runBlacklistZoneRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/blacklists/zone/$zoneId",
	component: BlacklistZonePage,
});
const blacklistZoneRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/blacklists/zone/$zoneId",
	component: BlacklistZonePage,
});
const runBlacklistTargetRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/runs/$runId/blacklists/target/$target",
	component: BlacklistTargetPage,
});
const blacklistTargetRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/blacklists/target/$target",
	component: BlacklistTargetPage,
});
// The report library (pm/reports.mdx) — the left bar's Reports item lands here.
const reportsRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/reports",
	component: ReportsPage,
});
// The per-domain ingested-report-emails view (pm/emails.mdx §7.1): DMARC aggregate (rua) +
// TLS-RPT reports turned into problems-and-fixes, with the per-source-IP details table.
const domainReportsRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/domains/$id/reports",
	component: DomainReportsPage,
});
// The Scheduled Checks configuration page (pm/scheduled_checks.mdx) — opened by the dashboard
// chevron next to the scheduled-checks toggle.
const scheduledChecksRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/scheduled-checks",
	component: ScheduledChecksPage,
});
// The Install page (pm/install_brew.mdx §4, pm/install_npm.mdx §6): reached by a preflight
// diversion from a run (?from + ?intent resume it afterward, §8) or proactively from Settings.
const installRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/install",
	component: InstallPage,
	validateSearch: (
		search: Record<string, unknown>,
	): { manager?: string; from?: string; intent?: string } => ({
		...(typeof search.manager === "string" ? { manager: search.manager } : {}),
		...(typeof search.from === "string" ? { from: search.from } : {}),
		...(typeof search.intent === "string" ? { intent: search.intent } : {}),
	}),
});
const settingsIndexRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/settings",
	component: SettingsPage,
});
const settingsSectionRoute = createRoute({
	getParentRoute: () => appLayoutRoute,
	path: "/settings/$section",
	component: SettingsPage,
});

const routeTree = rootRoute.addChildren([
	signInRoute,
	ssoCallbackRoute,
	appLayoutRoute.addChildren([
		dashboardRoute,
		domainsRoute,
		runDetailRoute,
		runReportRoute,
		dmarcRoute,
		// The static `check/:checkKey` explainer routes register ahead of the `:problemId` param
		// routes (pm/checks/dmarc.mdx §6.3).
		dmarcCheckRoute,
		runDmarcCheckRoute,
		dmarcProblemRoute,
		runDmarcRoute,
		runDmarcProblemRoute,
		dnsRoute,
		dnsRunRoute,
		dnsCheckRoute,
		dnsCheckAliasRoute,
		dnsProblemRoute,
		dkimRoute,
		dkimProblemRoute,
		dkimRunRoute,
		dkimRunProblemRoute,
		spfRoute,
		spfRunRoute,
		spfProblemRoute,
		contentScoringRoute,
		auditsRoute,
		blacklistsRoute,
		dnssecExpiryRoute,
		dnssecRoute,
		domainBlacklistsRoute,
		runBlacklistsRoute,
		blacklistDomainRoute,
		blacklistStateRoute,
		runBlacklistStateRoute,
		domainBlacklistStateRoute,
		runBlacklistZoneRoute,
		blacklistZoneRoute,
		runBlacklistTargetRoute,
		blacklistTargetRoute,
		reportsRoute,
		domainReportsRoute,
		scheduledChecksRoute,
		installRoute,
		settingsIndexRoute,
		settingsSectionRoute,
	]),
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
	interface Register {
		router: typeof router;
	}
}
