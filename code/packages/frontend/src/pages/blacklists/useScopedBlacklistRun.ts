import { useParams } from "@tanstack/react-router";
import { useMemo } from "react";
import { useAuditRun, useDomainRuns } from "@/api/audit";
import { useBlacklistRun } from "@/api/blacklists";
import { useDomains } from "@/api/domains";
import type { AuditResult, BlacklistRunResults } from "@/api/types";

/**
 * Shared run resolution for the run-scoped Blacklists explainer pages
 * (pm/checks/blacklists.mdx §20): every explainer route exists in two shapes —
 * `/domains/$id/runs/$runId/blacklists/...` (one specific run) and the newest-run alias
 * `/domains/$id/blacklists/...`. Everything a page renders comes from that ONE run's
 * `blacklists` section; pages never silently mix runs (§20.8).
 */
export interface ScopedBlacklistRun {
	/** The monitored-domain id from the route (null on legacy name-keyed shorthands). */
	domainId: string | null;
	/** The domain name (resolved from the domain record or the run itself). */
	domainName: string | null;
	/** Present only on the run-scoped (non-alias) routes. */
	runId: string | undefined;
	/** The viewed run's blacklists section. */
	run: BlacklistRunResults | undefined;
	isLoading: boolean;
	/** True once the monitored-domain list has loaded (gates alias redirects). */
	domainsLoaded: boolean;
	/** This domain's runs that carry a Blacklists section, newest first (history strips). */
	domainRuns: AuditResult[];
}

export function useScopedBlacklistRun(): ScopedBlacklistRun {
	const params = useParams({ strict: false }) as {
		id?: string;
		runId?: string;
		domain?: string;
	};
	const { data: domains } = useDomains();
	const record = params.id
		? domains?.find((d) => d.id === params.id)
		: domains?.find((d) => d.name === params.domain);
	const domainName = record?.name ?? params.domain ?? null;
	const domainId = params.id ?? record?.id ?? null;

	// Newest-run alias reads the store's latest doc; a run-scoped view reads that run's report.
	const latest = useBlacklistRun(
		domainName ?? "",
		!params.runId && !!domainName,
	);
	const { data: auditRun, isLoading: runLoading } = useAuditRun(params.runId);
	const { data: allRuns } = useDomainRuns(domainId ?? undefined);

	const domainRuns = useMemo(
		() => (allRuns ?? []).filter((r) => r.results?.blacklist),
		[allRuns],
	);

	const run: BlacklistRunResults | undefined = params.runId
		? auditRun?.results?.blacklist
		: latest.data;

	return {
		domainId,
		domainName: domainName ?? run?.domain ?? null,
		runId: params.runId,
		run,
		isLoading: params.runId ? runLoading : latest.isLoading,
		domainsLoaded: domains !== undefined,
		domainRuns,
	};
}
