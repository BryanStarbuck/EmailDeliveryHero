import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "./axios";

/**
 * The Install contract (pm/install_brew.mdx §7, pm/install_npm.mdx §6). Detects which Brew/OS tools
 * and npm/pnpm packages are missing for a pending run, installs the selected ones, and streams
 * per-row progress. Reached by a preflight diversion from a run (§8) or proactively from Settings.
 */

export type ToolManager = "brew" | "npm" | "all";
export type ToolCategory =
	| "dns"
	| "spf"
	| "dkim"
	| "dmarc"
	| "blacklist"
	| "spam"
	| "tls"
	| "general";
export type ToolTier = "default" | "extended";

export interface ToolStatus {
	id: string;
	manager: "brew" | "npm" | "special";
	category: ToolCategory;
	tier: ToolTier;
	label: string;
	summary: string;
	binaries: string[];
	installCmd: string;
	install: string;
	autoInstallable: boolean;
	notes?: string;
	installed: boolean;
	resolved?: string;
}

export interface PreflightResult {
	manager: ToolManager;
	brewPresent: boolean | null;
	pnpmEnable: "corepack" | "npm" | "none";
	missing: ToolStatus[];
	optional: ToolStatus[];
	installed: ToolStatus[];
}

export interface InstallItemResult {
	id: string;
	ok: boolean;
	code: number | null;
	tail: string;
}

export interface InstallJobStatus {
	jobId: string;
	done: boolean;
	phases: Record<string, "queued" | "installing" | "done" | "failed">;
	results: InstallItemResult[];
}

/** GET /api/install/preflight — the scope-aware missing / optional / installed split. */
export function usePreflight(manager: ToolManager, scope: string | undefined) {
	return useQuery({
		queryKey: ["install", "preflight", manager, scope ?? "all"] as const,
		queryFn: async () =>
			(
				await api.get<PreflightResult>("/install/preflight", {
					params: { manager, scope },
				})
			).data,
	});
}

/** Imperative preflight — used by the run funnel to decide "divert or run" (pm/install_brew.mdx §1). */
export async function fetchPreflight(
	manager: ToolManager,
	scope: string,
): Promise<PreflightResult> {
	return (
		await api.get<PreflightResult>("/install/preflight", {
			params: { manager, scope },
		})
	).data;
}

/** POST /api/install/run — start a serial install of the selected ids; returns a jobId. */
export function useStartInstall() {
	return useMutation({
		mutationFn: async (ids: string[]) =>
			(
				await api.post<{ jobId: string; ids: string[] }>("/install/run", {
					ids,
				})
			).data,
	});
}

/** Poll one install job's status (poll fallback for the SSE stream). */
export async function fetchJobStatus(jobId: string): Promise<InstallJobStatus> {
	return (await api.get<InstallJobStatus>(`/install/run/${jobId}`)).data;
}

/** Force a fresh detection (Re-detect). */
export async function redetect(manager: ToolManager): Promise<ToolStatus[]> {
	return (
		await api.post<ToolStatus[]>("/install/detect", undefined, {
			params: { manager },
		})
	).data;
}
