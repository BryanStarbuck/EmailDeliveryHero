import { createRequire } from "node:module";
import { locateTool } from "@shared/tool-runner";
import type { ToolCatalogEntry, ToolStatus } from "./catalog";

/**
 * Detection (pm/install_brew.mdx §5, pm/install_npm.mdx §5). Cheap-first, mostly in-process:
 *   - binary   → locateTool(any of the entry's binaries) (what a run will actually use)
 *   - node-module → require.resolve(pkg) from the backend node_modules
 *   - pnpm     → locateTool('pnpm')
 *   - workspace → node_modules present (resolve a known dep)
 *   - builtin  → always satisfied
 */

const require_ = createRequire(__filename);

/** Whether the monorepo workspace has been installed (node_modules present). */
function workspaceInstalled(): boolean {
	try {
		require_.resolve("@nestjs/core");
		return true;
	} catch {
		return false;
	}
}

/** Resolve an npm package from the backend node_modules; returns its path or null. */
function resolveModule(pkg: string): string | null {
	try {
		return require_.resolve(pkg);
	} catch {
		return null;
	}
}

export function detectEntry(entry: ToolCatalogEntry): ToolStatus {
	let installed = false;
	let resolved: string | undefined;

	switch (entry.detect) {
		case "builtin":
			installed = true;
			break;
		case "pnpm": {
			const p = locateTool("pnpm");
			installed = p !== null;
			resolved = p ?? undefined;
			break;
		}
		case "workspace":
			installed = workspaceInstalled();
			break;
		case "node-module": {
			const p = entry.pkg ? resolveModule(entry.pkg) : null;
			installed = p !== null;
			resolved = p ?? undefined;
			break;
		}
		default: {
			// binary: installed iff any provided binary resolves on PATH (ToolLocator semantics).
			for (const bin of entry.binaries) {
				const p = locateTool(bin);
				if (p) {
					installed = true;
					resolved = p;
					break;
				}
			}
		}
	}

	return { ...entry, installed, resolved };
}

export function detectAll(entries: ToolCatalogEntry[]): ToolStatus[] {
	return entries.map(detectEntry);
}

/** Is Homebrew present? (pm/install_brew.mdx §5.1) */
export function brewPresent(): boolean {
	return locateTool("brew") !== null;
}

/** Which enable-path to offer for pnpm (corepack preferred, then npm global). */
export function pnpmEnablePath(): "corepack" | "npm" | "none" {
	if (locateTool("corepack")) return "corepack";
	if (locateTool("npm")) return "npm";
	return "none";
}
