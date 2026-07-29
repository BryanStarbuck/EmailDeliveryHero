import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { stateSubdir } from "@shared/state-dir";

/**
 * The raw report payload store (pm/Email_Complaints.mdx §10.4 block 2, §13).
 *
 * The drill-down offers a **View raw report** link that pretty-prints the source XML/JSON for the
 * selected report. The parsed store (report-store.ts) keeps only the normalized shape, which is
 * lossy on purpose — so the decompressed payload is kept verbatim, once, beside it:
 *
 *   <state>/reports/<domainId>/raw/dmarc/<reporterOrg>-<reportId>.xml
 *   <state>/reports/<domainId>/raw/tlsrpt/<reporterOrg>-<reportDate>.json
 *
 * This is evidence, so it is written verbatim and never rewritten: the whole point of showing a user
 * the raw report is that it is the receiver's words, not ours. Reports ingested before this store
 * existed simply have no raw copy, and the API falls back to the normalized JSON.
 */

/** A path-safe file stem — the same rule report-store.ts uses, so the keys line up exactly. */
function safeStem(value: string): string {
	const cleaned = (value ?? "")
		.replace(/[^A-Za-z0-9._@+-]+/g, "_")
		.replace(/\.\./g, "_");
	return cleaned.length > 0 ? cleaned : "unknown";
}

function rawPath(
	domainId: string,
	kind: "dmarc" | "tlsrpt",
	reporterOrg: string,
	key: string,
): string {
	return join(
		stateSubdir("reports", safeStem(domainId), "raw", kind),
		`${safeStem(reporterOrg)}-${safeStem(key)}.${kind === "dmarc" ? "xml" : "json"}`,
	);
}

/**
 * Keep the decompressed payload for one report. Best-effort and write-once: a failure here must
 * never fail an ingest, because the parsed report — the thing the product actually runs on — has
 * already been stored successfully by the time this is called.
 */
export function saveRawReport(
	domainId: string,
	kind: "dmarc" | "tlsrpt",
	reporterOrg: string,
	key: string,
	payload: string,
): void {
	try {
		const path = rawPath(domainId, kind, reporterOrg, key);
		if (existsSync(path)) return;
		mkdirSync(dirname(path), { recursive: true });
		writeFileSync(path, payload, "utf8");
	} catch {
		// Evidence is a nicety; ingestion is not. Never let this throw into the ingest loop.
	}
}

/** The stored raw payload for one report, or null when none was kept. */
export function readRawReport(
	domainId: string,
	kind: "dmarc" | "tlsrpt",
	reporterOrg: string,
	key: string,
): string | null {
	try {
		const path = rawPath(domainId, kind, reporterOrg, key);
		return existsSync(path) ? readFileSync(path, "utf8") : null;
	} catch {
		return null;
	}
}
