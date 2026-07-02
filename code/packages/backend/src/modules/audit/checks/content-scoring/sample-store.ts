import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readJson, writeJson } from "@shared/json-store";
import { stateSubdir } from "@shared/state-dir";

/**
 * The per-domain sample-message store (pm/checks/content_scoring.mdx §5). This module is the ONLY
 * code that knows sample files live under `~/.email_delivery_hero/samples/<domainId>/` — the raw
 * `.eml` is written to `samples/<domainId>/<sampleId>.eml` (the `raw_path`) and an
 * `samples/<domainId>/index.json` array holds the metadata rows. One sample is `active` per domain
 * (the one scored); history is retained. A later move to Postgres (`content_sample_messages`)
 * touches this module alone (acceptance criterion 10).
 */

/** Reject samples larger than ~10 MB (pm/checks/content_scoring.mdx §3 edge cases). */
export const MAX_SAMPLE_BYTES = 10 * 1024 * 1024;

/** One row of `content_sample_messages` (camelCase in the JSON store, snake over the API). */
export interface ContentSampleRecord {
	id: string;
	domainId: string;
	uploadedAt: string;
	/** Absolute path to the stored .eml (large bodies live on disk, never in index.json). */
	rawPath: string | null;
	/** Inline raw source for small pasted samples; one of rawPath/rawText is always set. */
	rawText: string | null;
	/** Parsed From: header for display ("which message was graded"). */
	fromHeader: string | null;
	/** Parsed Subject: header for display. */
	subject: string | null;
	/** The sample currently scored — at most one active per domain. */
	active: boolean;
	byteSize: number;
}

/** Inline pasted samples up to this size in index.json; larger bodies go to the .eml file only. */
const INLINE_LIMIT_BYTES = 64 * 1024;

function domainDir(domainId: string): string {
	return stateSubdir("samples", domainId);
}

function indexPath(domainId: string): string {
	return join(domainDir(domainId), "index.json");
}

/** All stored samples for a domain, newest upload first. */
export function listSamples(domainId: string): ContentSampleRecord[] {
	return readJson<ContentSampleRecord[]>(indexPath(domainId), []).sort((a, b) =>
		b.uploadedAt.localeCompare(a.uploadedAt),
	);
}

/** The sample currently scored for the domain, or null when none was ever uploaded. */
export function getActiveSample(domainId: string): ContentSampleRecord | null {
	return listSamples(domainId).find((s) => s.active) ?? null;
}

/** The raw RFC 5322 source of one stored sample (inline text or the .eml on disk). */
export function readSampleRaw(sample: ContentSampleRecord): string | null {
	if (sample.rawText !== null && sample.rawText !== undefined)
		return sample.rawText;
	if (sample.rawPath && existsSync(sample.rawPath)) {
		try {
			return readFileSync(sample.rawPath, "utf8");
		} catch {
			return null;
		}
	}
	return null;
}

/** Unfold one RFC 5322 header from the raw source (headers end at the first blank line). */
function parseHeader(raw: string, name: string): string | null {
	const headerBlock = raw.split(/\r?\n\r?\n/, 1)[0] ?? "";
	const lines = headerBlock.split(/\r?\n/);
	const prefix = `${name.toLowerCase()}:`;
	for (let i = 0; i < lines.length; i++) {
		if (lines[i].toLowerCase().startsWith(prefix)) {
			let value = lines[i].slice(prefix.length);
			// RFC 5322 folding: continuation lines start with whitespace.
			for (let j = i + 1; j < lines.length && /^[ \t]/.test(lines[j]); j++)
				value += ` ${lines[j].trim()}`;
			return value.trim() || null;
		}
	}
	return null;
}

/**
 * Persist an uploaded/pasted sample (pm/checks/content_scoring.mdx §8 AC 2): writes the raw source
 * to `samples/<domainId>/<sampleId>.eml`, marks the new row `active`, deactivates any prior active
 * sample (history retained), and records the parsed `from_header`/`subject`. Oversized samples are
 * rejected before anything touches disk.
 */
export function saveSample(domainId: string, raw: string): ContentSampleRecord {
	const byteSize = Buffer.byteLength(raw, "utf8");
	if (byteSize === 0) throw new Error("Sample message is empty");
	if (byteSize > MAX_SAMPLE_BYTES) {
		throw new Error(
			`Sample message is too large (${byteSize} bytes; max ${MAX_SAMPLE_BYTES})`,
		);
	}
	const id = randomUUID();
	const rawPath = join(domainDir(domainId), `${id}.eml`);
	writeFileSync(rawPath, raw, "utf8");
	const record: ContentSampleRecord = {
		id,
		domainId,
		uploadedAt: new Date().toISOString(),
		rawPath,
		rawText: byteSize <= INLINE_LIMIT_BYTES ? raw : null,
		fromHeader: parseHeader(raw, "From"),
		subject: parseHeader(raw, "Subject"),
		active: true,
		byteSize,
	};
	const rows = readJson<ContentSampleRecord[]>(indexPath(domainId), []).map(
		(s) => ({
			...s,
			active: false,
		}),
	);
	rows.push(record);
	writeJson(indexPath(domainId), rows);
	return record;
}

/** Delete one stored sample (and its .eml). Deleting the active sample leaves the domain sample-less. */
export function deleteSample(domainId: string, sampleId: string): boolean {
	const rows = readJson<ContentSampleRecord[]>(indexPath(domainId), []);
	const target = rows.find((s) => s.id === sampleId);
	if (!target) return false;
	if (target.rawPath && existsSync(target.rawPath)) {
		try {
			unlinkSync(target.rawPath);
		} catch {
			/* best-effort file cleanup; the index row still goes away */
		}
	}
	writeJson(
		indexPath(domainId),
		rows.filter((s) => s.id !== sampleId),
	);
	return true;
}
