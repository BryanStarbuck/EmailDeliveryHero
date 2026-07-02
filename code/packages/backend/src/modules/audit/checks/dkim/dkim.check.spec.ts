import { generateKeyPairSync } from "node:crypto";
import {
	analyzeAdspLegacy,
	analyzeSelectorRecord,
	type DkimResults,
	decodeDkimKey,
	deriveDkimProblemStates,
	parseDkimRecord,
	recordSetsEqual,
} from "./dkim.check";

/** Generate a real RSA public key of the given size, base64-encoded the way DKIM publishes it. */
function rsaP(bits: number): string {
	const { publicKey } = generateKeyPairSync("rsa", { modulusLength: bits });
	return publicKey.export({ format: "der", type: "spki" }).toString("base64");
}

/** Split a record into the ≤255-byte character-strings a healthy DNS answer uses. */
const chunksOf = (record: string) =>
	Array.from({ length: Math.ceil(record.length / 255) }, (_, i) =>
		Math.min(255, record.length - i * 255),
	);

const analyze = (
	record: string,
	source: "configured" | "discovered" = "configured",
) =>
	analyzeSelectorRecord("example.com", "s1", source, [record], {
		resolvedVia: "txt",
		cnameTarget: null,
		chunkLengths: chunksOf(record),
	});

const byId = (a: ReturnType<typeof analyze>, id: string) =>
	a.findings.find((f) => f.id === id);

describe("parseDkimRecord", () => {
	it("tokenizes tag=value pairs, trimming and lower-casing names", () => {
		expect(parseDkimRecord("v=DKIM1; K=rsa ;p=abc")).toEqual({
			v: "DKIM1",
			k: "rsa",
			p: "abc",
		});
	});

	it("keeps the first occurrence of a duplicated tag and tolerates empty tokens", () => {
		expect(parseDkimRecord("v=DKIM1;; p=abc; p=def;")).toEqual({
			v: "DKIM1",
			p: "abc",
		});
	});

	it("parses an empty p= (revocation) as an empty string", () => {
		expect(parseDkimRecord("v=DKIM1; p=")).toEqual({ v: "DKIM1", p: "" });
	});
});

describe("decodeDkimKey", () => {
	it("reads the modulus bits of a real 2048-bit RSA key", () => {
		const d = decodeDkimKey(rsaP(2048), "rsa");
		expect(d.valid).toBe(true);
		expect(d.keyBits).toBe(2048);
		expect(d.keySha256).toHaveLength(64);
	});

	it("reads 1024-bit keys too", () => {
		expect(decodeDkimKey(rsaP(1024), "rsa").keyBits).toBe(1024);
	});

	it("rejects non-base64 input", () => {
		const d = decodeDkimKey("not base64!!!", "rsa");
		expect(d.valid).toBe(false);
	});

	it("rejects base64 that is not a public key (PEM-paste corruption)", () => {
		const d = decodeDkimKey(
			Buffer.from("-----BEGIN PUBLIC KEY-----").toString("base64"),
			"rsa",
		);
		expect(d.valid).toBe(false);
	});

	it("accepts a raw 32-byte ed25519 key with null bits", () => {
		const d = decodeDkimKey(Buffer.alloc(32, 7).toString("base64"), "ed25519");
		expect(d.valid).toBe(true);
		expect(d.keyBits).toBeNull();
	});

	it("rejects an ed25519 key of the wrong length", () => {
		expect(
			decodeDkimKey(Buffer.alloc(31, 7).toString("base64"), "ed25519").valid,
		).toBe(false);
	});
});

describe("analyzeSelectorRecord", () => {
	it("passes a healthy 2048-bit record", () => {
		const a = analyze(`v=DKIM1; k=rsa; p=${rsaP(2048)}`);
		expect(a.result.present).toBe(true);
		expect(a.result.parses).toBe(true);
		expect(a.result.key_bits).toBe(2048);
		expect(byId(a, "dkim.keylength.s1")?.severity).toBe("ok");
		expect(byId(a, "dkim.testflag.s1")?.severity).toBe("ok");
		expect(
			a.findings.every(
				(f) => f.severity !== "critical" && f.severity !== "warning",
			),
		).toBe(true);
	});

	it("flags an empty p= as revoked — critical when configured, info when discovered", () => {
		expect(byId(analyze("v=DKIM1; p="), "dkim.revoked.s1")?.severity).toBe(
			"critical",
		);
		expect(
			byId(analyze("v=DKIM1; p=", "discovered"), "dkim.revoked.s1")?.severity,
		).toBe("info");
	});

	it("flags an unparseable key as critical", () => {
		const a = analyze("v=DKIM1; k=rsa; p=!!bad!!");
		expect(byId(a, "dkim.parses.s1")?.severity).toBe("critical");
		expect(a.result.parses).toBe(false);
	});

	it("warns on a 1024-bit key and rejects a sub-1024 key", () => {
		expect(
			byId(analyze(`v=DKIM1; p=${rsaP(1024)}`), "dkim.keylength.s1")?.severity,
		).toBe("warning");
		expect(
			byId(analyze(`v=DKIM1; p=${rsaP(512)}`), "dkim.keylength.s1")?.severity,
		).toBe("critical");
	});

	it("warns on t=y and records the flag; t=s is info only", () => {
		const test = analyze(`v=DKIM1; t=y; p=${rsaP(2048)}`);
		expect(byId(test, "dkim.testflag.s1")?.severity).toBe("warning");
		expect(test.result.has_test_flag).toBe(true);

		const strict = analyze(`v=DKIM1; t=s; p=${rsaP(2048)}`);
		expect(byId(strict, "dkim.testflag.s1")?.severity).toBe("ok");
		expect(byId(strict, "dkim.flags.s1")?.severity).toBe("info");
		expect(strict.result.has_strict_flag).toBe(true);
	});

	it("flags h=sha1-only as critical but tolerates sha1 alongside sha256", () => {
		expect(
			byId(analyze(`v=DKIM1; h=sha1; p=${rsaP(2048)}`), "dkim.algorithm.s1")
				?.severity,
		).toBe("critical");
		expect(
			byId(
				analyze(`v=DKIM1; h=sha1:sha256; p=${rsaP(2048)}`),
				"dkim.algorithm.s1",
			),
		).toBeUndefined();
	});

	it("warns when the service type excludes email", () => {
		expect(
			byId(analyze(`v=DKIM1; s=tlsrpt; p=${rsaP(2048)}`), "dkim.flags.s1")
				?.severity,
		).toBe("warning");
		expect(
			byId(analyze(`v=DKIM1; s=email; p=${rsaP(2048)}`), "dkim.flags.s1"),
		).toBeUndefined();
	});

	it("flags an invalid v= tag as critical", () => {
		expect(
			byId(analyze(`v=DKIM2; p=${rsaP(2048)}`), "dkim.parses.s1")?.severity,
		).toBe("critical");
	});

	it("warns when multiple TXT records answer at one selector (RFC 6376 §3.6.2.2)", () => {
		const rec = `v=DKIM1; p=${rsaP(2048)}`;
		const a = analyzeSelectorRecord(
			"example.com",
			"s1",
			"configured",
			["something-else", rec],
			{
				resolvedVia: "txt",
				cnameTarget: null,
				chunkLengths: chunksOf(rec),
			},
		);
		expect(byId(a, "dkim.single_record.s1")?.severity).toBe("warning");
		// …but still evaluates the DKIM-shaped record.
		expect(a.result.parses).toBe(true);
	});

	it("warns on an oversize TXT character-string", () => {
		const rec = `v=DKIM1; p=${rsaP(2048)}`;
		const a = analyzeSelectorRecord("example.com", "s1", "configured", [rec], {
			resolvedVia: "txt",
			cnameTarget: null,
			chunkLengths: [300],
		});
		expect(byId(a, "dkim.record_size.s1")?.severity).toBe("warning");
		expect(a.result.oversize_chunk).toBe(true);
	});

	it("records a CNAME delegation on the result", () => {
		const rec = `v=DKIM1; p=${rsaP(2048)}`;
		const a = analyzeSelectorRecord("example.com", "s1", "configured", [rec], {
			resolvedVia: "cname",
			cnameTarget: "s1.domainkey.u123.wl001.sendgrid.net",
			chunkLengths: chunksOf(rec),
		});
		expect(a.result.resolved_via).toBe("cname");
		expect(a.result.cname_target).toBe("s1.domainkey.u123.wl001.sendgrid.net");
	});

	it("notes unknown tags as info", () => {
		expect(
			byId(analyze(`v=DKIM1; x=oops; p=${rsaP(2048)}`), "dkim.flags.s1")
				?.severity,
		).toBe("info");
	});
});

describe("recordSetsEqual", () => {
	it("compares record SETS, ignoring answer order (round-robin is never a disagreement)", () => {
		expect(recordSetsEqual(["a", "b"], ["b", "a"])).toBe(true);
		expect(recordSetsEqual([], [])).toBe(true);
		expect(recordSetsEqual(["a"], [])).toBe(false);
		expect(recordSetsEqual(["a"], ["b"])).toBe(false);
		expect(recordSetsEqual(["a", "a"], ["a", "b"])).toBe(false);
	});
});

describe("analyzeAdspLegacy (pm/checks/dkim.mdx §4 dkim.adsp_legacy)", () => {
	it("returns a single ok finding when neither legacy name answers", () => {
		const out = analyzeAdspLegacy("example.com", [], []);
		expect(out.findings).toHaveLength(1);
		expect(out.findings[0]?.id).toBe("dkim.adsp_legacy");
		expect(out.findings[0]?.severity).toBe("ok");
		expect(out.adsp).toEqual({ present: false, record: null, practice: null });
		expect(out.legacy_domainkeys).toEqual({ present: false, record: null });
	});

	it("flags ADSP dkim=discardable as warning with the parsed practice", () => {
		const out = analyzeAdspLegacy("example.com", ["dkim=discardable"], []);
		expect(out.adsp).toEqual({
			present: true,
			record: "dkim=discardable",
			practice: "discardable",
		});
		const f = out.findings.find((x) => x.id === "dkim.adsp_legacy.adsp");
		expect(f?.severity).toBe("warning");
	});

	it("flags any other ADSP value as info", () => {
		const out = analyzeAdspLegacy("example.com", ["dkim=all"], []);
		expect(out.adsp.practice).toBe("all");
		expect(
			out.findings.find((x) => x.id === "dkim.adsp_legacy.adsp")?.severity,
		).toBe("info");
	});

	it("flags a DomainKeys o= policy leftover as info and records it", () => {
		const out = analyzeAdspLegacy("example.com", [], ["o=-; n=notes"]);
		expect(out.legacy_domainkeys).toEqual({
			present: true,
			record: "o=-; n=notes",
		});
		expect(
			out.findings.find((x) => x.id === "dkim.adsp_legacy.domainkeys")
				?.severity,
		).toBe("info");
	});

	it("calls out a key record at the bare _domainkey name as a key at the wrong name", () => {
		const out = analyzeAdspLegacy(
			"example.com",
			[],
			[`v=DKIM1; p=${rsaP(1024)}`],
		);
		// Not a policy leftover — the observation block stays empty, the finding explains the mistake.
		expect(out.legacy_domainkeys.present).toBe(false);
		const f = out.findings.find((x) => x.id === "dkim.adsp_legacy.domainkeys");
		expect(f?.severity).toBe("info");
		expect(f?.title).toContain("bare _domainkey");
	});
});

describe("deriveDkimProblemStates — PS-17 / PS-18 (append-only ids)", () => {
	const baseResults = { working_selectors: 1 } as DkimResults;
	const finding = (
		id: string,
		severity: "ok" | "info" | "warning" | "critical",
	) => ({
		id,
		checkId: "dkim",
		title: id,
		severity,
		detail: id,
	});

	it("maps a resolver split view to PS-18", () => {
		const states = deriveDkimProblemStates(
			[finding("dkim.resolver_agreement.s1", "warning")],
			baseResults,
		);
		expect(states).toContain("PS-18");
	});

	it("never maps the info 'could not cross-check' to PS-18", () => {
		const states = deriveDkimProblemStates(
			[finding("dkim.resolver_agreement.s1", "info")],
			baseResults,
		);
		expect(states).not.toContain("PS-18");
		expect(states).toContain("PS-00");
	});

	it("maps ADSP/DomainKeys leftovers to PS-17 at warning AND info severity", () => {
		expect(
			deriveDkimProblemStates(
				[finding("dkim.adsp_legacy.adsp", "warning")],
				baseResults,
			),
		).toContain("PS-17");
		expect(
			deriveDkimProblemStates(
				[finding("dkim.adsp_legacy.domainkeys", "info")],
				baseResults,
			),
		).toContain("PS-17");
		// The healthy ok row never matches.
		const healthy = deriveDkimProblemStates(
			[finding("dkim.adsp_legacy", "ok")],
			baseResults,
		);
		expect(healthy).not.toContain("PS-17");
		expect(healthy).toContain("PS-00");
	});
});
