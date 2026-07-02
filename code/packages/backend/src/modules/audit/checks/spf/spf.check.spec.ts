import {
	allQualifierOf,
	analyzeSpfTerms,
	findMacroError,
	ipInCidr,
	ipv6ToBigInt,
	parseSpfRecord,
} from "./spf.check";

const analyze = (raw: string) =>
	analyzeSpfTerms("example.com", raw, parseSpfRecord(raw));
const byId = (findings: ReturnType<typeof analyze>, id: string) =>
	findings.find((f) => f.id === id);

describe("parseSpfRecord", () => {
	it("tokenizes qualifiers, mechanisms, values, and modifiers", () => {
		const p = parseSpfRecord(
			"v=spf1 ip4:203.0.113.0/24 -include:_spf.example.net ~all",
		);
		expect(p.mechanisms).toEqual([
			{
				qualifier: "+",
				type: "ip4",
				value: "203.0.113.0/24",
				lookup: false,
				raw: "ip4:203.0.113.0/24",
			},
			{
				qualifier: "-",
				type: "include",
				value: "_spf.example.net",
				lookup: true,
				raw: "-include:_spf.example.net",
			},
			{ qualifier: "~", type: "all", value: null, lookup: false, raw: "~all" },
		]);
		expect(p.syntaxErrors).toEqual([]);
	});

	it("parses redirect= and exp= modifiers and ignores unknown modifiers", () => {
		const p = parseSpfRecord(
			"v=spf1 redirect=_spf.example.com unknown-mod=whatever",
		);
		expect(p.redirect).toBe("_spf.example.com");
		expect(p.mechanisms.filter((m) => m.type === "redirect")).toHaveLength(1);
		expect(p.syntaxErrors).toEqual([]);
	});

	it("flags unknown mechanisms, bad CIDR ranges, and values on all", () => {
		expect(
			parseSpfRecord("v=spf1 inlcude:foo.com -all").syntaxErrors.join(),
		).toContain("unknown mechanism");
		expect(
			parseSpfRecord("v=spf1 ip4:1.2.3.4/33 -all").syntaxErrors.join(),
		).toContain("prefix out of range");
		expect(
			parseSpfRecord("v=spf1 ip6:2001:db8::/129 -all").syntaxErrors.join(),
		).toContain("prefix out of range");
		expect(
			parseSpfRecord("v=spf1 ip4:not-an-ip -all").syntaxErrors.join(),
		).toContain("malformed ip4");
		expect(
			parseSpfRecord("v=spf1 all:everything").syntaxErrors.join(),
		).toContain('"all" takes no value');
		expect(
			parseSpfRecord("v=spf1 include: -all").syntaxErrors.join(),
		).toContain("requires a domain");
	});

	it("accepts a and mx with optional domain and dual-cidr suffixes", () => {
		const p = parseSpfRecord(
			"v=spf1 a mx:mail.example.com a:web.example.com/24 -all",
		);
		expect(p.syntaxErrors).toEqual([]);
		expect(p.mechanisms.filter((m) => m.lookup)).toHaveLength(3);
	});
});

describe("findMacroError", () => {
	it("accepts valid macros and literal escapes", () => {
		expect(findMacroError("%{i}._spf.%{d}")).toBeNull();
		expect(findMacroError("%{ir}.%{l1r+-}._spf.%{d2}")).toBeNull();
		expect(findMacroError("100%%off")).toBeNull();
		expect(findMacroError("no-macros-here")).toBeNull();
	});

	it("rejects stray %, unterminated, and unknown macro letters", () => {
		expect(findMacroError("50%off")).toContain("stray");
		expect(findMacroError("%{i")).toContain("unterminated");
		expect(findMacroError("%{x}")).toContain("invalid macro");
	});
});

describe("ipInCidr / ipv6ToBigInt", () => {
	it("matches IPv4 addresses against CIDRs and bare IPs", () => {
		expect(ipInCidr("203.0.113.10", "203.0.113.0/24")).toBe(true);
		expect(ipInCidr("203.0.114.10", "203.0.113.0/24")).toBe(false);
		expect(ipInCidr("203.0.113.10", "203.0.113.10")).toBe(true);
		expect(ipInCidr("1.2.3.4", "0.0.0.0/0")).toBe(true);
	});

	it("matches IPv6 addresses including :: compression", () => {
		expect(ipv6ToBigInt("::1")).toBe(1n);
		expect(ipInCidr("2001:db8::5", "2001:db8::/32")).toBe(true);
		expect(ipInCidr("2001:db9::5", "2001:db8::/32")).toBe(false);
		expect(ipInCidr("2001:db8::5", "2001:db8::5")).toBe(true);
	});

	it("never cross-matches v4 against v6", () => {
		expect(ipInCidr("2001:db8::5", "203.0.113.0/24")).toBe(false);
		expect(ipInCidr("203.0.113.10", "2001:db8::/32")).toBe(false);
	});
});

describe("analyzeSpfTerms", () => {
	it("passes a healthy record with ok findings", () => {
		const f = analyze("v=spf1 include:_spf.google.com ip4:203.0.113.0/24 ~all");
		expect(byId(f, "spf.syntax")?.severity).toBe("ok");
		expect(byId(f, "spf.all")?.severity).toBe("ok");
		expect(
			f.every((x) => x.severity !== "critical" && x.severity !== "warning"),
		).toBe(true);
	});

	it("flags +all as critical and ?all / missing all as warnings", () => {
		expect(byId(analyze("v=spf1 ip4:1.2.3.4 +all"), "spf.all")?.severity).toBe(
			"critical",
		);
		expect(byId(analyze("v=spf1 ip4:1.2.3.4 ?all"), "spf.all")?.severity).toBe(
			"warning",
		);
		expect(byId(analyze("v=spf1 ip4:1.2.3.4"), "spf.all")?.severity).toBe(
			"warning",
		);
	});

	it("does not warn about a missing all when redirect= is present", () => {
		expect(
			byId(analyze("v=spf1 redirect=_spf.example.org"), "spf.all"),
		).toBeUndefined();
	});

	it("warns on mechanisms after all and on redirect combined with all", () => {
		const f = analyze("v=spf1 ~all ip4:1.2.3.4 redirect=_spf.example.org");
		expect(byId(f, "spf.all_terminal")?.severity).toBe("warning");
		expect(byId(f, "spf.redirect")?.severity).toBe("warning");
	});

	it("warns on the deprecated ptr mechanism and duplicate terms", () => {
		const f = analyze("v=spf1 ptr include:a.example include:a.example -all");
		expect(byId(f, "spf.ptr")?.severity).toBe("warning");
		expect(byId(f, "spf.dup_mechanisms")?.severity).toBe("warning");
	});

	it("flags /0 ranges as critical and very broad ranges as warnings", () => {
		expect(
			byId(analyze("v=spf1 ip4:0.0.0.0/0 -all"), "spf.cidr_scope")?.severity,
		).toBe("critical");
		expect(
			byId(analyze("v=spf1 ip4:10.0.0.0/7 -all"), "spf.cidr_scope")?.severity,
		).toBe("warning");
		expect(
			byId(analyze("v=spf1 ip4:10.0.0.0/24 -all"), "spf.cidr_scope"),
		).toBeUndefined();
	});

	it("reports syntax and macro errors as criticals", () => {
		expect(
			byId(analyze("v=spf1 ip4:1.2.3.4/33 -all"), "spf.syntax")?.severity,
		).toBe("critical");
		expect(
			byId(analyze("v=spf1 exists:%{x}.example.com -all"), "spf.macro")
				?.severity,
		).toBe("critical");
	});

	it("warns when the record risks UDP truncation", () => {
		const long = `v=spf1 ${Array.from({ length: 30 }, (_, i) => `ip4:203.0.${i}.0/24`).join(" ")} -all`;
		expect(long.length).toBeGreaterThan(450);
		expect(byId(analyze(long), "spf.length")?.severity).toBe("warning");
	});
});

describe("allQualifierOf", () => {
	it("reads the terminal all qualifier", () => {
		expect(allQualifierOf(parseSpfRecord("v=spf1 -all"))).toBe("-all");
		expect(allQualifierOf(parseSpfRecord("v=spf1 ~all"))).toBe("~all");
		expect(allQualifierOf(parseSpfRecord("v=spf1 all"))).toBe("+all");
		expect(allQualifierOf(parseSpfRecord("v=spf1 ip4:1.2.3.4"))).toBe(null);
	});
});
