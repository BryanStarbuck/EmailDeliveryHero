import { Link } from "@tanstack/react-router";
import { ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Shared chrome for the two DNSSEC fleet boards (pm/checks/dnssec.mdx §22.5): the page title and the
 * two-tab strip ("Fleet" → /dnssec, "Expiry radar" → /dnssec/expiry). Kept in one component so both
 * routes render an identical header and the active tab is unambiguous.
 */
export function DnssecFleetHeader({
	active,
}: {
	active: "fleet" | "expiry";
}) {
	return (
		<div className="mb-5">
			<div className="mb-3 flex items-center gap-2">
				<ShieldCheck className="h-6 w-6 text-[var(--edh-primary)]" />
				<h1 className="text-2xl font-bold">DNSSEC</h1>
			</div>
			<p className="mb-4 max-w-2xl text-sm text-[var(--edh-muted)]">
				Cross-domain DNSSEC hygiene. A broken chain takes a domain dark to
				validating resolvers; an expiring RRSIG is a silent countdown to the
				same outage. These boards surface both across your whole fleet.
			</p>
			<nav className="flex gap-1 border-b border-[var(--edh-border)]">
				<Tab to="/dnssec" label="Fleet" active={active === "fleet"} />
				<Tab
					to="/dnssec/expiry"
					label="Expiry radar"
					active={active === "expiry"}
				/>
			</nav>
		</div>
	);
}

function Tab({
	to,
	label,
	active,
}: {
	to: string;
	label: string;
	active: boolean;
}) {
	return (
		<Link
			to={to}
			className={cn(
				"-mb-px border-b-2 px-4 py-2 text-sm font-medium",
				active
					? "border-[var(--edh-primary)] text-[var(--edh-primary)]"
					: "border-transparent text-[var(--edh-muted)] hover:text-[var(--edh-fg)]",
			)}
		>
			{label}
		</Link>
	);
}
