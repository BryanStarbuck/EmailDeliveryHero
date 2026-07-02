import { RefreshCw } from "lucide-react";
import { useScanProgress } from "@/scan/ScanProgressContext";

/**
 * The scan-progress dock (pm/progress_ui.mdx §3). While a manual scan runs, a fixed stack of
 * per-domain "Running <domain>" cards sits in the bottom-left — offset past the 256px left bar so it
 * never overlaps the nav, and above the toast stack. Each card carries a spinning circular-arrows
 * icon; a card exists iff that domain's scan is in flight, so the stack drains card-by-card as
 * domains finish. Renders nothing when idle.
 */
export function ScanProgressDock() {
	const active = useScanProgress();
	if (active.length === 0) return null;

	return (
		// left: 272px clears the 256px bar (16px gutter); bottom: 88px sits above the toast stack.
		<div
			role="status"
			aria-label="Scan progress"
			className="fixed bottom-[88px] left-[272px] z-40 flex flex-col gap-2"
		>
			{active.map((s) => (
				<div
					key={s.domainId}
					className="flex min-w-[240px] max-w-[340px] items-center gap-2.5 rounded-lg border border-[var(--edh-border)] bg-white px-3 py-2 text-sm shadow-md"
				>
					<RefreshCw
						aria-hidden
						className="h-4 w-4 shrink-0 animate-spin text-[var(--edh-primary)]"
					/>
					<span className="truncate">
						<span className="text-[var(--edh-muted)]">Running </span>
						<span className="font-medium">{s.domain}</span>
					</span>
				</div>
			))}
		</div>
	);
}
