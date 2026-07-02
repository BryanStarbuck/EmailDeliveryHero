import { MoreVertical } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

export interface RowMenuItem {
	label: string;
	danger?: boolean;
	onClick: () => void;
}

/**
 * The ⋮ triple-dot pull-down used on table rows (pm/dashboard.mdx §4.3/§4.4, pm/reports.mdx §3.4).
 * The menu renders through a portal to document.body with fixed positioning so it can never be
 * clipped by an `overflow-hidden` table wrapper — it floats above the table and flows past its
 * bottom edge. Positioned from the trigger's viewport rect; closed by the invisible backdrop,
 * any item click, or any scroll/resize (a fixed menu would drift away from its trigger).
 */
export function RowMenu({
	label,
	items,
}: {
	label: string;
	items: RowMenuItem[];
}) {
	const [open, setOpen] = useState(false);
	const [pos, setPos] = useState<{ top: number; right: number } | null>(null);
	const btnRef = useRef<HTMLButtonElement>(null);

	const openMenu = () => {
		const rect = btnRef.current?.getBoundingClientRect();
		if (!rect) return;
		setPos({ top: rect.bottom + 4, right: window.innerWidth - rect.right });
		setOpen(true);
	};

	useEffect(() => {
		if (!open) return;
		const close = () => setOpen(false);
		window.addEventListener("scroll", close, true);
		window.addEventListener("resize", close);
		return () => {
			window.removeEventListener("scroll", close, true);
			window.removeEventListener("resize", close);
		};
	}, [open]);

	return (
		<>
			<button
				ref={btnRef}
				type="button"
				onClick={(e) => {
					e.stopPropagation();
					if (open) {
						setOpen(false);
					} else {
						openMenu();
					}
				}}
				aria-label={label}
				aria-haspopup="menu"
				aria-expanded={open}
				className="rounded p-1 text-[var(--edh-muted)] hover:bg-slate-100 hover:text-slate-700"
			>
				<MoreVertical className="h-4 w-4" />
			</button>
			{open &&
				pos &&
				createPortal(
					<>
						{/* Click-away backdrop — closes the menu without triggering anything underneath. */}
						<button
							type="button"
							aria-label="Close menu"
							onClick={(e) => {
								e.stopPropagation();
								setOpen(false);
							}}
							className="fixed inset-0 z-40 cursor-default"
						/>
						<div
							role="menu"
							style={{ top: pos.top, right: pos.right }}
							className="fixed z-50 w-56 rounded-md border border-[var(--edh-border)] bg-white py-1 shadow-lg"
						>
							{items.map((item) => (
								<button
									key={item.label}
									type="button"
									role="menuitem"
									onClick={(e) => {
										e.stopPropagation();
										setOpen(false);
										item.onClick();
									}}
									className={`block w-full px-3 py-2 text-left text-sm hover:bg-slate-100 ${
										item.danger ? "text-red-700" : "text-slate-900"
									}`}
								>
									{item.label}
								</button>
							))}
						</div>
					</>,
					document.body,
				)}
		</>
	);
}
