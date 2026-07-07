import type { LucideIcon } from "lucide-react";
import { ChevronDown } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

/**
 * The house "action-links row" (pm/page_actions.mdx) — the ONE way page-level actions render across
 * EmailDeliveryHero. A horizontal row of action HYPERLINKS placed directly under a page title, NOT a
 * dropdown. Modeled on the sister app's `.q-actions` row (Q/page_processing_queue.js setupActions).
 *
 * Each item is a link-colored, borderless control (this app's `--edh-primary` link token) with a
 * ~14px leading icon, underline on hover only, and a "·" separator between items. Items are always
 * visible; an optional "More ▾" overflow menu holds only the items explicitly flagged `overflow`.
 * Destructive actions tint red and route through a small web confirm modal — never `window.confirm`.
 *
 * A page's single primary CREATE/SAVE CTA (e.g. "Add domain", "Save") MAY stay a filled header
 * button; every other page action — re-runs, refreshes, exports, deletes — belongs in this row.
 */
export interface ActionLink {
	/** Visible label. */
	label: string;
	/** Optional leading icon (rendered at ~14px). */
	icon?: LucideIcon;
	/** Click handler. Required unless the item is purely decorative. */
	onClick?: () => void;
	/** Greys the item out and blocks clicks. */
	disabled?: boolean;
	/** Shows the icon spinning and blocks clicks (an in-flight action). */
	busy?: boolean;
	/** Tints the item red and (with `confirm`) gates it behind the web confirm modal. */
	danger?: boolean;
	/** Web confirm modal shown before `onClick` fires (reused for destructive actions). */
	confirm?: {
		title: string;
		body?: React.ReactNode;
		/** Label on the confirming button (defaults to the item's own label). */
		confirmLabel?: string;
	};
	/** Push this item into the trailing "More ▾" overflow menu instead of inline. */
	overflow?: boolean;
	/** Accessible title/tooltip. */
	title?: string;
}

export function ActionLinksRow({
	actions,
	className,
	ariaLabel = "Page actions",
}: {
	actions: ActionLink[];
	className?: string;
	ariaLabel?: string;
}) {
	const [confirming, setConfirming] = useState<ActionLink | null>(null);

	const inline = actions.filter((a) => !a.overflow);
	const overflow = actions.filter((a) => a.overflow);

	const fire = (a: ActionLink) => {
		if (a.disabled || a.busy) return;
		if (a.confirm) {
			setConfirming(a);
			return;
		}
		a.onClick?.();
	};

	return (
		<div
			// gap-3.5 = 14px, matching the reference `.q-actions` row.
			className={`flex flex-wrap items-center gap-3.5 text-sm ${className ?? ""}`}
			role="toolbar"
			aria-label={ariaLabel}
		>
			{inline.map((a, i) => (
				<span key={a.label} className="inline-flex items-center gap-3.5">
					{i > 0 && (
						<span aria-hidden className="text-[var(--edh-border)]">
							·
						</span>
					)}
					<ActionLinkButton action={a} onFire={() => fire(a)} />
				</span>
			))}

			{overflow.length > 0 && (
				<>
					{inline.length > 0 && (
						<span aria-hidden className="text-[var(--edh-border)]">
							·
						</span>
					)}
					<MoreMenu actions={overflow} onFire={fire} />
				</>
			)}

			{confirming && (
				<ConfirmDialog
					action={confirming}
					onCancel={() => setConfirming(null)}
					onConfirm={() => {
						const a = confirming;
						setConfirming(null);
						a.onClick?.();
					}}
				/>
			)}
		</div>
	);
}

/** One inline hyperlink-styled action. */
function ActionLinkButton({
	action,
	onFire,
}: {
	action: ActionLink;
	onFire: () => void;
}) {
	const { label, icon: Icon, disabled, busy, danger, title } = action;
	return (
		<button
			type="button"
			onClick={onFire}
			disabled={disabled || busy}
			title={title ?? label}
			className={`inline-flex items-center gap-1.5 hover:underline disabled:no-underline disabled:opacity-40 ${
				danger ? "text-red-600" : "text-[var(--edh-primary)]"
			}`}
		>
			{Icon && <Icon className={`h-3.5 w-3.5 ${busy ? "animate-spin" : ""}`} />}
			{label}
		</button>
	);
}

/**
 * Trailing "More ▾" overflow menu — only rendered when at least one action opts in with `overflow`.
 * Renders through a portal so it can never be clipped, matching RowMenu's approach.
 */
function MoreMenu({
	actions,
	onFire,
}: {
	actions: ActionLink[];
	onFire: (a: ActionLink) => void;
}) {
	const [open, setOpen] = useState(false);
	const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
	const btnRef = useRef<HTMLButtonElement>(null);

	const openMenu = () => {
		const rect = btnRef.current?.getBoundingClientRect();
		if (!rect) return;
		setPos({ top: rect.bottom + 4, left: rect.left });
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
				onClick={() => (open ? setOpen(false) : openMenu())}
				aria-haspopup="menu"
				aria-expanded={open}
				className="inline-flex items-center gap-1 text-[var(--edh-primary)] hover:underline"
			>
				More <ChevronDown className="h-3.5 w-3.5" />
			</button>
			{open &&
				pos &&
				createPortal(
					<>
						<button
							type="button"
							aria-label="Close menu"
							onClick={() => setOpen(false)}
							className="fixed inset-0 z-40 cursor-default"
						/>
						<div
							role="menu"
							style={{ top: pos.top, left: pos.left }}
							className="fixed z-50 min-w-52 rounded-md border border-[var(--edh-border)] bg-white py-1 shadow-lg"
						>
							{actions.map((a) => {
								const Icon = a.icon;
								return (
									<button
										key={a.label}
										type="button"
										role="menuitem"
										disabled={a.disabled || a.busy}
										onClick={() => {
											setOpen(false);
											onFire(a);
										}}
										className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-slate-100 disabled:opacity-40 ${
											a.danger ? "text-red-700" : "text-slate-900"
										}`}
									>
										{Icon && (
											<Icon
												className={`h-3.5 w-3.5 ${a.busy ? "animate-spin" : ""}`}
											/>
										)}
										{a.label}
									</button>
								);
							})}
						</div>
					</>,
					document.body,
				)}
		</>
	);
}

/**
 * The small web confirm modal for destructive actions (never `window.confirm`). Mirrors the
 * DomainsPage remove dialog and the reference's `openDeleteAllContentModal` — Cancel is focused by
 * default so a destructive action is never a single Enter-press away.
 */
function ConfirmDialog({
	action,
	onCancel,
	onConfirm,
}: {
	action: ActionLink;
	onCancel: () => void;
	onConfirm: () => void;
}) {
	const cancelRef = useRef<HTMLButtonElement>(null);
	useEffect(() => {
		cancelRef.current?.focus();
		const onKey = (e: KeyboardEvent) => {
			if (e.key === "Escape") onCancel();
		};
		document.addEventListener("keydown", onKey);
		return () => document.removeEventListener("keydown", onKey);
	}, [onCancel]);

	const c = action.confirm;
	return (
		<div
			role="alertdialog"
			aria-modal="true"
			aria-label={c?.title ?? action.label}
			className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4"
		>
			<div className="w-full max-w-md rounded-lg border border-[var(--edh-border)] bg-white p-5 shadow-xl">
				<h2 className="text-lg font-semibold">{c?.title ?? action.label}</h2>
				{c?.body && (
					<div className="mt-2 text-sm text-[var(--edh-muted)]">{c.body}</div>
				)}
				<div className="mt-4 flex justify-end gap-2">
					<button
						ref={cancelRef}
						type="button"
						onClick={onCancel}
						className="rounded-md border border-[var(--edh-border)] px-4 py-2 text-sm hover:bg-slate-50"
					>
						Cancel
					</button>
					<button
						type="button"
						onClick={onConfirm}
						className={`rounded-md px-4 py-2 text-sm font-medium text-white ${
							action.danger
								? "bg-red-600 hover:bg-red-700"
								: "bg-[var(--edh-primary)]"
						}`}
					>
						{c?.confirmLabel ?? action.label}
					</button>
				</div>
			</div>
		</div>
	);
}
