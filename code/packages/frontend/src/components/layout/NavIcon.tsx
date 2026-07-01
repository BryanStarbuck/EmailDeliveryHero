import {
  Ban,
  Clock,
  Globe,
  LayoutDashboard,
  LogOut,
  type LucideIcon,
  Mailbox,
  Settings,
  ShieldAlert,
  ShieldCheck,
  User,
} from "lucide-react"

/** Icon names referenced in left_bar.yaml → lucide-react components. */
const ICONS: Record<string, LucideIcon> = {
  LayoutDashboard,
  Globe,
  ShieldCheck,
  Ban,
  Mailbox,
  Settings,
  ShieldAlert,
  User,
  Clock,
  LogOut,
}

/** Resolves a lucide icon by yaml name; an unknown name renders NO icon (pm/leftbar.mdx §6). */
export function NavIcon({ name, className }: { name?: string; className?: string }) {
  const Icon = name ? ICONS[name] : undefined
  if (!Icon) return null
  return <Icon className={className ?? "h-4 w-4"} aria-hidden />
}
