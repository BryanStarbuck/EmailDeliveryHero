import {
  Ban,
  Clock,
  Globe,
  LayoutDashboard,
  LogOut,
  type LucideIcon,
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
  Settings,
  ShieldAlert,
  User,
  Clock,
  LogOut,
}

export function NavIcon({ name, className }: { name?: string; className?: string }) {
  const Icon = (name && ICONS[name]) || Globe
  return <Icon className={className ?? "h-4 w-4"} aria-hidden />
}
