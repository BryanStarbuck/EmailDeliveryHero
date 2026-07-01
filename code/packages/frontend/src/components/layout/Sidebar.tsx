import { useAuth } from "@auth/react"
import { Link, useLocation } from "@tanstack/react-router"
import { ArrowLeft } from "lucide-react"
import { appNavItems, appTitle, settingsBackRoute, settingsGroups } from "@/config/left_bar"
import { cn } from "@/lib/utils"
import { AccountMenu } from "./AccountMenu"
import { NavIcon } from "./NavIcon"

export type SidebarVariant = "app" | "settings"

const SHELL = "flex h-full w-64 shrink-0 flex-col border-r border-[var(--edh-border)] bg-white"
const ITEM =
  "flex items-center gap-2 rounded-md px-2 py-2 text-sm text-slate-700 transition-colors hover:bg-slate-100"
const ACTIVE = "bg-[var(--edh-primary)]/10 font-medium text-[var(--edh-primary)]"

/** Hide an item whose permission gate the signed-in user doesn't satisfy. */
function useGate() {
  const { has } = useAuth()
  return (gate?: string): boolean => {
    if (!gate) return true
    const [kind, value] = gate.split(":")
    try {
      return kind === "role" ? has({ role: value }) : has({ permission: gate })
    } catch {
      return false
    }
  }
}

export function Sidebar({ variant }: { variant: SidebarVariant }) {
  return variant === "settings" ? <SettingsSidebar /> : <AppSidebar />
}

function AppSidebar() {
  const pathname = useLocation({ select: (l) => l.pathname })
  const isActive = (route: string) =>
    route === "/" ? pathname === "/" : pathname === route || pathname.startsWith(`${route}/`)

  return (
    <nav className={SHELL}>
      <div className="flex h-14 items-center gap-2 border-b border-[var(--edh-border)] px-4">
        <span className="text-lg font-semibold text-[var(--edh-primary)]">{appTitle}</span>
      </div>
      <div className="flex-1 space-y-1 overflow-y-auto p-2">
        {appNavItems.map((item) => (
          <Link
            key={item.id}
            to={item.route}
            className={cn(ITEM, isActive(item.route) && ACTIVE)}
            title={item.description}
          >
            <NavIcon name={item.icon} />
            {item.label}
          </Link>
        ))}
      </div>
      <AccountMenu />
    </nav>
  )
}

function SettingsSidebar() {
  const pathname = useLocation({ select: (l) => l.pathname })
  const gate = useGate()
  const isActive = (route: string) => pathname === route

  return (
    <nav className={SHELL}>
      <div className="flex h-14 items-center border-b border-[var(--edh-border)] px-2">
        <Link to={settingsBackRoute} className={cn(ITEM, "font-medium")}>
          <ArrowLeft className="h-4 w-4" /> Back to app
        </Link>
      </div>
      <div className="flex-1 space-y-4 overflow-y-auto p-2">
        {settingsGroups.map((group) => {
          const items = group.items.filter((i) => gate(i.permission_gate))
          if (items.length === 0) return null
          return (
            <div key={group.id}>
              <div className="px-2 pb-1 text-xs font-semibold uppercase tracking-wide text-[var(--edh-muted)]">
                {group.label}
              </div>
              <div className="space-y-1">
                {items.map((item) => (
                  <Link
                    key={item.id}
                    to={item.route}
                    className={cn(ITEM, isActive(item.route) && ACTIVE)}
                    title={item.description}
                  >
                    <NavIcon name={item.icon} />
                    {item.label}
                  </Link>
                ))}
              </div>
            </div>
          )
        })}
      </div>
      <AccountMenu />
    </nav>
  )
}
