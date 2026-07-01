import { useAuth, useUser } from "@auth/react"
import { Link } from "@tanstack/react-router"
import { useEffect, useRef, useState } from "react"
import { accountMenuItems } from "@/config/left_bar"
import { logger } from "@/lib/logger"
import { cn } from "@/lib/utils"
import { NavIcon } from "./NavIcon"

/**
 * Bottom-left account block: avatar/name/email that opens an upward popup menu (Settings, Admin
 * [gated], Log out). Identity comes from the OpenAuthFederated session (useUser); Log out calls the
 * SDK's signOut — we never clear the session ourselves.
 */
export function AccountMenu() {
  const { signOut, has } = useAuth()
  const { user } = useUser()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener("mousedown", onClick)
    return () => document.removeEventListener("mousedown", onClick)
  }, [open])

  const email = user?.primaryEmailAddress ?? ""
  const name =
    [user?.firstName, user?.lastName].filter(Boolean).join(" ") || email.split("@")[0] || "Account"
  const initial = (name || "?").charAt(0).toUpperCase()

  const gate = (permission?: string): boolean => {
    if (!permission) return true
    const [kind, value] = permission.split(":")
    try {
      return kind === "role" ? has({ role: value }) : has({ permission })
    } catch {
      return false
    }
  }

  const onSignOut = () => {
    signOut({ redirectUrl: "/sign-in" }).catch((err) => logger.error("Sign-out failed", err))
  }

  return (
    <div ref={ref} className="relative border-t border-[var(--edh-border)] p-2">
      {open && (
        <div className="absolute bottom-full left-2 right-2 mb-1 overflow-hidden rounded-md border border-[var(--edh-border)] bg-white shadow-lg">
          {accountMenuItems.map((item) => {
            if (!gate(item.permission_gate)) return null
            if (item.action === "sign_out") {
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={onSignOut}
                  className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-slate-100"
                >
                  <NavIcon name={item.icon} />
                  {item.label}
                </button>
              )
            }
            return (
              <Link
                key={item.id}
                to={item.route ?? "/"}
                onClick={() => setOpen(false)}
                className="flex items-center gap-2 px-3 py-2 text-sm hover:bg-slate-100"
              >
                <NavIcon name={item.icon} />
                {item.label}
              </Link>
            )
          })}
        </div>
      )}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "flex w-full items-center gap-2 rounded-md px-2 py-2 text-left hover:bg-slate-100",
        )}
      >
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-[var(--edh-primary)] text-sm font-semibold text-white">
          {initial}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium">{name}</span>
          <span className="block truncate text-xs text-[var(--edh-muted)]">{email}</span>
        </span>
      </button>
    </div>
  )
}
