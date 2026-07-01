import { useAuth, useUser } from "@auth/react"
import { Link } from "@tanstack/react-router"
import { LogIn } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { accountMenuItems } from "@/config/left_bar"
import { logger } from "@/lib/logger"
import { cn } from "@/lib/utils"
import { NavIcon } from "./NavIcon"

/**
 * Bottom-of-the-nav account block. Login is OPTIONAL (pm/security.mdx §3.2): when logged out this
 * shows a single "Sign in" button (the user is the `default` user until they click it); when signed
 * in it shows the avatar/name/email that opens an upward popup menu (Settings, Admin [gated], Log
 * out). Identity comes from the OpenAuthFederated session (useUser); Log out calls the SDK's signOut
 * — which returns the app to the `default` user, it never boots the person out of the app.
 */
export function AccountMenu() {
  const { isSignedIn, signOut, has } = useAuth()
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

  // Logged out → the account slot is a "Sign in" entry point to the Google Workspace SSO flow.
  if (!isSignedIn) {
    return (
      <div className="border-t border-[var(--edh-border)] p-2">
        <Link
          to="/sign-in"
          className="flex w-full items-center gap-2 rounded-md px-2 py-2 text-left text-sm font-medium text-[var(--edh-primary)] hover:bg-slate-100"
          title="Sign in with your company Google Workspace account"
        >
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-200 text-slate-500">
            <LogIn className="h-4 w-4" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate">Sign in</span>
            <span className="block truncate text-xs font-normal text-[var(--edh-muted)]">
              Using default settings
            </span>
          </span>
        </Link>
      </div>
    )
  }

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
    // Return to the app as the `default` user (pm/security.mdx §3.2) — not to the sign-in screen.
    signOut({ redirectUrl: "/" }).catch((err) => logger.error("Sign-out failed", err))
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
