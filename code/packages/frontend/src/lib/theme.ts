import { logger } from "@/lib/logger"

/**
 * Theme boot + the `edh.theme` localStorage mirror (pm/storage.mdx §9). localStorage is ONLY a
 * fast, pre-network cache so the theme applies instantly at boot with no flash — the server
 * (users/<email>/config.yaml → theme) is always the source of truth: after load the mirror is
 * reconciled from GET /api/settings, and on change the app writes through to the server and then
 * updates the mirror. Clearing localStorage loses nothing but the pre-boot hint. No secret or
 * long-lived token is ever placed here (pm/authentication.mdx) — auth lives in the HttpOnly
 * oaf_edh cookie plus the library-owned `oaf_edh…` keys that @auth/react manages itself.
 */

export type Theme = "system" | "light" | "dark"

/** The one app-owned localStorage key (pm/storage.mdx §9). */
export const THEME_STORAGE_KEY = "edh.theme"

function isTheme(value: unknown): value is Theme {
  return value === "system" || value === "light" || value === "dark"
}

/** The pre-boot hint from the mirror; `system` when absent/unreadable. */
export function storedTheme(): Theme {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY)
    return isTheme(raw) ? raw : "system"
  } catch {
    return "system" // localStorage can be unavailable (privacy mode) — never let theming throw.
  }
}

/** Resolve `system` against the OS preference. */
function resolve(theme: Theme): "light" | "dark" {
  if (theme !== "system") return theme
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
  } catch {
    return "light"
  }
}

/** Paint the theme onto <html> (data-theme + color-scheme) — cheap and idempotent. */
export function applyTheme(theme: Theme): void {
  const resolved = resolve(theme)
  const root = document.documentElement
  root.dataset.theme = resolved
  root.style.colorScheme = resolved
}

/**
 * Set the user's theme: apply immediately, update the mirror, and write through to the server
 * (the caller — the Settings page — persists via PUT /api/settings; see pm/settings.mdx).
 */
export function setTheme(theme: Theme): void {
  applyTheme(theme)
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme)
  } catch {
    /* mirror only — losing it costs nothing but the pre-boot hint */
  }
}

/**
 * Reconcile the mirror with the server-side per-user truth after the session is up
 * (users/<email>/config.yaml → theme, served by GET /api/settings). Best-effort: any failure
 * (endpoint not deployed, offline, logged-out 401) leaves the pre-boot hint in place.
 */
export async function reconcileThemeFromServer(): Promise<void> {
  try {
    // Plain fetch (cookie auth) rather than the axios layer: this runs at boot, must never queue
    // behind the auth bridge, and a miss is entirely acceptable.
    const res = await fetch("/api/settings", { credentials: "include" })
    if (!res.ok) return
    const body = (await res.json()) as { theme?: unknown; ui?: { theme?: unknown } }
    const serverTheme = body?.theme ?? body?.ui?.theme
    if (isTheme(serverTheme) && serverTheme !== storedTheme()) setTheme(serverTheme)
  } catch (err) {
    logger.debug?.("Theme reconcile skipped", err)
  }
}

/**
 * Boot-time init (called from main.tsx before first paint): apply the mirrored theme instantly,
 * track OS light/dark flips while in `system` mode, then reconcile with the server in the
 * background once the app is up.
 */
export function initTheme(): void {
  applyTheme(storedTheme())
  try {
    window
      .matchMedia("(prefers-color-scheme: dark)")
      .addEventListener("change", () => applyTheme(storedTheme()))
  } catch {
    /* matchMedia may be missing in odd embedders — theming stays static there */
  }
  void reconcileThemeFromServer()
}
