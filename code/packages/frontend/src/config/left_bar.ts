/**
 * Left-bar config loader. Parses the single source of truth — pm/left_bar.yaml — and exposes typed
 * nav structures for the two bars (app + settings). We import the master file directly as raw text
 * (Vite `?raw`) and parse it with `yaml`; there is no in-package copy. Vite `server.fs.allow`
 * (vite.config.ts) grants the dev server read access to the repo root where pm/ lives.
 */
import { parse } from "yaml"
import { logger } from "@/lib/logger"
// pm/left_bar.yaml lives at the EmailDeliveryHero repo root (outside the frontend package).
import leftBarYaml from "../../../../../pm/left_bar.yaml?raw"

export interface NavItem {
  id: string
  label: string
  icon?: string
  route: string
  order?: number
  description?: string
  permission_gate?: string
}

export interface AccountMenuItem {
  id: string
  label: string
  icon?: string
  route?: string
  action?: string
  permission_gate?: string
}

export interface SettingsGroup {
  id: string
  label: string
  order?: number
  items: NavItem[]
}

interface RawBar {
  Location?: string
  header?: { label?: string; back_route?: string }
  nav_items?: NavItem[]
  groups?: SettingsGroup[]
  footer?: Array<{ menu_items?: AccountMenuItem[] }>
}

interface RawRoot {
  Left_Nav?: { Left_bars?: RawBar[] }
}

function bars(): RawBar[] {
  try {
    const root = parse(leftBarYaml) as RawRoot
    return root.Left_Nav?.Left_bars ?? []
  } catch (err) {
    logger.error("Failed to parse left_bar.yaml; nav will be empty", err)
    return []
  }
}

function barAt(location: string): RawBar | undefined {
  return bars().find((b) => b.Location === location)
}

/** The app bar's title (from its header). */
export const appTitle: string = barAt("app")?.header?.label ?? "EmailDeliveryHero"

/** Primary app nav items, ordered. */
export const appNavItems: NavItem[] = [...(barAt("app")?.nav_items ?? [])].sort(
  (a, b) => (a.order ?? 0) - (b.order ?? 0),
)

/** Account-block menu items (footer of the app bar). */
export const accountMenuItems: AccountMenuItem[] =
  barAt("app")?.footer?.find((f) => Array.isArray(f.menu_items))?.menu_items ?? []

/** Settings-bar groups, ordered. */
export const settingsGroups: SettingsGroup[] = [...(barAt("settings")?.groups ?? [])].sort(
  (a, b) => (a.order ?? 0) - (b.order ?? 0),
)

export const settingsBackRoute: string = barAt("settings")?.header?.back_route ?? "/"
