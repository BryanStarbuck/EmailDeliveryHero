/* Minimal console logger. Kept as its own module so call sites don't sprinkle raw console.* and so
 * a future enhancement can ship client errors to the backend without touching every caller. */
export const logger = {
  info: (msg: string, ...rest: unknown[]) => console.info(`[edh] ${msg}`, ...rest),
  warn: (msg: string, ...rest: unknown[]) => console.warn(`[edh] ${msg}`, ...rest),
  error: (msg: string, ...rest: unknown[]) => console.error(`[edh] ${msg}`, ...rest),
}
