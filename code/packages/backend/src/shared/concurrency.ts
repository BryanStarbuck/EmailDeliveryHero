/**
 * A tiny, dependency-free bounded-concurrency runner (a `p-limit`-style "task view"). The audit
 * runner uses it to scan domains in parallel with a small cap (pm/progress_ui.mdx §4.2–4.3). Because
 * DNS/SMTP checks are I/O-bound, bounded async concurrency — not OS worker threads — is the right,
 * lightweight tool. Runs `fn` over `items` with at most `limit` in flight and preserves input order.
 * Kept in sync with the frontend copy at `frontend/src/lib/concurrency.ts`.
 */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  const bound = Math.max(1, Math.min(limit, items.length))
  let next = 0

  async function worker(): Promise<void> {
    while (true) {
      const i = next++
      if (i >= items.length) return
      results[i] = await fn(items[i], i)
    }
  }

  await Promise.all(Array.from({ length: bound }, () => worker()))
  return results
}
