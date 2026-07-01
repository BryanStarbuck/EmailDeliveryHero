/**
 * A tiny, dependency-free bounded-concurrency runner (a `p-limit`-style "task view"), shared by the
 * scan fan-out so N domains scan in parallel without opening N sockets at once (pm/progress_ui.mdx
 * §4.3). Runs `fn` over `items` with at most `limit` in flight, preserves input order in the returned
 * array, and — because deliverability work is I/O-bound — relies on the event loop, not worker
 * threads. Kept in sync with the backend copy at `backend/src/shared/concurrency.ts`.
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
