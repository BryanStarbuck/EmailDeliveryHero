import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query"
import { logger } from "@/lib/logger"

/**
 * API failures surfaced through react-query are caught by the library, so they never reach the
 * global window "unhandledrejection" handler. Forward them here instead: logger.error POSTs to
 * /api/health/client-error and the fault lands in error.err tagged [Frontend] (pm/errors.mdx §3, §7.9).
 */
export const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error, query) => {
      logger.error(`API query failed: ${JSON.stringify(query.queryKey)}`, error)
    },
  }),
  mutationCache: new MutationCache({
    onError: (error, _variables, _context, mutation) => {
      const key = mutation.options.mutationKey
      logger.error(`API mutation failed${key ? `: ${JSON.stringify(key)}` : ""}`, error)
    },
  }),
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})
