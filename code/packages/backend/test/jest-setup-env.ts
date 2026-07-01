/**
 * Jest environment setup — keep unit-test logging OUT of the real fault trail.
 *
 * `shared/logging.ts` resolves `LOG_DIR` from `EDH_LOG_DIR` at import time (module top level), and
 * defaults to the live state dir (~/T/_emaildeliveryhero). Without this hook, any test that exercises
 * code which logs (e.g. RolesGuard's 403 denials) would append bogus WARN lines to the production
 * `error.err`/`log.log`. Registered via the jest `setupFiles` list so it runs BEFORE the test module
 * graph — and therefore before logging.ts reads these vars.
 *
 * Effect: each Jest worker writes to a throwaway temp dir and echoes nothing to the console.
 */
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

process.env.EDH_LOG_DIR = mkdtempSync(join(tmpdir(), "edh-jest-logs-"))
process.env.EDH_LOG_CONSOLE = "false"
