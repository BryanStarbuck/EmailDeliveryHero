import { blacklistCheck } from "./blacklist.check"
import { dkimCheck } from "./dkim.check"
import { dmarcCheck } from "./dmarc.check"
import { mxCheck } from "./mx.check"
import { spfCheck } from "./spf.check"
import type { Checker } from "./types"

/**
 * The checker registry. The audit runner iterates this list; adding a new deliverability check is
 * just implementing the `Checker` interface and adding it here.
 */
export const CHECKERS: Checker[] = [spfCheck, dkimCheck, dmarcCheck, mxCheck, blacklistCheck]

export type { AuditResult, CheckContext, Checker, Finding, Severity } from "./types"
