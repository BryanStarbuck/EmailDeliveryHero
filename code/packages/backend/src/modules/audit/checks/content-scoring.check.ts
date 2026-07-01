import type { Checker, Finding } from "./types"

/**
 * Message content spam scoring (SpamAssassin-style). Scores a user-supplied sample message — the raw
 * RFC 5322 source of a real email the user sends from the domain — through the Homebrew
 * `spamassassin`/`spamc` engine, reports every rule that fired with its individual weight, and maps
 * subject / MIME / HTML-hygiene / header-sanity / attachment / encoding signals to concrete fixes.
 * Threshold is 5.0; EmailDeliveryHero treats 0–2 as safe, 2–5 as a warning, ≥ 5 as critical.
 *
 * Per pm/checks/content_scoring.mdx §7 every sub-check here is FUTURE-round: none is answerable from
 * DNS. Scoring gates on (1) a stored sample `.eml` for the domain and (2) the SpamAssassin binary —
 * neither of which is available to a pure-DNS checker (`CheckContext` carries no sample, and no
 * message store is wired in the first round). Rather than fabricate a score, this checker emits a
 * single `info` finding describing exactly what content scoring will verify once those inputs land,
 * and — read-only — reports whether the local SpamAssassin binary is already installed so the
 * remediation is accurate. It never emits `warning`/`critical` and never throws.
 */

const CHECK_ID = "content"

/**
 * Best-effort, graceful probe for a Homebrew SpamAssassin binary. Uses `which` via execFile (never a
 * shell string) with a short timeout; any failure (binary absent, `which` missing, timeout) resolves
 * to `false` instead of throwing, so the checker degrades cleanly.
 */
async function hasSpamAssassin(): Promise<boolean> {
  const { execFile } = await import("node:child_process")
  const probe = (bin: string): Promise<boolean> =>
    new Promise((resolve) => {
      try {
        execFile("which", [bin], { timeout: 3000 }, (err, stdout) => {
          resolve(!err && stdout.trim().length > 0)
        })
      } catch {
        resolve(false)
      }
    })
  const [spamc, spamassassin] = await Promise.all([probe("spamc"), probe("spamassassin")])
  return spamc || spamassassin
}

export const contentScoringCheck: Checker = {
  id: "content.scoring",
  label: "Message Content Spam Scoring",
  async run(_ctx): Promise<Finding[]> {
    const installed = await hasSpamAssassin()

    const engineHint = installed
      ? "The Homebrew SpamAssassin binary is already installed on this host, so scoring can begin as soon as a sample is uploaded."
      : "SpamAssassin is not installed on this host yet — run `brew install spamassassin` so the message can be scored."

    return [
      {
        id: "content.pending",
        checkId: CHECK_ID,
        title: "Content scoring pending — no sample message",
        severity: "info",
        detail:
          "Message content spam scoring runs a representative sample email (raw RFC 5322 headers + body) through SpamAssassin and reports every rule that fired with its individual score. It will grade the subject (ALL-CAPS, excess '!!!', fake RE:/FWD:), MIME structure (a text/plain alternative alongside text/html, matched boundaries, valid charset), HTML hygiene (hidden/white-on-white text, tiny fonts), trigger phrases and obfuscation, header sanity (Message-ID, Date), attachment risk (executables, macro Office docs), and gratuitous base64 encoding — mapping the SpamAssassin total (safe 0–2, warning 2–5, critical ≥ 5.0) and each fired rule to a concrete fix. It cannot run from DNS alone: it needs a user-supplied sample and the local SpamAssassin engine. " +
          engineHint,
        remediation: installed
          ? "Upload a representative .eml for this domain (drag-drop the raw email source or paste it) to enable SpamAssassin content scoring."
          : "Install the engine with `brew install spamassassin`, then upload a representative .eml for this domain (drag-drop the raw email source or paste it) to enable content scoring.",
        evidence: installed ? "spamassassin: installed" : "spamassassin: not found",
      },
    ]
  },
}
