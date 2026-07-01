import { Check, Copy } from "lucide-react"
import { useState } from "react"

/**
 * Copy-to-clipboard for a finding's fix (pm/ui.mdx §1.4). For record-level fixes this copies the
 * exact string the user pastes into their DNS provider, so they never retype a TXT record.
 */
export function CopyFixButton({ text, label = "Copy fix" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const onCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <button
      type="button"
      onClick={onCopy}
      className="inline-flex shrink-0 items-center gap-1 rounded-md border border-[var(--edh-border)] px-2 py-1 text-xs font-medium hover:bg-white"
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 text-emerald-600" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
      {copied ? "Copied" : label}
    </button>
  )
}
