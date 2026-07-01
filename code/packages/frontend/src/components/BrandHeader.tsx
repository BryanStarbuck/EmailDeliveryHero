/**
 * The big "Email Delivery Hero" wordmark that crowns the Dashboard (pm/ui.mdx §4, pm/dashboard.mdx
 * §2). Large, extra-bold, tracked-out, with visible spacing between the three words — the brand is a
 * feature, not a label.
 */
export function BrandHeader() {
  return (
    <h1 className="text-4xl font-extrabold tracking-[0.25em] text-slate-900 md:text-5xl">
      <span>Email</span>
      <span className="mx-3">Delivery</span>
      <span>Hero</span>
    </h1>
  )
}
