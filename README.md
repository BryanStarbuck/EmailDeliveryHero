# EmailDeliveryHero

**Audit your email deliverability — find out whether your domains are landing in spam or on blacklists, and get the exact fixes to apply.**

EmailDeliveryHero is an open source web app you run on your own machine (`localhost`) to police the health of the email domains you care about. It continuously watches for the problems that quietly kill your open rates — spam filtering and blacklisting — and tells you, in plain language, how to fix them.

---

## Why This Exists

You can send a perfect email and still never reach the inbox. Somewhere between "Send" and your recipient, a spam filter or a domain blacklist can silently drop or bury your message — and most senders never find out why their deliverability is bad. There's no bounce, no error, just silence.

EmailDeliveryHero closes that visibility gap. Point it at your domains and it tells you whether you're actually landing in inboxes, whether you've been blacklisted anywhere, and precisely what to change to recover.

---

## What It Does

* **Spam filter checks** — Determines whether your email domains are getting caught by spam filters.
* **Blacklist checks** — Determines whether your domains appear on email blacklists.
* **Actionable fixes** — For every problem it finds, it tells you the specific fix to apply.
* **Continuous monitoring** — Runs periodic checks on a schedule and surfaces new problems as they appear.
* **Clear reporting** — Reports the problems it finds alongside the exact remediation steps.

You "police" your domains: add the ones you care about, let EmailDeliveryHero watch them, and act on what it flags.

---

## How It Works

EmailDeliveryHero is a **web app that runs locally on `localhost`**. You start it, open it in your browser, add the domains you want to protect, and review the audit results and fixes it produces. Behind the scenes it leans on proven, widely available command-line tooling to run its checks, so results reflect the same signals real mail systems use.

---

## Getting Started

> EmailDeliveryHero runs on localhost. Clone the repo, start the app, and open it in your browser.

```bash
# 1. Clone the repository
git clone https://github.com/BryanStarbuck/EmailDeliveryHero.git
cd EmailDeliveryHero

# 2. Start the app (see setup notes below)
#    Then open the printed localhost URL in your browser.
```

Once the app is running, open it in your browser, sign in, add your domains, and run your first audit.

### Requirements

* A Mac or Linux machine capable of running the local web app.
* **[Homebrew](https://brew.sh/)** — EmailDeliveryHero uses Brew-installed command-line tools to perform many of its checks.

---

## Authentication

EmailDeliveryHero uses **[OpenAuth Federated](https://github.com/BryanStarbuck/OpenAuthFederated)** for authentication — an open source, self-hostable authentication layer used much like Clerk or Auth0. This keeps your sign-in fully under your control, in keeping with the local-first, open source spirit of the project.

---

## Contributing

EmailDeliveryHero is open source and contributions are welcome. Open an issue to report a bug or request a feature, or send a pull request. If you're adding a new deliverability check, prefer widely available Brew-installed tooling so results stay reproducible across machines.

---

## Links

* **Repository:** https://github.com/BryanStarbuck/EmailDeliveryHero
* **Authentication (OpenAuth Federated):** https://github.com/BryanStarbuck/OpenAuthFederated
