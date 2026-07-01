# EmailDeliveryHero

## Charter of This Directory

**EmailDeliveryHero** is an **open source project**.

* **Git Remote (origin):** https://github.com/BryanStarbuck/EmailDeliveryHero.git

### Purpose

EmailDeliveryHero is a web app (runs on localhost) for **auditing email deliverability** — determining whether your email domains are being caught by spam filters or landing on blacklists, and how to fix them.

### What It Does

* Checks whether your email domains are getting caught by spam filters or not.
* Checks whether your domains are on blacklists or not.
* Tells you how to fix any problems it finds.
* Runs periodic checks and looks for problems.
* Reports the problems it finds and the specific fixes to apply.

### Architecture & Conventions

* **Web app that runs on localhost.**
* **Tooling:** Internally we will often use **Brew-installed tools** (Homebrew) to do our work.
* **Authentication:** We use **OpenAuth Federated** for authentication.
  * Local repo: `~/BGit/Bryan_git/OpenAuthFederated/`
  * REPO: https://github.com/BryanStarbuck/OpenAuthFederated.git
  * OpenAuth Federated is our open source version of Clerk / Auth0, used much like Clerk.
