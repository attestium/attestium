# Adoption

We built Attestium not just for ourselves, but for the entire open-source community. We believe that verifiable runtime integrity is a fundamental building block for a more secure and trustworthy internet. This section outlines our own adoption, our vision for community adoption, and the critical security problems this framework solves for open-source companies.

## Live Transparency at [Forward Email](https://github.com/forwardemail/forwardemail.net)

We practice what we preach. At [Forward Email](https://forwardemail.net), we use the full [Attestium](https://github.com/attestium/attestium), [Audit Status](https://github.com/auditstatus/auditstatus), and [Upptime](https://github.com/upptime/upptime) stack to continuously monitor the integrity of our production servers. We have made our real-time audit results public for anyone to inspect at any time:

> **<https://status.forwardemail.net>**

This status page is not just a simple uptime monitor; it is a live feed of our server integrity checks. When [Upptime](https://github.com/upptime/upptime) runs an `ssh-audit` check, it executes the [Audit Status](https://github.com/auditstatus/auditstatus) binary on our servers, which in turn uses [Attestium](https://github.com/attestium/attestium) to perform TPM-backed cryptographic verification of our entire runtime environment. The results are pushed to our public status page, providing a transparent, third-party verifiable record of our production state.

If a check fails—whether due to a file mismatch, an unexpected process, or a TPM attestation failure—our team is immediately alerted via text messages and other notifications, allowing us to investigate and respond within minutes. This is not a theoretical exercise; it is a live, production-grade security system that we rely on every day.

## A Call to the Open-Source Community

We strongly encourage other open-source companies to adopt this framework. The modern software landscape is built on trust, but that trust is increasingly under attack. High-profile supply chain attacks have demonstrated that build-time security is not enough. We need to be able to verify the integrity of our software *as it runs*.

This is especially critical for companies that are building the next generation of open-source infrastructure and services. We have identified several companies that we believe would be ideal candidates for adopting Attestium, as their business models are built on providing trustworthy, transparent, and secure services. For each, we have included their website, primary GitHub repository, and the main programming languages they use:

* **Supabase** ([supabase.com](https://supabase.com)) - [github.com/supabase/supabase](https://github.com/supabase/supabase) (TypeScript, Go)
* **Cal.com** ([cal.com](https://cal.com)) - [github.com/calcom/cal.com](https://github.com/calcom/cal.com) (TypeScript)
* **Documenso** ([documenso.com](https://documenso.com)) - [github.com/documenso/documenso](https://github.com/documenso/documenso) (TypeScript)
* **Bitwarden** ([bitwarden.com](https://bitwarden.com)) - [github.com/bitwarden/clients](https://github.com/bitwarden/clients) (TypeScript)
* **Infisical** ([infisical.com](https://infisical.com)) - [github.com/Infisical/infisical](https://github.com/Infisical/infisical) (TypeScript)
* **Jitsi** ([jitsi.org](https://jitsi.org)) - [github.com/jitsi/jitsi-meet](https://github.com/jitsi/jitsi-meet) (TypeScript, JavaScript)
* **Element** ([element.io](https://element.io)) - [github.com/element-hq/element-web](https://github.com/element-hq/element-web) (TypeScript, CSS)
* **Mattermost** ([mattermost.com](https://mattermost.com)) - [github.com/mattermost/mattermost](https://github.com/mattermost/mattermost) (Go, TypeScript)
* **Ghost** ([ghost.org](https://ghost.org)) - [github.com/TryGhost/Ghost](https://github.com/TryGhost/Ghost) (JavaScript, TypeScript)
* **Plausible Analytics** ([plausible.io](https://plausible.io)) - [github.com/plausible/analytics](https://github.com/plausible/analytics) (Elixir, React)
* **PostHog** ([posthog.com](https://posthog.com)) - [github.com/PostHog/posthog](https://github.com/PostHog/posthog) (Python, TypeScript)
* **Chatwoot** ([chatwoot.com](https://www.chatwoot.com)) - [github.com/chatwoot/chatwoot](https://github.com/chatwoot/chatwoot) (Ruby, Vue, JavaScript)
* **Twenty** ([twenty.com](https://twenty.com)) - [github.com/twentyhq/twenty](https://github.com/twentyhq/twenty) (TypeScript)
* **Gitea** ([gitea.io](https://gitea.io)) - [github.com/go-gitea/gitea](https://github.com/go-gitea/gitea) (Go, TypeScript)
* **Rocket.Chat** ([rocket.chat](https://www.rocket.chat)) - [github.com/RocketChat/Rocket.Chat](https://github.com/RocketChat/Rocket.Chat) (TypeScript)
* **Plane** ([plane.so](https://plane.so)) - [github.com/makeplane/plane](https://github.com/makeplane/plane) (TypeScript, Python)

By adopting a framework like Attestium, these companies can provide a new level of assurance to their users, customers, and enterprise clients. They can prove, with cryptographic certainty, that the code running on their servers is the exact same code that is in their public repositories—unmodified and uncompromised.

## Preventing the Insider Threat

While external threats get the most attention, the insider threat remains one of the most difficult to mitigate. A rogue employee, a compromised third-party vendor, or even a datacenter technician with physical access to a server (an "evil-maid" attack) can bypass traditional security measures and inject malicious code directly into a running application.

This is not a theoretical risk. With SSH access, a malicious actor can easily modify application files, install backdoors, or alter dependencies. Attestium is designed to defeat this entire class of attacks. Because it hashes the entire project directory and verifies the integrity of running processes against their on-disk binaries, any unauthorized modification will be immediately detected and flagged.

This provides a powerful layer of defense, not just for end-users, but for the entire team. It ensures that even with privileged access, no single individual can compromise the integrity of the production environment without being detected. It builds a culture of trust and accountability, backed by cryptographic proof.
