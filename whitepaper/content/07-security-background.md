# Our Security Background

Before we built Attestium, we spent years hardening our own infrastructure at [Forward Email](https://forwardemail.net). Security isn't a feature we bolted on — it's the foundation we built everything on top of. Our production environment is managed entirely through [open-source Ansible playbooks](https://github.com/forwardemail/forwardemail.net/tree/master/ansible) that anyone can inspect. This section documents what we've done, why we built Attestium instead of hiring a third-party auditor, and why we think continuous automated verification beats a point-in-time audit.

## Ansible-Managed Infrastructure

Every server we operate is provisioned and hardened through Ansible. There are no manual SSH sessions to configure things. No snowflake servers. Every security measure is codified, version-controlled, and reproducible. Here's what our playbooks enforce.

### Kernel and System Hardening

We disable core dumps entirely — hard and soft limits set to zero, `fs.suid_dumpable=0`, `ProcessSizeMax=0` in systemd, and `kernel.core_pattern` piped to `/bin/false`. Transparent Huge Pages are disabled via a systemd service. Swap is turned off on all non-database servers (database servers keep it with `vm.swappiness=1`). We run over 50 sysctl kernel parameters including ASLR (`kernel.randomize_va_space=2`), TCP SYN cookies for flood protection, RFC 1337 TIME-WAIT assassination protection, and dynamically scaled TCP buffers based on available RAM.

Our filesystem mounts use `tmpfs` on `/dev/shm` with `noexec,nosuid,nodev` flags — code cannot execute from shared memory. Data partitions use `noatime` and `nodiratime`. I/O schedulers are tuned per drive type: `none` for NVMe, `deadline` for SSDs, with optimized read-ahead values. Web-facing servers use TCP BBR congestion control with `fq` queueing; internal servers use CUBIC with `fq_codel`.

### USB Device Whitelisting

The `usb-storage` kernel module is disabled via `modprobe.d` and the initramfs is rebuilt to persist this across reboots. We maintain a whitelist of authorized USB devices by `vendor:product` ID in `/etc/security-monitor/authorized-usb-devices.conf`. Any unrecognized USB device triggers an immediate email alert to the team. Udev rules (`99-usb-monitor.rules`) provide real-time detection on top of the 5-minute polling cycle. A datacenter technician plugging in a USB drive gets flagged instantly.

### SSH and Access Control

Root login is disabled (`PermitRootLogin no`). Password authentication is disabled — only key-based auth is allowed. The root password is locked. We maintain two users: `devops` (with sudo, no password prompt) and `deploy` (with a 4096-bit SSH key, limited privileges). Fail2Ban is configured aggressively: 2 failed attempts triggers a permanent ban (`bantime=-1`) with a 365-day find window. We replaced Postfix with `msmtp` — a lightweight send-only SMTP client with no listening daemon and no open ports.

### Eight Security Monitoring Systems

We run eight independent monitoring systems, all implemented as systemd timers with rate-limited email alerts:

1. **System Resource Monitor** — CPU, memory, and disk usage with five threshold levels (75%, 80%, 90%, 95%, 100%), checked every 5 minutes.
2. **SSH Security Monitor** — Failed logins, successful logins, root access, unknown IPs, and after-hours logins, checked every 10 minutes.
3. **USB Device Monitor** — Unknown device detection with vendor:product ID whitelisting, checked every 5 minutes plus real-time udev rules.
4. **Root Access Monitor** — Direct root login, sudo usage, `su` to root, and privilege escalation attempts, checked every 5 minutes.
5. **Lynis Audit Monitor** — Automated [Lynis](https://cisofy.com/lynis/) security audits run on a schedule.
6. **Package Monitor** — Tracks every package installation and removal.
7. **Open Ports Monitor** — Detects unexpected listening services.
8. **SSL Certificate Monitor** — Monitors TLS certificate expiry dates.

Each monitor uses whitelist files in `/etc/security-monitor/` for authorized IPs, users, USB devices, root users, and sudo users. Rate limiting prevents alert flooding — resource alerts have a 1-hour cooldown per threshold, SSH root access alerts have no cooldown (always alert), and USB alerts have a 1-hour cooldown per device.

### Command Logging and Auditing

Every command executed on our servers is logged through multiple layers: `auditd` with custom audit rules, enhanced bash logging in both `/etc/profile.d/` (login shells) and `/etc/bash.bashrc` (all interactive shells), zsh logging in `/etc/zsh/zshrc.d/`, and `rsyslog` capturing everything to `/var/log/bash-commands.log` with 30-day logrotate retention. If someone runs a command on our servers, we have a record of it.

### Automatic Security Updates

Unattended upgrades are enabled for security patches with automatic reboots at 02:00 (except database servers). We deploy a custom port scan protection script (our own [maintained fork](https://github.com/forwardemail/portscan-protection)). DNS resolves through Cloudflare and Google with a local Unbound caching resolver. MongoDB is installed from the official repository, Valkey is compiled from source — we have zero Ansible Galaxy dependencies. No external roles, no third-party playbook code.

## Why Not a Third-Party Audit?

A one-time security audit from a reputable firm costs $5,000–$10,000 USD or more. That buys you a snapshot — a report that says "on this date, we checked these things and they looked fine." The moment the audit ends, the report starts going stale. New code gets deployed, packages get updated, configurations change. The audit doesn't tell you what happened last Tuesday at 3 AM.

But the cost isn't the real problem. The real problem is trust.

We manage email. Email is the most sensitive communication channel most people have — password resets, financial statements, legal correspondence, medical records. Giving a third-party auditor SSH access to our production servers means trusting them with access to all of that. Even with the best intentions, an audit can take weeks or months. During that entire window, we'd need to monitor their access, verify they aren't exfiltrating data, and hope that their own systems haven't been compromised. We'd essentially need to audit the auditor.

We do plan to eventually undergo a third-party audit from one of our [recommended providers](https://forwardemail.net/en/blog/docs/best-security-audit-companies). But we believe continuous, automated, cryptographic verification is strictly better than periodic human inspection. Attestium runs every few minutes. It doesn't get tired, it doesn't have a bad day, and it doesn't need SSH access to your production email servers.

## From Hardening to Verification

All of the hardening described above — the sysctl parameters, the USB whitelisting, the eight monitoring systems, the command logging — these are preventive controls. They make it harder for an attacker to do damage. But they don't answer the fundamental question: is the code running on this server right now the same code that's in our public repository?

That's the gap Attestium fills. We built it because we needed it ourselves. Every measure in our Ansible playbooks is designed to prevent unauthorized changes. Attestium is designed to detect them — continuously, cryptographically, and in a way that anyone can verify. And with the addition of process memory integrity, we can now answer an even deeper question: is the code *actually executing in memory* the same code that's on disk? Because on a hardened server, the most dangerous attacker isn't the one who modifies files — it's the one who modifies memory.

\newpage
