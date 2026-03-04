# Systems Architecture

Here, we detail the architecture of each layer in the Attestium stack, from the core library to the uptime monitor integration.

## Layer 1: [Attestium](https://github.com/attestium/attestium) (Core Verification Engine)

Attestium is the heart of our stack. It’s a Node.js library providing the essential tools for runtime integrity verification. Its key functions include:

* **`generateVerificationReport()`**: The main entry point, orchestrating all checks and compiling the final JSON report.
* **`checkCodeIntegrity()`**: Verifies application code against a git commit hash or a recursive checksum of all project files.
* **`checkRunningProcesses()`**: On Linux, this function iterates through `/proc` to identify running processes and hashes their executables from `/proc/<pid>/exe`, ensuring the running code hasn't been tampered with.
* **`checkBinarySignatures()`**: Verifies the integrity of critical system binaries like `node`, `npm`, and `git` by comparing their checksums to known-good values.
* **`checkTpmAttestation()`**: Interacts with the system’s TPM using `tpm2-tools` to create a hardware-signed quote, verifying the integrity of the boot process and kernel.

## Layer 2: [Audit Status](https://github.com/auditstatus/auditstatus) (Monitoring Tool)

Audit Status is our command-line interface for Attestium. It’s designed for periodic server audits and is distributed as a single executable binary created with Node.js’s SEA feature. Its main features are:

* **YAML Configuration**: A simple `auditstatus.config.yml` file allows you to specify which checks to run and their expected outcomes.
* **JSON Output**: It outputs a structured JSON report with a top-level `passed` flag and detailed results for each check, making it easy to integrate with other tools.
* **Simple CLI**: The `auditstatus check` command runs a full system audit.

## Layer 3: [Upptime](https://github.com/upptime/upptime) (Uptime Monitoring System)

We extended [Upptime](https://github.com/upptime/upptime), an open-source uptime monitor, with a new `ssh-audit` check type for remote runtime integrity verification. The process is straightforward:

1. **Download Binary**: Upptime fetches the specified version of the Audit Status binary from GitHub Releases.
2. **SCP to Server**: It copies the binary to `/dev/shm` on the remote server, an in-memory filesystem that ensures automatic cleanup.
3. **Execute Audit**: It runs the binary via SSH, passing all configuration as command-line flags.
4. **Parse Output**: It captures and parses the JSON output to determine the check's result.
5. **Cleanup**: Finally, it removes the binary from the remote server.

This approach requires no pre-installed software on the remote server besides an SSH server, and all configuration is managed centrally in the `.upptimerc.yml` file.
