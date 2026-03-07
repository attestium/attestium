# Systems Architecture

Here, we detail the architecture of each layer in the Attestium stack, from the core library to the uptime monitor integration.

## Layer 1: [Attestium](https://github.com/attestium/attestium) (Core Verification Engine)

Attestium is the heart of our stack. It's a Node.js library providing the essential tools for runtime integrity verification. It exposes three subpath exports, each addressing a distinct verification domain.

### Main Module (`attestium`)

The primary export provides file-level verification, TPM attestation, and runtime monitoring:

* **`generateVerificationReport()`**: The main entry point, orchestrating all checks and compiling the final JSON report.
* **`checkCodeIntegrity()`**: Verifies application code against a git commit hash or a recursive checksum of all project files.
* **`checkRunningProcesses()`**: On Linux, this function iterates through `/proc` to identify running processes and hashes their executables from `/proc/<pid>/exe`, ensuring the on-disk binary hasn't been replaced.
* **`checkBinarySignatures()`**: Verifies the integrity of critical system binaries like `node`, `npm`, and `git` by comparing their checksums to known-good values.
* **`checkTpmAttestation()`**: Interacts with the system's TPM using `tpm2-tools` to create a hardware-signed quote, verifying the integrity of the boot process and kernel.

### Process Integrity Module (`attestium/process-integrity`)

This module closes the critical gap between file-level and memory-level verification. Where the main module verifies that the *file on disk* is correct, this module verifies that what the CPU is *actually executing* hasn't been tampered with. It provides five cross-platform checks:

* **`checkMemoryMaps(pid)`**: On Linux, parses `/proc/<pid>/maps` to enumerate every memory region in the process address space. It flags four categories of anomalies: anonymous executable regions (potential shellcode or JIT abuse), deleted file-backed mappings (a hallmark of fileless malware using `memfd_create`), unexpected shared libraries not in the approved set, and W^X violations where a region is simultaneously writable and executable. On macOS, it uses `vmmap` to perform equivalent analysis. On Windows, it enumerates loaded modules via PowerShell.

* **`checkExecutablePageHash(pid)`**: The definitive memory integrity check. On Linux, it reads the `r-xp` (read-execute, private) memory pages directly from `/proc/<pid>/mem` at their virtual addresses, hashes them with SHA-256, and compares the result byte-for-byte against the corresponding offsets in the on-disk ELF binary. If an attacker has modified the executable code in memory—via `ptrace`, `/proc/<pid>/mem` writes, or any other injection technique—the hashes will diverge. This is the check that proves the process in memory is identical to the binary on disk.

* **`checkLinkerIntegrity(pid)`**: Inspects the process environment for library injection vectors. On Linux, it reads `/proc/<pid>/environ` for `LD_PRELOAD` and `LD_LIBRARY_PATH`, and checks `/etc/ld.so.preload` for system-wide preloads. On macOS, it checks for `DYLD_INSERT_LIBRARIES`. On Windows, it queries the `AppInit_DLLs` registry key. Any of these being set is a strong indicator of library injection.

* **`checkTracerPid(pid)`**: Detects debugger attachment. On Linux, it reads `TracerPid` from `/proc/<pid>/status`—a non-zero value means another process is tracing this one via `ptrace`, which is how most runtime code injection is performed. On macOS, it checks for `lldb` and `dtrace` processes targeting the PID. On Windows, it inspects loaded debug modules.

* **`checkFileDescriptors(pid)`**: Inspects `/proc/<pid>/fd` for suspicious file descriptors, specifically `memfd_create` anonymous files (the primary vector for fileless malware on Linux) and deleted files held open (a technique for hiding malicious payloads). On macOS, it uses `lsof` for equivalent analysis.

### Release Verification Module (`attestium/release-verification`)

This module implements three-way verification: running binary vs. on-disk binary vs. official upstream release. It answers a question that no other tool in the Node.js ecosystem answers: is the code running on this server the same code that was published by the upstream maintainers?

* **`verifyNodeRelease()`**: Hashes the running Node.js binary (`process.execPath`) and compares it against the official `SHASUMS256.txt` from `nodejs.org/dist/v<version>/`. On Windows, where the SHASUMS entry is for the raw `node.exe` binary, this provides a direct hash comparison. On Linux and macOS, where the SHASUMS entry is for the distribution archive, it stores both hashes for reference and supports deep extraction for definitive comparison.

* **`verifyGlobalPackage(name)`**: Verifies globally installed packages (npm, pnpm, pm2) against the npm registry. It fetches the registry metadata for the installed version, extracts the `dist.integrity` and `dist.shasum` hashes, and compares them against the installed package. It also resolves the `repository` field to identify the upstream GitHub source.

* **`verifyModules(modules)`**: The supply chain provenance check. For each installed dependency in `node_modules`, it performs a multi-step verification: (1) reads the installed `package.json` to determine the version, (2) fetches the corresponding version metadata from the npm registry, (3) compares the lockfile integrity hash against the registry integrity hash, and (4) verifies the `gitHead` field—the Git commit SHA that npm records at publish time—against the GitHub API to confirm that the published version was built from a commit that actually exists in the project's public repository. This last step is critical: it detects the scenario where an attacker with npm publish credentials pushes a version that was never in the public source code.

## Layer 2: [Audit Status](https://github.com/auditstatus/auditstatus) (Monitoring Tool)

Audit Status is our command-line interface for Attestium. It's designed for periodic server audits and is distributed as a single executable binary created with Node.js's SEA feature. Its main features are:

* **YAML Configuration**: A simple `auditstatus.config.yml` file allows you to specify which checks to run and their expected outcomes.
* **JSON Output**: It outputs a structured JSON report with a top-level `passed` flag and detailed results for each check, making it easy to integrate with other tools.
* **Simple CLI**: The `auditstatus check` command runs a full system audit, including the new `--no-process-integrity` and `--no-release-verification` flags for environments where these checks are not needed or not supported.
* **Integrated Checks**: It orchestrates all of Attestium's verification primitives—file integrity, TPM attestation, process verification, memory integrity, and release provenance—into a single unified report.

## Layer 3: [Upptime](https://github.com/upptime/upptime) (Uptime Monitoring System)

We extended [Upptime](https://github.com/upptime/upptime), an open-source uptime monitor, with a new `ssh-audit` check type for remote runtime integrity verification. The process is straightforward:

1. **Download Binary**: Upptime fetches the specified version of the Audit Status binary from GitHub Releases.
2. **SCP to Server**: It copies the binary to `/dev/shm` on the remote server, an in-memory filesystem that ensures automatic cleanup.
3. **Execute Audit**: It runs the binary via SSH, passing all configuration as command-line flags.
4. **Parse Output**: It captures and parses the JSON output to determine the check's result.
5. **Cleanup**: Finally, it removes the binary from the remote server.

This approach requires no pre-installed software on the remote server besides an SSH server, and all configuration is managed centrally in the `.upptimerc.yml` file.
