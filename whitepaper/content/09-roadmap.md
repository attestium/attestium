# Future Roadmap

We are just getting started. Here is a look at what we have shipped recently and what we have planned for the future of Attestium.

## Recently Shipped

These capabilities were on our roadmap and are now available:

* **Process Memory Integrity**: We now perform in-memory analysis of running processes to detect fileless malware, code injection attacks, `LD_PRELOAD` hijacking, debugger attachment, and anonymous executable regions. This includes byte-for-byte comparison of executable memory pages against on-disk binaries via `/proc/<pid>/mem`.
* **Three-Way Release Verification**: We now verify the running Node.js binary against official `nodejs.org` SHASUMS, verify npm/pnpm/pm2 against registry integrity hashes, and verify every installed module's provenance back to its GitHub source via `gitHead` verification.
* **Cross-Platform Support**: Process integrity and release verification now work on Linux, macOS, and Windows, using platform-native APIs (`/proc`, `vmmap`, PowerShell) on each.

## Enhanced Runtime Analysis

We plan to continue deepening our runtime analysis capabilities:

* **Behavioral Analysis**: We will add support for behavioral analysis to detect anomalous activity, such as unexpected network connections, file access patterns, or unusual system call sequences.
* **eBPF Integration**: We are exploring eBPF to provide a more efficient and powerful mechanism for runtime monitoring with minimal overhead. eBPF would allow us to hook into kernel events in real time, providing continuous verification without the polling overhead of reading `/proc`.
* **Deep Node.js Binary Verification**: We plan to add full archive extraction for Node.js release verification on Linux and macOS, downloading the official tarball, extracting the binary, and performing a direct hash comparison rather than relying on archive-level SHASUMS.

## Broader Platform Support

Our goal is to make Attestium a cross-platform solution. We have recently added macOS and Windows support for process integrity and release verification. We plan to extend this further:

* **Additional Language Runtimes**: Support for Python, Go, and Rust binaries, with runtime-specific verification strategies for each.
* **Container-Aware Verification**: Process integrity checks that understand container namespaces and can verify processes inside Docker/Podman containers from the host.

## Cloud Provider Integration

We are exploring integrations with cloud providers to enhance security in cloud environments:

* **AWS Nitro Enclaves**: We plan to use Nitro Enclaves to create a secure and isolated environment for the Attestium verifier, enabling remote attestation of EC2 instances without trusting the underlying hypervisor.
* **Google Cloud and Azure Confidential Computing**: We are also exploring similar integrations with Google Cloud and Azure's confidential computing offerings.

## Community and Collaboration

Attestium is an open-source project, and we are committed to building a strong community around it. We welcome contributions and are eager to collaborate with other projects in the software supply chain security space, including Sigstore, SLSA, and Keylime. We believe that by working together, we can build a more secure and trustworthy digital ecosystem.
