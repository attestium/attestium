# Security Architecture

Our security strategy is built on a defense-in-depth approach, combining standard cryptographic primitives, a hardware root of trust, process memory analysis, supply chain provenance verification, and a clear threat model.

## Cryptographic Primitives

We use standard, well-vetted cryptographic tools:

* **SHA-256**: For all file, process, and memory page hashing.
* **HMAC-SHA256**: For keyed-hash message authentication.
* **AES-256-GCM**: For authenticated encryption of sensitive data at rest.

## TPM 2.0 Hardware-Backed Security

The security of any attestation system rests on the trustworthiness of its hardware. We designed Attestium to leverage a Trusted Platform Module (TPM) as its hardware root of trust. The TPM provides a secure environment for cryptographic operations and key storage.

### Why TPM 2.0 is Critical

Attestium **requires TPM 2.0** for production deployments where maximum security is needed. While Attestium can operate in software-only mode for development and testing, **TPM 2.0 integration is essential** for addressing the fundamental limitations of software-only verification systems.

When running in software-only mode, Attestium is vulnerable to several sophisticated attack vectors:

* **Runtime Patching**: An attacker with root access can modify the Node.js runtime or kernel to bypass Attestium's checks.
* **Memory Manipulation**: Direct memory access can alter verification logic or cryptographic keys.
* **Filesystem Tampering**: An attacker can modify files on disk and then intercept filesystem calls to return the original content to Attestium.
* **Verification Bypass**: The entire verification process can be mocked or disabled by a sufficiently privileged attacker.

TPM 2.0 provides a hardware root of trust that mitigates these attacks:

* **Hardware-Protected Keys**: Cryptographic keys are stored in the TPM chip and cannot be extracted.
* **Measured Boot**: The TPM measures the entire boot process, creating a cryptographic record of the system state.
* **Sealed Storage**: Data can be encrypted and "sealed" to a specific system state. It can only be unsealed if the system is in the exact same state.
* **Remote Attestation**: The TPM can provide a signed quote of its internal state, allowing a remote party to verify the system's integrity.

### Attestium's TPM 2.0 Integration

Attestium leverages these TPM 2.0 features to provide a secure verification environment:

* **Key Management**: Attestium's cryptographic keys are generated and stored in the TPM.
* **Integrity Verification**: The TPM is used to verify the integrity of the boot process and the running system.
* **Sealed Data**: Verification baselines are sealed to the TPM, preventing tampering.
* **Hardware Random**: The TPM's hardware random number generator is used for cryptographic operations.

## Process Memory Integrity

File-level verification answers the question: is the file on disk correct? But it cannot answer the more fundamental question: is the code *actually executing in memory* the same code that's on disk? These are different questions, and the distinction matters.

On Linux, the `/proc` filesystem exposes the internal state of every running process. An attacker who has gained root access—or who has exploited a vulnerability to gain `ptrace` capabilities—can modify a process's executable memory pages without touching the file on disk. The classic attack vectors include:

* **`ptrace` injection**: Attaching to a running process and writing arbitrary code into its address space. This is how most debuggers work, and it's how most runtime code injection is performed.
* **`/proc/<pid>/mem` writes**: Directly writing to a process's virtual memory through the proc filesystem. No debugger attachment required—just write access to the file.
* **`LD_PRELOAD` hijacking**: Setting the `LD_PRELOAD` environment variable to force the dynamic linker to load a malicious shared library before all others. The injected library can override any function in any shared library, including libc.
* **`memfd_create` fileless payloads**: Creating anonymous in-memory files that never touch the disk, then executing them via `/proc/self/fd/<n>`. This is the foundation of modern fileless malware on Linux.

Attestium's Process Integrity module detects all of these. It reads `/proc/<pid>/maps` to enumerate every memory region and flag anomalies. It reads the actual executable pages from `/proc/<pid>/mem` and hashes them against the on-disk binary. It inspects the process environment for `LD_PRELOAD`. It checks `TracerPid` for debugger attachment. And it scans file descriptors for `memfd_create` payloads.

On macOS, equivalent analysis is performed via `vmmap`, `lsof`, and process environment inspection. On Windows, PowerShell is used to enumerate loaded modules and check for `AppInit_DLLs` registry injection.

## Supply Chain Provenance

The npm ecosystem has a trust gap that most developers don't think about. When you run `npm install express`, you trust that the package on the npm registry was built from the source code in the `expressjs/express` GitHub repository. But there is no cryptographic link between the two. An attacker who compromises an npm maintainer's credentials can publish a version that contains entirely different code from what's on GitHub, and the standard `npm audit` workflow will not detect it.

Attestium's Release Verification module addresses this by performing three-way verification:

1. **Running vs. On-Disk**: Is the binary executing in memory the same as the file on disk? (Covered by Process Integrity.)
2. **On-Disk vs. Official Release**: Does the on-disk binary match the official upstream release? For Node.js, this means comparing the SHA-256 hash against the `SHASUMS256.txt` published at `nodejs.org`. For npm packages, this means comparing the lockfile integrity hash against the registry's `dist.integrity` field.
3. **Published vs. Source**: Does the version published on npm correspond to a real commit in the project's public GitHub repository? Attestium verifies the `gitHead` field from the npm registry metadata against the GitHub API, confirming that the published version was built from source code that exists in the public repository.

This three-way chain of verification—from memory to disk to upstream to source—provides end-to-end provenance for the entire runtime environment.

## Threat Model

We consider four primary adversaries:

1. **External Attacker**: An attacker who has gained unauthorized access to the server (e.g., through a remote code execution vulnerability). They may be able to tamper with files or inject code into running processes. File integrity, process memory integrity, and TPM attestation all work together to detect this class of attack.

2. **Insider Threat**: A user with legitimate server access who may tamper with files, modify the Attestium configuration, or inject code via `LD_PRELOAD` or `ptrace`. They cannot compromise the TPM. Process memory integrity and linker inspection detect these attacks even when the insider has root access.

3. **Supply Chain Compromise**: An attacker who has compromised an upstream dependency—either by injecting malicious code into the npm registry or by publishing a version that diverges from the public GitHub source. Release verification and module integrity checks detect this class of attack by verifying provenance back to the upstream source.

4. **Fileless Malware**: An attacker who operates entirely in memory, using techniques like `memfd_create`, anonymous executable mappings, or process hollowing to avoid leaving any trace on disk. Memory map analysis, file descriptor inspection, and executable page hashing detect this class of attack because they examine the actual process state, not just the filesystem.

Attestium is designed to detect and mitigate all four threats. File and process integrity checks detect tampering by external or internal actors. Process memory integrity detects in-memory injection and fileless attacks. Release verification detects supply chain compromise. TPM-based attestation detects a compromised OS or boot process. Our layered architecture, with its clear separation of concerns, provides defense in depth across the entire attack surface.
