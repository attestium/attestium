# Security Architecture

Our security strategy is built on a defense-in-depth approach, combining standard cryptographic primitives, a hardware root of trust, and a clear threat model.

## Cryptographic Primitives

We use standard, well-vetted cryptographic tools:

* **SHA-256**: For all file and process hashing.
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

## Threat Model

We consider three primary adversaries:

1. **External Attacker**: An attacker who has gained unauthorized access to the server (e.g., through a remote code execution vulnerability). They may be able to tamper with files but cannot compromise the TPM or Attestium itself.
2. **Insider Threat**: A user with legitimate server access who may tamper with files or modify the Attestium configuration, but cannot compromise the TPM.
3. **Supply Chain Compromise**: An attacker who has compromised an upstream dependency (e.g., a malicious npm package). They may be able to inject malicious code into the application but cannot compromise the underlying OS or TPM.

Attestium is designed to detect and mitigate all three threats. File and process integrity checks detect tampering by external or internal actors. TPM-based attestation detects a compromised OS or boot process. Our layered architecture, with its clear separation of concerns, helps mitigate the risk of a supply chain compromise.
