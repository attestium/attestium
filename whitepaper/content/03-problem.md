# The Problem

The software supply chain is broken. We have focused intensely on securing software before it's deployed, but we've largely ignored what happens after. This is the critical gap where trust evaporates.

## Build-Time Security is Not Enough

We have made great strides with initiatives like SLSA[^slsa] and Sigstore[^sigstore], creating a chain of trust from source code to binary. But that chain breaks at runtime. As Google's engineers noted, build-time enforcement alone cannot protect infrastructure from compromised code[^google_bab]. A runtime mechanism is not just a nice-to-have; it is a necessity.

## Where Existing Solutions Fall Short

Before developing Attestium, we conducted extensive research into existing verification, attestation, and integrity monitoring solutions. Our analysis revealed nine critical gaps that existing solutions couldn't address for our specific requirements:

1. **Runtime Application Verification Gap**: Most solutions focus on build-time, deployment-time, or infrastructure-level verification. They cannot detect runtime tampering or code injection attacks.

2. **Third-Party Verification API Gap**: Existing solutions lack standardized APIs for external verification, making it difficult for auditors to independently verify system integrity.

3. **Developer Experience Gap**: Hardware-based solutions require specialized knowledge and infrastructure, creating a high barrier to adoption for typical web applications.

4. **Node.js Ecosystem Gap**: Most solutions are language-agnostic or focused on other platforms, with poor integration into Node.js applications and workflows.

5. **Cost and Complexity Gap**: Many solutions are expensive or too complex for many applications and organizations.

6. **Granular Monitoring Gap**: File integrity tools monitor files, and application tools monitor performance, but no solution provides granular application code verification.

7. **Continuous Verification Gap**: Most solutions provide point-in-time verification, which cannot detect tampering between verification intervals.

8. **Process Memory Integrity Gap**: Existing tools verify files on disk, but they do not verify what is actually running in memory. An attacker who injects code via `ptrace`, writes to `/proc/<pid>/mem`, or uses `LD_PRELOAD` to hijack shared library loading will pass every file-level check because the on-disk binary is unchanged—only the in-memory copy is modified. This is the blind spot that makes fileless malware and runtime code injection so effective[^redcanary_fileless].

9. **Supply Chain Provenance Gap**: Even when a package is verified against the npm registry, there is no guarantee that the published version was built from the source code in the project's public repository. An attacker with npm publish credentials can push a version that differs entirely from what's on GitHub, and no existing tool in the Node.js ecosystem detects this divergence[^npm_supply_chain].

We need a solution that is holistic, layered, and developer-first. This is why we built Attestium.

[^slsa]: SLSA, "Supply-chain Levels for Software Artifacts": [https://slsa.dev/](https://slsa.dev/)
[^sigstore]: Sigstore, "A new standard for signing, verifying, and protecting software": [https://www.sigstore.dev/](https://www.sigstore.dev/)
[^google_bab]: Google Cloud, "Binary Authorization for Borg": [https://cloud.google.com/docs/security/binary-authorization-for-borg](https://cloud.google.com/docs/security/binary-authorization-for-borg)
[^redcanary_fileless]: Red Canary, "Process Memory Integrity on Linux": [https://redcanary.com/blog/threat-detection/process-memory-integrity-linux/](https://redcanary.com/blog/threat-detection/process-memory-integrity-linux/)
[^npm_supply_chain]: Socket, "Supply Chain Attacks on npm": [https://socket.dev/blog/supply-chain-attacks-on-npm](https://socket.dev/blog/supply-chain-attacks-on-npm)
