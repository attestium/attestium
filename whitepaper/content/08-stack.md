# The Attestium Stack in Context

We didn't build Attestium in a vacuum. It stands on the shoulders of giants in system transparency, runtime attestation, and supply chain security. Here, we discuss how Attestium complements and builds upon this existing work.

## How We Compare

| Project | Focus | How We Complement It |
|---|---|---|
| **System Transparency** | Boot-time integrity | We extend ST's principles to the runtime environment, providing continuous verification of running applications and their in-memory state. |
| **Keylime** | Cloud infrastructure attestation | We offer a more application-focused, developer-friendly approach, particularly for Node.js environments, with process-level memory analysis. |
| **Sigstore** | Software artifact signing | We provide the post-deployment verification that ensures the code running in production is the same code Sigstore signed at build time—not just on disk, but in memory. |
| **SLSA** | Supply chain security framework | We provide a mechanism to enforce SLSA principles at runtime, including three-way verification from running process to upstream source. |
| **Reproducible Builds** | Verifiable software builds | We can verify that the code running in production matches a specific reproducible build, closing the loop between build and runtime. |
| **Socket.dev** | Dependency risk analysis | We complement Socket's static analysis with runtime verification, confirming that what's installed matches what's on the registry and what's on GitHub. |

```{.mermaid format=pdf}
graph LR
    subgraph L3["Upptime"]
        U1["SSH Audit"]
        U2["Git Hash"]
        U3[".upptimerc.yml"]
    end
    subgraph L2["Audit Status"]
        A1["CLI / SEA"]
        A2["Check Engine"]
        A3["PM2"]
        A4["Process Verify"]
    end
    subgraph L1["Attestium"]
        C1["Code Integrity"]
        C2["TPM"]
        C3["Tamper Store"]
        C4["Runtime Hooks"]
        C5["Process Memory"]
        C6["Release Verify"]
    end
    subgraph HW["Hardware / OS"]
        T1["TPM 2.0"]
        T2["/proc FS"]
        T3["/proc/mem"]
    end
    subgraph EXT["Upstream Sources"]
        E1["nodejs.org"]
        E2["npm Registry"]
        E3["GitHub API"]
    end
    L3 --> L2 --> L1 --> HW
    L1 --> EXT
```

## Building on Existing Work

**System Transparency (ST)**[^st] pioneered verifiable infrastructure for VPN servers. We take their boot-time integrity model and apply it to the application runtime, extending the chain of trust to the code you actually run—and now, to the code actually executing in process memory.

**Keylime**[^keylime2] offers powerful TPM-based attestation for cloud infrastructure. We provide a more lightweight, application-centric alternative, making TPM-based attestation more accessible for Node.js developers. Our process memory integrity module adds a layer that Keylime's infrastructure-level approach doesn't cover: verifying that the bytes in a process's executable pages match the binary on disk.

**Sigstore**[^sigstore2] and **SLSA**[^slsa2] are essential for securing the software supply chain at build time. We complete the picture by providing the post-deployment verification they lack, creating an end-to-end chain of trust from developer to production. Our release verification module extends this further by verifying that what's on the npm registry was actually built from the public source code on GitHub.

**Reproducible Builds**[^repro] ensure that a given set of source code always produces the same binary. This is a vital step, but as Lamb and Zacchiroli note, it is a necessary but not sufficient condition for a trustworthy supply chain[^ieee_repro2]. Attestium closes the loop by verifying that the code running in production matches a specific reproducible build—and that the process memory hasn't been modified after the binary was loaded.

[^st]: Mullvad VPN, "Introducing System Transparency for our VPN servers": [https://mullvad.net/en/blog/diskless-infrastructure-beta-system-transparency-stboot](https://mullvad.net/en/blog/diskless-infrastructure-beta-system-transparency-stboot)
[^keylime2]: Keylime, "A CNCF project for TPM-based cloud attestation": [https://keylime.dev/](https://keylime.dev/)
[^sigstore2]: Sigstore, "A new standard for signing, verifying, and protecting software": [https://www.sigstore.dev/](https://www.sigstore.dev/)
[^slsa2]: SLSA, "Supply-chain Levels for Software Artifacts": [https://slsa.dev/](https://slsa.dev/)
[^repro]: Reproducible Builds, "Increasing the integrity of software supply chains": [https://reproducible-builds.org/](https://reproducible-builds.org/)
[^ieee_repro2]: D. E. Lamb and S. Zacchiroli, "The Trustworthy Software Supply Chain," IEEE Software, 2021: [https://ieeexplore.ieee.org/document/9423215](https://ieeexplore.ieee.org/document/9423215)
