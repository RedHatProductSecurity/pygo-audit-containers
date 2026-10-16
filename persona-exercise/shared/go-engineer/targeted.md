# Go Remediation Engineer — Targeted Vulnerability Follow-up

## Evidence and interpretation

This follow-up uses only the supplied snapshots and preserved runtime root filesystems.
All five snapshots report complete govulncheck binary-scan coverage for every identified
Go binary, so none of the 20 identifier-container pairs is indeterminate. A result of
**not detected in this snapshot** means only that no matching finding record exists in
that completed snapshot. It is not a claim that the image, rootfs, binary, native code,
or an unexamined package is not vulnerable.

Evidence labels below expand to these exact paths:

- **A-S** — `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`
- **A-R1** — `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/argocd`
- **A-R2** — `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/git-lfs`
- **A-R3** — `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/helm`
- **A-R4** — `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/kustomize`
- **D-S** — `persona-exercise/snapshots/dex-51454e5c706f/audit.json`
- **D-R** — `/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/usr/local/bin/dex`
- **Q-S** — `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json`
- **Q-R** — `/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/workspace/manager`
- **G-S** — `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json`
- **G-R** — `/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/usr/local/bin/manager`
- **R-S** — `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json`
- **R-R** — `/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/usr/bin/kube-rbac-proxy`

## Argo CD

Container:
`registry.redhat.io/openshift-gitops-1/argocd-rhel9@sha256:deda478bd4d845e08dd25fb839e1c15d7d4507a397c7184c90b4f78d19410e05`.
Snapshot coverage is complete for 4/4 Go binaries: `/usr/local/bin/argocd`,
`/usr/local/bin/git-lfs`, `/usr/local/bin/helm`, and `/usr/local/bin/kustomize`.
Evidence: **A-S**.

| Identifier | Result | Coverage basis | Detected binary/package/version evidence | Rootfs relevance | Evidence |
|---|---|---|---|---|---|
| CVE-2026-46595 | **detected** | Complete, 4/4 | `/usr/local/bin/git-lfs`: `golang.org/x/crypto/ssh`, module `golang.org/x/crypto@v0.36.0`, symbol evidence. `/usr/local/bin/helm`: the same package, module `golang.org/x/crypto@v0.45.0`, symbol evidence. | Limited additional integrity evidence: **A-R2** and **A-R3** exist and hash to the values recorded in **A-S**. This confirms the affected preserved files match the snapshot, not runtime reachability. | **A-S**, **A-R2**, **A-R3** |
| CVE-2025-68121 | **not detected in this snapshot** | Complete, 4/4 | No matching finding record. This does not establish non-vulnerability or package absence. | No vulnerability-specific evidence. **A-R1**–**A-R4** exist and match snapshot hashes, which only connects the preserved Go files to the snapshot. | **A-S**, **A-R1**–**A-R4** |
| CVE-2026-41889 | **not detected in this snapshot** | Complete, 4/4 | No matching finding record. This does not establish non-vulnerability or associated-component absence. | No vulnerability-specific evidence; file/hash verification adds only snapshot-to-rootfs file integrity. | **A-S**, **A-R1**–**A-R4** |
| CVE-2024-3094 | **not detected in this snapshot** | Complete for the four identified Go binaries | No matching Go finding record. No conclusion about other rootfs components is supported. | No vulnerability-specific rootfs evidence was available from the supplied records; matching Go-binary files do not answer whether the identifier applies elsewhere in the rootfs. | **A-S**, **A-R1**–**A-R4** |

Rootfs hashes independently observed: **A-R1**
`02ad20a8355e8f6910c4daf5c529c5ac4df64a077fb217f336dc3e73cf67b9aa`, **A-R2**
`7a546ec8fc23eee9e5b893297ff71b5bf479403c230b1375cba8cef786407bb1`, **A-R3**
`cbc5e5a4fb8c5a3ad4fae6466ac6ddd80dbf7a15c28310d48a7755d1658d10b8`, and **A-R4**
`18a3904966c7d799f34190c9354016597eb6e408097fb90e604bb6b323abb067`; all match
**A-S**.

## Dex

Container:
`registry.redhat.io/openshift-gitops-1/dex-rhel9@sha256:51454e5c706fd913503980d29a11ab233e3d0b82d319b23d46394612dd81d3ff`.
Snapshot coverage is complete for the sole identified Go binary, `/usr/local/bin/dex`.
Evidence: **D-S**.

| Identifier | Result | Coverage basis | Detected binary/package/version evidence | Rootfs relevance | Evidence |
|---|---|---|---|---|---|
| CVE-2026-46595 | **not detected in this snapshot** | Complete, 1/1 | No matching finding record; no non-vulnerability or component-absence conclusion follows. | No vulnerability-specific evidence. **D-R** exists and matches the snapshot hash, establishing only file identity. | **D-S**, **D-R** |
| CVE-2025-68121 | **not detected in this snapshot** | Complete, 1/1 | No matching finding record; no non-vulnerability or package-absence conclusion follows. | No vulnerability-specific evidence; the matching rootfs file only confirms the scanned binary is preserved. | **D-S**, **D-R** |
| CVE-2026-41889 | **not detected in this snapshot** | Complete, 1/1 | No matching finding record; no non-vulnerability or associated-component-absence conclusion follows. | No vulnerability-specific evidence; file integrity is the only added fact. | **D-S**, **D-R** |
| CVE-2024-3094 | **not detected in this snapshot** | Complete for the identified Go binary | No matching Go finding record. This does not address other rootfs components. | No vulnerability-specific evidence; the Go-binary hash cannot answer whether the identifier applies elsewhere in the rootfs. | **D-S**, **D-R** |

**D-R** hashes to
`bb4c13d7c0479f799b7fef0642f0fc7c008fd2f971c12a99e0249fee1f2fccb8`, matching
**D-S**.

## Quay Operator

Container:
`registry.redhat.io/quay/quay-operator-rhel9@sha256:d64966c08c644f4843d9ff0281f7c9357802c4769d09389c18b62389ab019692`.
Snapshot coverage is complete for the sole identified Go binary, `/workspace/manager`.
Evidence: **Q-S**.

| Identifier | Result | Coverage basis | Detected binary/package/version evidence | Rootfs relevance | Evidence |
|---|---|---|---|---|---|
| CVE-2026-46595 | **not detected in this snapshot** | Complete, 1/1 | No matching finding record. `golang.org/x/crypto@v0.41.0` is nevertheless declared in this binary, demonstrating that non-detection is not module absence. | No vulnerability-specific evidence. **Q-R** exists and matches the snapshot hash. | **Q-S**, **Q-R** |
| CVE-2025-68121 | **not detected in this snapshot** | Complete, 1/1 | No matching finding record; no non-vulnerability or package-absence conclusion follows. | No vulnerability-specific evidence; rootfs inspection adds only file identity. | **Q-S**, **Q-R** |
| CVE-2026-41889 | **detected** | Complete, 1/1 | `/workspace/manager`: `github.com/jackc/pgx/v5/internal/sanitize`, module `github.com/jackc/pgx/v5@v5.7.4`, symbol evidence. | Limited additional integrity evidence: **Q-R** exists and hashes to the value in **Q-S**. It does not prove runtime execution of the vulnerable symbol. | **Q-S**, **Q-R** |
| CVE-2024-3094 | **not detected in this snapshot** | Complete for the identified Go binary | No matching Go finding record. No conclusion about other rootfs components follows. | No vulnerability-specific evidence; matching the Go binary cannot answer whether the identifier applies elsewhere in the rootfs. | **Q-S**, **Q-R** |

**Q-R** hashes to
`03959d49eafd2c07dd5add7dc793a81fa7959c9a0b64646d6979733c1e45576b`, matching
**Q-S**.

## GitOps Operator

Container:
`registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator@sha256:95aa28b8b04efde78d2e4495d2c58e7f8ebd5b399cb2afda927eb01011d2061e`.
Snapshot coverage is complete for the sole identified Go binary, `/usr/local/bin/manager`.
Evidence: **G-S**.

| Identifier | Result | Coverage basis | Detected binary/package/version evidence | Rootfs relevance | Evidence |
|---|---|---|---|---|---|
| CVE-2026-46595 | **detected** | Complete, 1/1 | `/usr/local/bin/manager`: `golang.org/x/crypto/ssh`, module `golang.org/x/crypto@v0.39.0`, symbol evidence. | Limited integrity evidence: the exact binary identified in **G-R** exists and matches the snapshot hash; runtime reachability is not established. | **G-S**, **G-R** |
| CVE-2025-68121 | **detected** | Complete, 1/1 | `/usr/local/bin/manager`: `crypto/tls`, module `stdlib@v1.24.6`, symbol evidence. | Limited integrity evidence: **G-R** matches the snapshot binary hash, but this does not prove runtime invocation. | **G-S**, **G-R** |
| CVE-2026-41889 | **not detected in this snapshot** | Complete, 1/1 | No matching finding record; no non-vulnerability or associated-component-absence conclusion follows. | No vulnerability-specific evidence; matching the preserved binary adds only file identity. | **G-S**, **G-R** |
| CVE-2024-3094 | **not detected in this snapshot** | Complete for the identified Go binary | No matching Go finding record. This does not address other rootfs components. | No vulnerability-specific evidence; rootfs file integrity cannot answer whether the identifier applies elsewhere in the rootfs. | **G-S**, **G-R** |

The exact inspected **G-R** binary hashes to
`34578cdf615bba1b8e70f88db76cf241eb8ae253cb5bce93d1c912fd10240bf4`, matching
**G-S**.

## kube-rbac-proxy

Container:
`registry.redhat.io/openshift4/ose-kube-rbac-proxy@sha256:58698c84109b0833060ab86ef36c0092418c87aba61ba271bef60a18e6b5a6af`.
Snapshot coverage is complete for the sole identified Go binary,
`/usr/bin/kube-rbac-proxy`. Evidence: **R-S**.

| Identifier | Result | Coverage basis | Detected binary/package/version evidence | Rootfs relevance | Evidence |
|---|---|---|---|---|---|
| CVE-2026-46595 | **not detected in this snapshot** | Complete, 1/1 | No matching finding record; no non-vulnerability or associated-component-absence conclusion follows. | No vulnerability-specific evidence. **R-R** exists and matches the snapshot hash. | **R-S**, **R-R** |
| CVE-2025-68121 | **detected** | Complete, 1/1 | `/usr/bin/kube-rbac-proxy`: `crypto/tls`, module `stdlib@v1.20.12`, symbol evidence. | Limited integrity evidence: **R-R** exists and matches the snapshot binary hash. Runtime invocation is not established. | **R-S**, **R-R** |
| CVE-2026-41889 | **not detected in this snapshot** | Complete, 1/1 | No matching finding record; no non-vulnerability or associated-component-absence conclusion follows. | No vulnerability-specific evidence; rootfs inspection adds only file identity. | **R-S**, **R-R** |
| CVE-2024-3094 | **not detected in this snapshot** | Complete for the identified Go binary | No matching Go finding record. No conclusion about other rootfs components follows. | No vulnerability-specific evidence; the preserved Go-binary hash cannot answer whether the identifier applies elsewhere in the rootfs. | **R-S**, **R-R** |

**R-R** hashes to
`1448e55b04d3a40a37d9a0e62014c2cb0f341d9af7ba6ff4a1950bc86ed19113`, matching
**R-S**.

## Comparison with the organic analysis

### Results already discovered organically

Every targeted **detected** result was already present in the organic component matrices:

- CVE-2026-46595 in Argo CD's `/usr/local/bin/git-lfs` and `/usr/local/bin/helm`.
- CVE-2026-41889 in Quay Operator's `/workspace/manager`.
- CVE-2026-46595 and CVE-2025-68121 in GitOps Operator's
  `/usr/local/bin/manager`.
- CVE-2025-68121 in `/usr/bin/kube-rbac-proxy`.

The organic Quay Operator claim review also explicitly observed that CVE-2026-46595 was
not detected even though `golang.org/x/crypto@v0.41.0` was declared.

Organic evidence:
`persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`,
`persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json`,
`persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json`,
and
`persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json`.

### Results missed organically

The organic analysis did not perform the complete 20-pair negative check. In particular,
CVE-2024-3094 was not discussed for any image, and most other targeted negative pairs
were not individually called out. They were implicit in complete preferred-identifier
inventories but not stated as targeted results. The follow-up therefore adds explicit,
coverage-qualified negative results rather than new positive detections.

### Review of initial interpretation

No organic conclusion needs correction for overstating a negative result. The organic
analysis consistently treated absence as “not detected in this snapshot,” rejected the
claim that non-detection proves component absence, and distinguished module records from
package/symbol evidence. The targeted review reinforces two limitations:

1. A declared module can be present without a matching vulnerability finding, as shown
   by Quay Operator's x/crypto record and CVE-2026-46595.
2. Complete Go-binary coverage does not turn CVE-2024-3094's absent Go finding into a
   statement about other components in the rootfs.
