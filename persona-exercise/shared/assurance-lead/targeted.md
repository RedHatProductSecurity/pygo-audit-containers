# Platform assurance lead: targeted vulnerability follow-up

## Interpretation

This review uses the supplied schema-6 snapshots and preserved runtime roots
only. `Detected` means the snapshot contains a matching binary-mode
`govulncheck` finding. `Not detected in this snapshot` means no matching
finding appears and every Go binary identified in that snapshot completed its
vulnerability scan. It does **not** mean the container or binary is not
vulnerable, that an associated component is absent, or that exploitability was
disproved. No requested pair is indeterminate.

Rootfs inspection adds file-continuity evidence only: every Go binary reported
by these snapshots still exists at the preserved path and its SHA-256 matches
the snapshot. Reading those files does not independently add vulnerability,
reachability, or exploitability evidence.

## Evidence map and rootfs continuity

### Argo CD

- Container:
  `registry.redhat.io/openshift-gitops-1/argocd-rhel9@sha256:deda478bd4d845e08dd25fb839e1c15d7d4507a397c7184c90b4f78d19410e05`
- Snapshot: `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`
- Coverage: `persona-exercise/snapshots/argocd-deda478bd4d8/overview.txt`
- Finding detail: `persona-exercise/snapshots/argocd-deda478bd4d8/findings.txt`
- Rootfs: `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/`
- All four preserved Go binaries exist and hash-match: `/usr/local/bin/argocd`
  (`02ad20a8355e8f6910c4daf5c529c5ac4df64a077fb217f336dc3e73cf67b9aa`),
  `/usr/local/bin/git-lfs`
  (`7a546ec8fc23eee9e5b893297ff71b5bf479403c230b1375cba8cef786407bb1`),
  `/usr/local/bin/helm`
  (`cbc5e5a4fb8c5a3ad4fae6466ac6ddd80dbf7a15c28310d48a7755d1658d10b8`),
  and `/usr/local/bin/kustomize`
  (`18a3904966c7d799f34190c9354016597eb6e408097fb90e604bb6b323abb067`).

### Dex

- Container:
  `registry.redhat.io/openshift-gitops-1/dex-rhel9@sha256:51454e5c706fd913503980d29a11ab233e3d0b82d319b23d46394612dd81d3ff`
- Snapshot: `persona-exercise/snapshots/dex-51454e5c706f/audit.json`
- Coverage: `persona-exercise/snapshots/dex-51454e5c706f/overview.txt`
- Finding detail: `persona-exercise/snapshots/dex-51454e5c706f/findings.txt`
- Rootfs: `/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/`
- `/usr/local/bin/dex` exists and hash-matches
  `bb4c13d7c0479f799b7fef0642f0fc7c008fd2f971c12a99e0249fee1f2fccb8`.

### Quay Operator

- Container:
  `registry.redhat.io/quay/quay-operator-rhel9@sha256:d64966c08c644f4843d9ff0281f7c9357802c4769d09389c18b62389ab019692`
- Snapshot: `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json`
- Coverage: `persona-exercise/snapshots/quay-operator-d64966c08c64/overview.txt`
- Finding detail:
  `persona-exercise/snapshots/quay-operator-d64966c08c64/findings.txt`
- Rootfs: `/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/`
- `/workspace/manager` exists and hash-matches
  `03959d49eafd2c07dd5add7dc793a81fa7959c9a0b64646d6979733c1e45576b`.

### GitOps Operator

- Container:
  `registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator@sha256:95aa28b8b04efde78d2e4495d2c58e7f8ebd5b399cb2afda927eb01011d2061e`
- Snapshot:
  `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json`
- Coverage:
  `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/overview.txt`
- Finding detail:
  `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/findings.txt`
- Rootfs: `/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/`
- `/usr/local/bin/manager` exists and hash-matches
  `34578cdf615bba1b8e70f88db76cf241eb8ae253cb5bce93d1c912fd10240bf4`.

### kube-rbac-proxy

- Container:
  `registry.redhat.io/openshift4/ose-kube-rbac-proxy@sha256:58698c84109b0833060ab86ef36c0092418c87aba61ba271bef60a18e6b5a6af`
- Snapshot:
  `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json`
- Coverage:
  `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/overview.txt`
- Finding detail:
  `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/findings.txt`
- Rootfs:
  `/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/`
- `/usr/bin/kube-rbac-proxy` exists and hash-matches
  `1448e55b04d3a40a37d9a0e62014c2cb0f341d9af7ba6ff4a1950bc86ed19113`.

## Results by container

### Argo CD — complete coverage, 4 of 4 Go binaries

| Identifier | Result | Snapshot evidence | Rootfs relevance |
|---|---|---|---|
| `CVE-2026-46595` | **detected** | Package `golang.org/x/crypto/ssh`, module `golang.org/x/crypto`, symbol evidence: `/usr/local/bin/git-lfs` at `v0.36.0` and `/usr/local/bin/helm` at `v0.45.0`. | Both files exist and hash-match as recorded above. This ties the findings to the preserved binaries but does not prove runtime reachability. |
| `CVE-2025-68121` | **not detected in this snapshot** | No matching finding; complete 4/4 coverage supports this snapshot-scoped result. | All four scanned binaries are preserved and hash-match. Inspection adds no independent evidence that the vulnerability or associated code is absent. |
| `CVE-2026-41889` | **not detected in this snapshot** | No matching finding; complete 4/4 coverage supports this snapshot-scoped result. | Same continuity evidence; no independent vulnerability or absence evidence. |
| `CVE-2024-3094` | **not detected in this snapshot** | No matching finding; complete 4/4 coverage supports this snapshot-scoped result. | Same continuity evidence; no independent vulnerability or absence evidence. |

Exact evidence paths are the Argo CD snapshot, overview, findings report, and
rootfs paths in the evidence map above.

### Dex — complete coverage, 1 of 1 Go binary

| Identifier | Result | Snapshot evidence | Rootfs relevance |
|---|---|---|---|
| `CVE-2026-46595` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | `/usr/local/bin/dex` exists and hash-matches. That adds continuity only, not proof of absence or non-vulnerability. |
| `CVE-2025-68121` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | Same continuity-only evidence. |
| `CVE-2026-41889` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | Same continuity-only evidence. |
| `CVE-2024-3094` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | Same continuity-only evidence. |

Exact evidence paths are the Dex snapshot, overview, findings report, and
rootfs paths in the evidence map above.

### Quay Operator — complete coverage, 1 of 1 Go binary

| Identifier | Result | Snapshot evidence | Rootfs relevance |
|---|---|---|---|
| `CVE-2026-46595` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | `/workspace/manager` exists and hash-matches. That adds continuity only, not proof of absence or non-vulnerability. |
| `CVE-2025-68121` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | Same continuity-only evidence. |
| `CVE-2026-41889` | **detected** | Package `github.com/jackc/pgx/v5/internal/sanitize`, module `github.com/jackc/pgx/v5`, current version `v5.7.4`, symbol evidence, affecting `/workspace/manager`. | The affected file exists and hash-matches, tying the finding to the preserved binary; reachability remains unknown. |
| `CVE-2024-3094` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | Continuity only; no independent vulnerability or absence evidence. |

Exact evidence paths are the Quay Operator snapshot, overview, findings
report, and rootfs paths in the evidence map above.

### GitOps Operator — complete coverage, 1 of 1 Go binary

| Identifier | Result | Snapshot evidence | Rootfs relevance |
|---|---|---|---|
| `CVE-2026-46595` | **detected** | Package `golang.org/x/crypto/ssh`, module `golang.org/x/crypto`, current version `v0.39.0`, symbol evidence, affecting `/usr/local/bin/manager`. | The affected file exists and hash-matches, tying the finding to the preserved binary; reachability remains unknown. |
| `CVE-2025-68121` | **detected** | Package `crypto/tls`, module `stdlib`, current version `v1.24.6`, symbol evidence, affecting `/usr/local/bin/manager`. | The affected file exists and hash-matches; this is continuity evidence rather than independent reachability evidence. |
| `CVE-2026-41889` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | The scanned binary is preserved and hash-matches, but inspection does not prove absence or non-vulnerability. |
| `CVE-2024-3094` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | Same continuity-only evidence. |

Exact evidence paths are the GitOps Operator snapshot, overview, findings
report, and rootfs paths in the evidence map above.

### kube-rbac-proxy — complete coverage, 1 of 1 Go binary

| Identifier | Result | Snapshot evidence | Rootfs relevance |
|---|---|---|---|
| `CVE-2026-46595` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | `/usr/bin/kube-rbac-proxy` exists and hash-matches. That adds continuity only, not proof of absence or non-vulnerability. |
| `CVE-2025-68121` | **detected** | Package `crypto/tls`, module `stdlib`, current version `v1.20.12`, symbol evidence, affecting `/usr/bin/kube-rbac-proxy`. | The affected file exists and hash-matches, tying the finding to the preserved binary; reachability remains unknown. |
| `CVE-2026-41889` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | Continuity only; no independent vulnerability or absence evidence. |
| `CVE-2024-3094` | **not detected in this snapshot** | No matching finding; complete 1/1 coverage supports this snapshot-scoped result. | Continuity only; no independent vulnerability or absence evidence. |

Exact evidence paths are the kube-rbac-proxy snapshot, overview, findings
report, and rootfs paths in the evidence map above.

## Cross-container result matrix

| Identifier | Argo CD | Dex | Quay Operator | GitOps Operator | kube-rbac-proxy |
|---|---|---|---|---|---|
| `CVE-2026-46595` | detected: `git-lfs`, `helm` | not detected | not detected | detected: `manager` | not detected |
| `CVE-2025-68121` | not detected | not detected | not detected | detected: `manager` | detected: `kube-rbac-proxy` |
| `CVE-2026-41889` | not detected | not detected | detected: `manager` | not detected | not detected |
| `CVE-2024-3094` | not detected | not detected | not detected | not detected | not detected |

Every “not detected” entry in this compact matrix means “not detected in this
snapshot with complete coverage,” subject to the qualifications above.

## Comparison with the organic analysis

The initial assurance analysis organically discovered every targeted positive:

- `CVE-2026-46595` in Argo CD's `/usr/local/bin/git-lfs` and
  `/usr/local/bin/helm`, supported by `golang.org/x/crypto`, and in GitOps
  Operator's `/usr/local/bin/manager` at `golang.org/x/crypto@v0.39.0`.
- `CVE-2025-68121` in GitOps Operator's `/usr/local/bin/manager` at
  `stdlib@v1.24.6` and kube-rbac-proxy's `/usr/bin/kube-rbac-proxy` at
  `stdlib@v1.20.12`.
- `CVE-2026-41889` in Quay Operator's `/workspace/manager` at
  `github.com/jackc/pgx/v5@v5.7.4`.

These appear in `persona-exercise/shared/assurance-lead/analysis.md` only as a
comparison record; the independent evidence remains the authorized snapshot
and rootfs paths cited above.

No detected targeted pair was missed. The initial analysis did not explicitly
perform or enumerate the 15 negative identifier-container checks, including
the five `CVE-2024-3094` results. It therefore did not organically discover
those targeted negative results as explicit checks, even though its complete
detected-identifier inventories did not list them.

The initial conclusions did not overstate a negative result or confuse a
declared module with a detected vulnerable package. For every image it
explicitly rejected the inference that non-detection proves package absence,
and its vulnerability groupings were built from finding records rather than
declared dependencies. The targeted follow-up reinforces that discipline:
complete coverage supports the phrase “not detected in this snapshot,” and
nothing stronger.
