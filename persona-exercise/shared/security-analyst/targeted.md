# Security Analyst Targeted Vulnerability Follow-up

## Method and result boundaries

I rendered read-only targeted checks from each supplied `audit.json`; I did not
rescan any rootfs or query an external source. All five snapshots record a
complete vulnerability scan for every identified Go binary, so none of the 20
identifier-container pairs is indeterminate. The recorded database update is
`2026-09-16T18:00:43Z`.

“Not detected in this snapshot” means only that no matching finding occurs in
that completed, historical snapshot. It does not mean that the container or
binary is not vulnerable. Partial dependency reconciliation in these
snapshots is informational and does not reduce the stated vulnerability-scan
coverage.

Exact evidence locations used throughout:

| Label | Snapshot | Preserved rootfs |
|---|---|---|
| Argo CD | `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json` | `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/` |
| Dex | `persona-exercise/snapshots/dex-51454e5c706f/audit.json` | `/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/` |
| Quay Operator | `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json` | `/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/` |
| GitOps Operator | `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json` | `/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/` |
| kube-rbac-proxy | `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json` | `/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/` |

For detected results, rootfs inspection independently confirms that every
reported binary pathname exists as a regular file. It does not add package,
symbol, runtime-reachability, or exploitability evidence. For non-detected
results, rootfs inspection adds no vulnerability-specific evidence: no
authorized advisory mapping or independent vulnerability scan is present in
the rootfs, so file presence or absence cannot strengthen the negative result.

## Argo CD

Coverage basis for every row: `complete`, 4 of 4 identified Go binaries; no
operational vulnerability-scan failure is recorded in the Argo CD snapshot.

| Identifier | Result | Snapshot evidence | Rootfs relevance |
|---|---|---|---|
| `CVE-2026-46595` | **detected** | Package `golang.org/x/crypto/ssh`, module `golang.org/x/crypto`, symbol evidence. Current version `v0.36.0` in `/usr/local/bin/git-lfs`; current version `v0.45.0` in `/usr/local/bin/helm`. | Both `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/git-lfs` and `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/helm` exist as regular files. That confirms path preservation only. |
| `CVE-2025-68121` | **not detected in this snapshot** | No matching finding in the completed 4/4 snapshot. This is not a claim of non-vulnerability or component absence. | No vulnerability-specific evidence added. The rootfs cannot turn this snapshot-negative result into a clean-container claim. |
| `CVE-2026-41889` | **not detected in this snapshot** | No matching finding in the completed 4/4 snapshot. | No vulnerability-specific evidence added. |
| `CVE-2024-3094` | **not detected in this snapshot** | No matching finding in the completed 4/4 snapshot. | No supplied rootfs record associates a file with this identifier; vulnerability status remains bounded to the snapshot result. |

Evidence paths: `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`
and `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/`.

## Dex

Coverage basis for every row: `complete`, 1 of 1 identified Go binary; no
operational vulnerability-scan failure is recorded.

| Identifier | Result | Snapshot evidence | Rootfs relevance |
|---|---|---|---|
| `CVE-2026-46595` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. This does not prove that `golang.org/x/crypto` or a package is absent; the same snapshot declares `golang.org/x/crypto@v0.51.0`. | No vulnerability-specific evidence added. |
| `CVE-2025-68121` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. Other findings provide `crypto/tls` symbol evidence, so this negative result cannot mean the package is absent. | No vulnerability-specific evidence added. |
| `CVE-2026-41889` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. | No vulnerability-specific evidence added. |
| `CVE-2024-3094` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. | No supplied rootfs evidence maps a file to this identifier. |

Evidence paths: `persona-exercise/snapshots/dex-51454e5c706f/audit.json`
and `/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/`.

## Quay Operator

Coverage basis for every row: `complete`, 1 of 1 identified Go binary; no
operational vulnerability-scan failure is recorded.

| Identifier | Result | Snapshot evidence | Rootfs relevance |
|---|---|---|---|
| `CVE-2026-46595` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. The snapshot still declares `golang.org/x/crypto@v0.41.0`; the negative result is not module-absence evidence. | No vulnerability-specific evidence added. |
| `CVE-2025-68121` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. Other findings provide `crypto/tls` symbol evidence; the package therefore cannot be inferred absent. | No vulnerability-specific evidence added. |
| `CVE-2026-41889` | **detected** | Package `github.com/jackc/pgx/v5/internal/sanitize`, module `github.com/jackc/pgx/v5`, current version `v5.7.4`, symbol evidence, affecting `/workspace/manager`. | `/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/workspace/manager` exists as a regular file. This confirms path preservation only. |
| `CVE-2024-3094` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. | No supplied rootfs evidence maps a file to this identifier. |

Evidence paths:
`persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json` and
`/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/`.

## GitOps Operator

Coverage basis for every row: `complete`, 1 of 1 identified Go binary; no
operational vulnerability-scan failure is recorded.

| Identifier | Result | Snapshot evidence | Rootfs relevance |
|---|---|---|---|
| `CVE-2026-46595` | **detected** | Package `golang.org/x/crypto/ssh`, module `golang.org/x/crypto`, current version `v0.39.0`, symbol evidence, affecting `/usr/local/bin/manager`. | `/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/usr/local/bin/manager` exists as a regular file. This confirms path preservation only. |
| `CVE-2025-68121` | **detected** | Package `crypto/tls`, module `stdlib`, current version `v1.24.6`, symbol evidence, affecting `/usr/local/bin/manager`. | The same preserved manager file exists; rootfs inspection adds no package or runtime-reachability evidence. |
| `CVE-2026-41889` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. | No vulnerability-specific evidence added. |
| `CVE-2024-3094` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. | No supplied rootfs evidence maps a file to this identifier. |

Evidence paths:
`persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json` and
`/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/`.

## kube-rbac-proxy

Coverage basis for every row: `complete`, 1 of 1 identified Go binary; no
operational vulnerability-scan failure is recorded.

| Identifier | Result | Snapshot evidence | Rootfs relevance |
|---|---|---|---|
| `CVE-2026-46595` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. The snapshot declares `golang.org/x/crypto@v0.27.0`, so non-detection does not prove module absence. | No vulnerability-specific evidence added. |
| `CVE-2025-68121` | **detected** | Package `crypto/tls`, module `stdlib`, current version `v1.20.12`, symbol evidence, affecting `/usr/bin/kube-rbac-proxy`. | `/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/usr/bin/kube-rbac-proxy` exists as a regular file. This confirms path preservation only. |
| `CVE-2026-41889` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. | No vulnerability-specific evidence added. |
| `CVE-2024-3094` | **not detected in this snapshot** | No matching finding in the completed 1/1 snapshot. | No supplied rootfs evidence maps a file to this identifier. |

Evidence paths:
`persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json` and
`/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/`.

## Cross-container result matrix

| Image | CVE-2026-46595 | CVE-2025-68121 | CVE-2026-41889 | CVE-2024-3094 |
|---|---|---|---|---|
| Argo CD | detected | not detected in this snapshot | not detected in this snapshot | not detected in this snapshot |
| Dex | not detected in this snapshot | not detected in this snapshot | not detected in this snapshot | not detected in this snapshot |
| Quay Operator | not detected in this snapshot | not detected in this snapshot | detected | not detected in this snapshot |
| GitOps Operator | detected | detected | not detected in this snapshot | not detected in this snapshot |
| kube-rbac-proxy | not detected in this snapshot | detected | not detected in this snapshot | not detected in this snapshot |

## Comparison with organic analysis

### Already discovered organically

- The organic analysis explicitly performed full five-image treatment of
  `CVE-2026-46595` and `CVE-2025-68121`, including every detected binary,
  package/module, current version, evidence level, and carefully qualified
  negative result. The targeted results agree with it.
- `CVE-2026-41889` was already present in the Quay Operator's complete
  identifier inventory, and `github.com/jackc/pgx/v5@v5.7.4` was listed among
  its finding-bearing components. The targeted phase adds the explicit binding
  to package `github.com/jackc/pgx/v5/internal/sanitize`, symbol evidence, and
  `/workspace/manager`.
- The organic per-image vulnerability inventories did not list
  `CVE-2026-41889` for the other four images, but they did not explicitly run
  or state a targeted negative check for that identifier.

### Missed in organic analysis

- `CVE-2024-3094` was not explicitly investigated. It was absent from every
  organic detected-identifier inventory, but absence from a list was not
  presented as a targeted result. The follow-up now establishes “not detected
  in this snapshot” with complete coverage for each of the five images.
- The organic assessment did not explicitly state the four negative
  `CVE-2026-41889` results. Those results are now recorded with their coverage
  basis.

### Negative-result and component-presence discipline

No organic conclusion overstated a negative result or confused module presence
with a detected vulnerable package. It consistently used “not detected in this
snapshot,” recorded the historical database boundary, and explicitly used
counterexamples showing that non-detection does not prove module/package
absence. The targeted phase reinforces that distinction: every negative result
has complete Go-binary scan coverage, yet none supports a general claim that
the container is not vulnerable.
