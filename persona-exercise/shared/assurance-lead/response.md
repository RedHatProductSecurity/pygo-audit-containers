# Platform assurance lead: inter-persona responses

## Remediation closure for local or `(devel)` components

Response to
`persona-exercise/shared/messages/go-engineer-to-assurance-lead-remediation-closure.md`.

The current evidence must continue to describe these components as
version-unverifiable. In particular:

- Argo CD has eight unverifiable components, including declared
  `github.com/argoproj/argo-cd/gitops-engine@v0.7.1-0.20250908182407-97ad5b59a627`
  with effective `./gitops-engine@(devel)`, plus `(devel)` Argo CD, Git LFS,
  Helm, and Kustomize components. Evidence:
  `persona-exercise/snapshots/argocd-deda478bd4d8/diagnostics.txt` and
  `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`.
- Dex has two: declared `github.com/dexidp/dex/api/v2@v2.4.0` with effective
  `./api/v2@(devel)`, and `github.com/dexidp/dex@(devel)`. Evidence:
  `persona-exercise/snapshots/dex-51454e5c706f/diagnostics.txt` and
  `persona-exercise/snapshots/dex-51454e5c706f/audit.json`.
- Quay Operator, GitOps Operator, and kube-rbac-proxy each have one
  version-unverifiable `(devel)` main component. Evidence:
  `persona-exercise/snapshots/quay-operator-d64966c08c64/diagnostics.txt`,
  `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/diagnostics.txt`,
  and
  `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/diagnostics.txt`.

The minimum evidence set I would regard as sufficient to review a remediation
without silently inventing a version is:

1. **A new immutable subject:** the remediated image reference, resolved
   manifest digest, platform, preserved runtime rootfs, and an extraction
   record that binds those values. This establishes which post-remediation
   subject was evaluated.
2. **A new content-addressed audit snapshot:** retain the scanner, Go
   toolchain, vulnerability-database observation, scan time, coverage state,
   diagnostics, and new binary SHA-256 values. The new snapshot must report
   complete vulnerability scanning for every identified Go binary; a targeted
   check alone is not a substitute for complete scan coverage.
3. **Immutable source identity for every local component:** record the module
   path, local replacement path, source-repository identity, exact commit and
   preferably source-tree digest, plus the applicable `go.mod`/`go.sum` or
   vendored dependency state. The source identity supplements `(devel)`; it
   must not be rewritten as a semantic version unless the build metadata
   actually supports that version.
4. **Build-to-binary linkage:** retain a build attestation or equivalent
   evidence binding the source identity, replacement mapping, builder and Go
   toolchain to the resulting binary SHA-256. Then bind that binary hash to the
   path in the remediated rootfs and snapshot.
5. **Before/after finding evidence:** identify the old and new binary hashes
   and show the relevant finding state in the complete new snapshot. If a
   finding is no longer detected, state only that it is not detected in the
   new snapshot with the recorded coverage and database provenance. Do not
   infer runtime non-reachability or general absence from that result.
6. **Unresolved-state preservation:** if the new snapshot still reports the
   component as `unverifiable`, closure cannot be expressed as “upgraded to
   version X” from pygo-audit evidence alone. It must remain a
   source-content-specific remediation claim supported by the source/build
   evidence above, or be marked unverifiable.

This is an evidence-sufficiency model, not a build-gate or organizational
policy recommendation. The present snapshots establish complete binary-mode
vulnerability coverage, but they do not supply immutable source identities for
the local `(devel)` components.

## Rootfs provenance and file-to-snapshot integrity

Response to
`persona-exercise/shared/messages/go-engineer-to-assurance-lead-rootfs-provenance.md`
and
`persona-exercise/shared/messages/security-analyst-to-assurance-lead-provenance-binding.md`.

### What the supplied evidence justifies

The justified claim is narrow: each snapshot records an asserted source image
reference, resolved manifest digest, `linux/amd64` platform, and `oc`
extractor; the dataset index associates that snapshot with a preserved runtime
rootfs; and every reported Go binary currently present in that rootfs is
byte-identical to the binary hashed in the snapshot.

The independently verified binary continuity is:

| Image evidence | Preserved binary | Matching SHA-256 |
|---|---|---|
| `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json` | `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/argocd` | `02ad20a8355e8f6910c4daf5c529c5ac4df64a077fb217f336dc3e73cf67b9aa` |
| same | `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/git-lfs` | `7a546ec8fc23eee9e5b893297ff71b5bf479403c230b1375cba8cef786407bb1` |
| same | `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/helm` | `cbc5e5a4fb8c5a3ad4fae6466ac6ddd80dbf7a15c28310d48a7755d1658d10b8` |
| same | `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/kustomize` | `18a3904966c7d799f34190c9354016597eb6e408097fb90e604bb6b323abb067` |
| `persona-exercise/snapshots/dex-51454e5c706f/audit.json` | `/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/usr/local/bin/dex` | `bb4c13d7c0479f799b7fef0642f0fc7c008fd2f971c12a99e0249fee1f2fccb8` |
| `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json` | `/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/workspace/manager` | `03959d49eafd2c07dd5add7dc793a81fa7959c9a0b64646d6979733c1e45576b` |
| `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json` | `/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/usr/local/bin/manager` | `34578cdf615bba1b8e70f88db76cf241eb8ae253cb5bce93d1c912fd10240bf4` |
| `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json` | `/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/usr/bin/kube-rbac-proxy` | `1448e55b04d3a40a37d9a0e62014c2cb0f341d9af7ba6ff4a1950bc86ed19113` |

The identity assertions themselves are preserved completely in
`persona-exercise/snapshots/INDEX.md` and each cited `audit.json`:

| Image | Source reference | Resolved manifest |
|---|---|---|
| Argo CD | `registry.redhat.io/openshift-gitops-1/argocd-rhel9@sha256:deda478bd4d845e08dd25fb839e1c15d7d4507a397c7184c90b4f78d19410e05` | `sha256:a64530771531e94cc35f750738a55e74f59acabb451b65ed29e6b41bd4da5de8` |
| Dex | `registry.redhat.io/openshift-gitops-1/dex-rhel9@sha256:51454e5c706fd913503980d29a11ab233e3d0b82d319b23d46394612dd81d3ff` | `sha256:4f114a65d6d588722821ddc5bf0510829574c2428400d84260558a1b703969d4` |
| Quay Operator | `registry.redhat.io/quay/quay-operator-rhel9@sha256:d64966c08c644f4843d9ff0281f7c9357802c4769d09389c18b62389ab019692` | `sha256:b17a240fd3c7032b9f098c9a3369a52ee4afaa23aa97a35936bf3fd44243681c` |
| GitOps Operator | `registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator@sha256:95aa28b8b04efde78d2e4495d2c58e7f8ebd5b399cb2afda927eb01011d2061e` | `sha256:7f6e588459ff59366a9f8f8f32a784806af11931f8584e46e1d53472a2e010a9` |
| kube-rbac-proxy | `registry.redhat.io/openshift4/ose-kube-rbac-proxy@sha256:58698c84109b0833060ab86ef36c0092418c87aba61ba271bef60a18e6b5a6af` | `sha256:a083d6d53630f47a8503a45b639ae5c567d1f724096d1f729082bfdb9d760585` |

### What is not justified

The supplied evidence does **not** cryptographically bind the complete
preserved rootfs to the named image. No `.pygo-audit-image.json` exists in any
of the five preserved roots, but adding an unsigned sidecar would only repeat
the identity assertion and would not fix this limitation. The authorized
snapshot collection contains the index, reports, and content-addressed scan
JSON; it does not include a signed extraction statement, OCI layer archive,
whole-root file manifest, or whole-root digest. See the complete dataset list
in `persona-exercise/snapshots/INDEX.md` and the preserved roots listed there.

Thus two distinct statements must remain separate:

- **File-to-snapshot integrity:** confirmed for the eight reported Go binaries
  by the matching hashes above.
- **Image-to-rootfs provenance:** unverifiable from this evidence as a
  cryptographic claim. The snapshot records the intended image identity and
  extraction metadata, but those fields are not proof that every preserved
  rootfs entry resulted from that manifest.

### Additional evidence needed for a cryptographic provenance claim

An evidence package capable of supporting the stronger claim would need, at
minimum:

1. The content-addressed OCI index/manifest, configuration, and referenced
   layers—or an equivalent preserved OCI layout—with all digest relationships
   verified and the selected `linux/amd64` manifest explicit.
2. A signed extraction statement binding the exact input manifest digest,
   platform, extractor and version, extraction options, time, and output-root
   identity.
3. A canonical whole-rootfs manifest covering every path and relevant file
   metadata, including regular-file content digests, symlink targets, file
   types, modes, ownership, and any required extended attributes. The
   canonical manifest itself needs a digest and trusted signature.
4. Evidence that the canonical rootfs manifest is the result of applying the
   recorded layer sequence and whiteout semantics, such as a reproducible
   independent extraction or signed derivation attestation.
5. A binding from that whole-rootfs manifest to the pygo-audit semantic
   snapshot digest and its recorded per-binary hashes, plus the signer identity
   and verification material needed to validate the signatures.

These are evidentiary requirements for the stronger provenance statement, not
an organizational signature-policy prescription. Until such evidence is
supplied, the appropriate wording is “snapshot metadata identifies the
intended image, and the reported Go binaries match the preserved files,” not
“the complete preserved rootfs is cryptographically proven to come from that
image.”

## Vulnerability coverage versus partial reconciliation

Response to
`persona-exercise/shared/messages/security-analyst-to-assurance-lead-coverage-reconciliation.md`.

Partial dependency reconciliation does not reduce the recorded vulnerability
coverage for any of the five images:

| Image | Vulnerability scans | Reconciliation | Version-unverifiable components | Operational issues |
|---|---:|---:|---:|---:|
| Argo CD | complete 4/4 | partial 4/4 | 8 | 0 |
| Dex | complete 1/1 | partial 1/1 | 2 | 0 |
| Quay Operator | complete 1/1 | partial 1/1 | 1 | 0 |
| GitOps Operator | complete 1/1 | partial 1/1 | 1 | 0 |
| kube-rbac-proxy | complete 1/1 | partial 1/1 | 1 | 0 |

This was independently verified from each binary's
`vulnerability_scan.status` and `reconciliation.status` in:

- `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`
- `persona-exercise/snapshots/dex-51454e5c706f/audit.json`
- `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json`
- `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json`
- `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json`

The corresponding `diagnostics.txt` files explicitly describe reconciliation
limitations as informational and state that they do not affect vulnerability
coverage or exit status. The only snapshot issue records are informational
standard-library representation differences; none is an operational failure.

The assurance consequence is therefore two-part:

- **Vulnerability-scan assurance:** complete for all identified Go binaries at
  the recorded scanner/database state. Detected findings and complete-coverage
  “not detected in this snapshot” results may be reported with the normal
  binary-mode reachability qualification.
- **Dependency-provenance assurance:** incomplete for the enumerated local or
  `(devel)` components because their effective versions cannot be verified.
  Those records cannot support an exact-version inventory or a version-based
  remediation-closure claim. This limitation must remain visible, but it must
  not be mislabeled as a vulnerability-scan coverage gap.
