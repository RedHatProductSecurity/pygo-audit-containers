# Security Analyst Phase-One Analysis

## Evidence boundary and interpretation

This assessment uses only the five snapshots under
`persona-exercise/snapshots/` and the corresponding preserved runtime roots
under `/tmp/pygo-audit-persona-rootfs/`. I did not rescan the roots, execute
their binaries, or consult external vulnerability information. A detected
finding below means the supplied binary-mode `govulncheck` result contains the
package/module evidence shown in the snapshot. It does not establish runtime
reachability or exploitability. “Not detected” is limited to this snapshot and
its recorded database update of `2026-09-16T18:00:43Z`.

## Executive finding summary

| Image | Audited Go binaries | Scan coverage | Unique findings | Affected packages | Reconciliation |
|---|---:|---|---:|---:|---|
| Argo CD | 4 | complete, 4/4 | 63 | 186 | partial; 8 unverifiable components and one representation difference |
| Dex | 1 | complete, 1/1 | 12 | 11 | partial; 2 unverifiable components and one representation difference |
| Quay Operator | 1 | complete, 1/1 | 14 | 13 | partial; 1 unverifiable component and one representation difference |
| GitOps Operator | 1 | complete, 1/1 | 70 | 198 | partial; 1 unverifiable component and one representation difference |
| kube-rbac-proxy | 1 | complete, 1/1 | 55 | 21 | partial; 1 unverifiable component and one representation difference |

Evidence: each image's `overview.txt`, `diagnostics.txt`, and `audit.json`
under `persona-exercise/snapshots/`. All seven audited Go binaries record
`CGO_ENABLED=true`; native libraries are explicitly outside this Go audit.
There are no vulnerability-scan timeouts or failed Go-binary scans in the five
snapshots.

### Requested vulnerability focus

| Image | CVE-2026-46595 | CVE-2025-68121 |
|---|---|---|
| Argo CD | **Detected:** `golang.org/x/crypto/ssh`, module `golang.org/x/crypto`; `v0.36.0` in `/usr/local/bin/git-lfs` and `v0.45.0` in `/usr/local/bin/helm`; symbol evidence | **Not detected in this snapshot**, complete 4/4 coverage |
| Dex | **Not detected in this snapshot**, complete 1/1 coverage | **Not detected in this snapshot**, complete 1/1 coverage |
| Quay Operator | **Not detected in this snapshot**, complete 1/1 coverage | **Not detected in this snapshot**, complete 1/1 coverage |
| GitOps Operator | **Detected:** `golang.org/x/crypto/ssh`, `golang.org/x/crypto@v0.39.0`, `/usr/local/bin/manager`; symbol evidence | **Detected:** `crypto/tls`, `stdlib@v1.24.6`, `/usr/local/bin/manager`; symbol evidence |
| kube-rbac-proxy | **Not detected in this snapshot**, complete 1/1 coverage | **Detected:** `crypto/tls`, `stdlib@v1.20.12`, `/usr/bin/kube-rbac-proxy`; symbol evidence |

Evidence: the five `audit.json` files, rendered with snapshot-backed targeted
checks. A negative result must not be read as component absence: for example,
Dex, Quay Operator, and kube-rbac-proxy all declare `golang.org/x/crypto`
despite no `CVE-2026-46595` finding, and Argo CD, Dex, and Quay Operator have
other symbol findings in `crypto/tls` despite no `CVE-2025-68121` finding.

Six identifiers recur in all five image snapshots:
`CVE-2026-33818`, `CVE-2026-39821`, `CVE-2026-56853`,
`CVE-2026-56859`, `CVE-2026-56860`, and `CVE-2026-56862`. This is a
cross-image detection pattern only; the supplied evidence contains no severity
or exploitability basis for ranking them.

## Argo CD

Image:
`registry.redhat.io/openshift-gitops-1/argocd-rhel9@sha256:deda478bd4d845e08dd25fb839e1c15d7d4507a397c7184c90b4f78d19410e05`

Primary evidence:
`persona-exercise/snapshots/argocd-deda478bd4d8/audit.json` and
`/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/`.

1. **Go binary inventory.** Four of 476 ELF files were identified as Go
   binaries: `/usr/local/bin/argocd`, `/usr/local/bin/git-lfs`,
   `/usr/local/bin/helm`, and `/usr/local/bin/kustomize`.
2. **Build identity.** All four record
   `go1.26.5 (Red Hat 1.26.5-1.el9_8) X:strictfipsruntime` and CGO enabled.
   Main module/package pairs are `github.com/argoproj/argo-cd/v3@(devel)` /
   `github.com/argoproj/argo-cd/v3/cmd` for `argocd`, unavailable /
   `command-line-arguments` for `git-lfs`, `helm.sh/helm/v3@(devel)` /
   `helm.sh/helm/v3/cmd/helm` for `helm`, and
   `sigs.k8s.io/kustomize/kustomize/v5@(devel)` /
   `sigs.k8s.io/kustomize/kustomize/v5` for `kustomize`.
3. **Coverage.** Vulnerability coverage is complete for all four binaries.
   There are no operational scan gaps. Partial reconciliation is informational
   and does not reduce the 4/4 coverage.
4. **Path preservation.** All four reported paths exist as regular files under
   `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/`.
5. **Detected vulnerability inventory.** The complete package/current-version/
   binary matrix is in
   `persona-exercise/snapshots/argocd-deda478bd4d8/findings.txt`. The detected
   preferred identifiers are:

   `CVE-2024-7598`, `CVE-2025-1767`, `CVE-2025-47911`,
   `CVE-2025-47913`, `CVE-2025-47914`, `CVE-2025-58181`,
   `CVE-2025-58190`, `CVE-2026-25680`, `CVE-2026-25681`,
   `CVE-2026-25934`, `CVE-2026-27136`, `CVE-2026-33186`,
   `CVE-2026-33762`, `CVE-2026-33814`, `CVE-2026-33818`,
   `CVE-2026-34165`, `CVE-2026-35469`, `CVE-2026-39821`,
   `CVE-2026-39827`, `CVE-2026-39828`, `CVE-2026-39829`,
   `CVE-2026-39830`, `CVE-2026-39831`, `CVE-2026-39832`,
   `CVE-2026-39833`, `CVE-2026-39834`, `CVE-2026-39835`,
   `CVE-2026-41506`, `CVE-2026-42502`, `CVE-2026-42506`,
   `CVE-2026-42508`, `CVE-2026-44740`, `CVE-2026-44973`,
   `CVE-2026-45022`, `CVE-2026-45570`, `CVE-2026-45571`,
   `CVE-2026-46595`, `CVE-2026-46597`, `CVE-2026-46598`,
   `CVE-2026-46600`, `CVE-2026-48978`, `CVE-2026-50151`,
   `CVE-2026-50162`, `CVE-2026-50163`, `CVE-2026-56852`,
   `CVE-2026-56853`, `CVE-2026-56854`, `CVE-2026-56855`,
   `CVE-2026-56858`, `CVE-2026-56859`, `CVE-2026-56860`,
   `CVE-2026-56862`, `CVE-2026-71556`, `CVE-2026-71557`,
   `CVE-2026-78662`, `CVE-2026-84303`, `CVE-2026-84304`,
   `CVE-2026-84445`, `GHSA-259r-337f-4rfw`,
   `GHSA-hrxh-6v49-42gf`, `GHSA-vh4v-2xq2-g5cg`,
   `GHSA-w5pp-99ch-qj29`, and `GO-2026-5932`.

   Finding-bearing component versions are `stdlib@v1.26.5` (all four);
   `golang.org/x/crypto` at `v0.53.0` (`argocd`), `v0.36.0` (`git-lfs`),
   and `v0.45.0` (`helm`); `golang.org/x/net` at `v0.38.0` (`git-lfs`)
   and `v0.47.0` (`helm`); `golang.org/x/text` at `v0.38.0`, `v0.23.0`,
   `v0.31.0`, and `v0.28.0` in `argocd`, `git-lfs`, `helm`, and
   `kustomize`, respectively; `google.golang.org/grpc` at `v1.79.3`
   (`argocd`) and `v1.72.1` (`helm`); plus
   `github.com/go-git/go-billy/v5@v5.6.2`,
   `github.com/go-git/go-git/v5@v5.14.0`,
   `k8s.io/kubernetes@v1.34.2` (`argocd`),
   `github.com/klauspost/compress@v1.18.0` and
   `github.com/moby/spdystream@v0.5.0` (`helm`), and
   `oras.land/oras-go/v2@v2.6.0` (`argocd` and `helm`).
6. **Recurring dependencies and versions.** The standard library version is
   identical across all four. Ninety-one declared dependency paths recur in at
   least two binaries; 45 have different versions. The differing paths are:
   `dario.cat/mergo`, `github.com/chai2010/gettext-go`,
   `github.com/davecgh/go-spew`, `github.com/go-errors/errors`,
   `github.com/go-logr/logr`, `github.com/go-openapi/jsonpointer`,
   `github.com/go-openapi/jsonreference`, `github.com/go-openapi/swag`,
   `github.com/google/gnostic-models`, `github.com/google/uuid`,
   `github.com/mailru/easyjson`, `github.com/mattn/go-isatty`,
   `github.com/moby/spdystream`, `github.com/pkg/errors`,
   `github.com/sergi/go-diff`, `github.com/sirupsen/logrus`,
   `github.com/spf13/cast`, `github.com/spf13/cobra`,
   `github.com/spf13/pflag`, `go.yaml.in/yaml/v3`,
   `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/oauth2`,
   `golang.org/x/sync`, `golang.org/x/sys`, `golang.org/x/term`,
   `golang.org/x/text`, `golang.org/x/time`,
   `google.golang.org/genproto/googleapis/rpc`, `google.golang.org/grpc`,
   `google.golang.org/protobuf`, `gopkg.in/evanphx/json-patch.v4`,
   `k8s.io/api`, `k8s.io/apiextensions-apiserver`,
   `k8s.io/apimachinery`, `k8s.io/apiserver`, `k8s.io/cli-runtime`,
   `k8s.io/client-go`, `k8s.io/component-base`, `k8s.io/kube-openapi`,
   `k8s.io/kubectl`, `sigs.k8s.io/kustomize/api`,
   `sigs.k8s.io/kustomize/kyaml`,
   `sigs.k8s.io/structured-merge-diff/v6`, and `sigs.k8s.io/yaml`.
   Exact versions by binary are preserved in `binaries.txt`.
7. **Effective replacements.** `argocd` records
   `github.com/argoproj/argo-cd/gitops-engine@v0.7.1-0.20250908182407-97ad5b59a627`
   replaced by `./gitops-engine@(devel)`. It also records same-path/same-version
   replacements for `github.com/golang/protobuf@v1.5.4`,
   `github.com/grpc-ecosystem/grpc-gateway@v1.16.0`,
   `gopkg.in/yaml.v2@v2.4.0`, `gopkg.in/yaml.v3@v3.0.1`, and these
   `v0.34.0` modules: `k8s.io/api`, `k8s.io/apiextensions-apiserver`,
   `k8s.io/apimachinery`, `k8s.io/apiserver`, `k8s.io/cli-runtime`,
   `k8s.io/client-go`, `k8s.io/component-base`,
   `k8s.io/component-helpers`, `k8s.io/controller-manager`,
   `k8s.io/kube-aggregator`, and `k8s.io/kubectl`.
8. **Reconciliation.** Eight components are unverifiable because at least one
   side is `(devel)`: Argo CD main module and local gitops-engine replacement,
   Git LFS main module, Helm main module, and four Kustomize modules
   (`api`, `cmd/config`, `kustomize/v5`, and `kyaml`). All four binaries also
   have the informational stdlib representation difference
   `v1.26.5` versus the Red Hat `go1.26.5 ... X:strictfipsruntime` string.
   These limitations do not affect vulnerability coverage.
9. **Container-wide versus isolated patterns.** Nine findings affect all four
   Go binaries: `CVE-2026-33818`, `CVE-2026-39821`, `CVE-2026-46600`,
   `CVE-2026-56852`, `CVE-2026-56853`, `CVE-2026-56858`,
   `CVE-2026-56859`, `CVE-2026-56860`, and `CVE-2026-56862`.
   Fourteen affect only `argocd`; five only `git-lfs`; four only `helm`;
   the remaining 31 affect two or three binaries. The exact binary grouping is
   in `findings.txt`.
19. **Most important observation.** This is the only multi-Go-binary image and
    it demonstrates that a container-level vulnerability list does not define
    a uniform binary impact: dependency versions and finding sets differ
    materially among its four tools. `CVE-2026-46595` is limited to `git-lfs`
    and `helm` in this snapshot.
20. **Unsafe conclusions.** The evidence cannot establish runtime
    reachability, severity, exploitability, native-library safety, layer
    history, or cryptographic binding between the extracted root and named
    manifest. `(devel)` and local replacements prevent exact reconciliation of
    eight components.

## Dex

Image:
`registry.redhat.io/openshift-gitops-1/dex-rhel9@sha256:51454e5c706fd913503980d29a11ab233e3d0b82d319b23d46394612dd81d3ff`

Evidence: `persona-exercise/snapshots/dex-51454e5c706f/audit.json`, its
`findings.txt` and `diagnostics.txt`, and
`/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/`.

1. **Inventory:** one of 264 ELF files is identified as a Go binary,
   `/usr/local/bin/dex`.
2. **Build:** Go
   `1.26.5 (Red Hat 1.26.5-1.el9_8) X:strictfipsruntime`, main module
   `github.com/dexidp/dex@(devel)`, main package
   `github.com/dexidp/dex/cmd/dex`, CGO enabled; no requested field is
   unavailable.
3. **Coverage:** complete 1/1, with no operational scan gap.
4. **Path:** `/usr/local/bin/dex` exists in the preserved root.
5. **Findings:** 12 preferred identifiers, all mapped to that binary:
   `CVE-2026-33818`, `CVE-2026-39821`, `CVE-2026-46600`,
   `CVE-2026-56852`, `CVE-2026-56853`, `CVE-2026-56858`,
   `CVE-2026-56859`, `CVE-2026-56860`, `CVE-2026-56862`,
   `CVE-2026-84304`, `CVE-2026-84445`, and `GHSA-hrxh-6v49-42gf`.
   Finding-bearing versions are `stdlib@v1.26.5`,
   `golang.org/x/net@v0.55.0`, `golang.org/x/text@v0.37.0`, and
   `google.golang.org/grpc@v1.79.3`. Exact package mappings are in
   `persona-exercise/snapshots/dex-51454e5c706f/findings.txt`.
6. **Recurrence/version differences:** only one Go binary exists, so there is
   no within-container cross-binary version comparison. Standard-library
   packages recur within the binary at the single `v1.26.5` version.
7. **Replacement:** `github.com/dexidp/dex/api/v2@v2.4.0` is effectively
   `./api/v2@(devel)`.
8. **Reconciliation:** the local API replacement and main module are
   unverifiable due to `(devel)`; stdlib has the informational `v1.26.5`
   versus Red Hat `go1.26.5` representation difference. Coverage remains
   complete.
9. **Pattern:** every detected finding affects the sole audited Go binary;
   this says nothing about the other 263 ELF files.
19. **Most important observation:** both requested CVEs are not detected in
    this complete snapshot, while 12 other findings are detected.
20. **Unsafe conclusions:** no runtime reachability, severity, exploitability,
    native-library safety, layer completeness, or cryptographic rootfs/image
    provenance conclusion is supported; local `(devel)` components are not
    exactly versioned.

## Quay Operator

Image:
`registry.redhat.io/quay/quay-operator-rhel9@sha256:d64966c08c644f4843d9ff0281f7c9357802c4769d09389c18b62389ab019692`

Evidence: `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json`,
its text reports, and
`/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/`.

1. **Inventory:** one of 263 ELF files is identified as a Go binary,
   `/workspace/manager`.
2. **Build:** Go
   `1.26.4 (Red Hat 1.26.4-1.el9_8) X:strictfipsruntime`, main module
   unavailable, main package `command-line-arguments`, CGO enabled.
3. **Coverage:** complete 1/1, with no operational scan gap.
4. **Path:** `/workspace/manager` exists in the preserved root.
5. **Findings:** `CVE-2026-33814`, `CVE-2026-33815`, `CVE-2026-33816`,
   `CVE-2026-33818`, `CVE-2026-34986`, `CVE-2026-39821`,
   `CVE-2026-41889`, `CVE-2026-42505`, `CVE-2026-46600`,
   `CVE-2026-56852`, `CVE-2026-56853`, `CVE-2026-56859`,
   `CVE-2026-56860`, and `CVE-2026-56862`, all mapped to the manager.
   Finding-bearing versions are `stdlib@v1.26.4`,
   `github.com/go-jose/go-jose/v4@v4.0.5`,
   `github.com/jackc/pgx/v5@v5.7.4`, `golang.org/x/net@v0.43.0`, and
   `golang.org/x/text@v0.29.0`; exact packages are in its `findings.txt`.
6. **Recurrence/version differences:** there is only one Go binary, so no
   cross-binary version comparison is available.
7. **Replacements:** none are recorded.
8. **Reconciliation:** `github.com/quay/quay-operator@(devel)` is
   unverifiable, and stdlib has an informational `v1.26.4` representation
   difference. Coverage remains complete.
9. **Pattern:** every finding maps to the sole audited Go binary.
19. **Most important observation:** neither requested CVE is detected, but 14
    other findings are present with complete Go-binary coverage.
20. **Unsafe conclusions:** the same reachability, severity, exploitability,
    native-library, layer, and provenance limitations apply; the main module
    version is not verifiable.

## GitOps Operator

Image:
`registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator@sha256:95aa28b8b04efde78d2e4495d2c58e7f8ebd5b399cb2afda927eb01011d2061e`

Evidence:
`persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json`, its text
reports, and
`/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/`.

1. **Inventory:** one of 247 ELF files is identified as a Go binary,
   `/usr/local/bin/manager`.
2. **Build:** Go
   `1.24.6 (Red Hat 1.24.6-1.module+el8.10.0+23407+428597c7) X:strictfipsruntime`,
   main module unavailable, main package `command-line-arguments`, CGO enabled.
3. **Coverage:** complete 1/1, with no operational scan gap.
4. **Path:** `/usr/local/bin/manager` exists in the preserved root.
5. **Findings:** the 70 preferred identifiers are:

   `CVE-2024-7598`, `CVE-2025-13281`, `CVE-2025-1767`, `CVE-2025-4563`,
   `CVE-2025-47912`, `CVE-2025-47913`, `CVE-2025-5187`,
   `CVE-2025-55191`, `CVE-2025-58181`, `CVE-2025-58185`,
   `CVE-2025-58186`, `CVE-2025-58187`, `CVE-2025-58188`,
   `CVE-2025-58189`, `CVE-2025-59531`, `CVE-2025-59537`,
   `CVE-2025-59538`, `CVE-2025-61723`, `CVE-2025-61724`,
   `CVE-2025-61726`, `CVE-2025-61727`, `CVE-2025-61728`,
   `CVE-2025-61729`, `CVE-2025-61730`, `CVE-2025-68121`, `CVE-2026-1229`,
   `CVE-2026-25679`, `CVE-2026-25934`, `CVE-2026-27139`,
   `CVE-2026-27145`, `CVE-2026-32280`, `CVE-2026-32281`,
   `CVE-2026-32283`, `CVE-2026-33762`, `CVE-2026-33811`,
   `CVE-2026-33814`, `CVE-2026-33818`, `CVE-2026-34165`,
   `CVE-2026-35469`, `CVE-2026-39821`, `CVE-2026-39827`,
   `CVE-2026-39828`, `CVE-2026-39829`, `CVE-2026-39830`,
   `CVE-2026-39831`, `CVE-2026-39832`, `CVE-2026-39834`,
   `CVE-2026-39835`, `CVE-2026-39836`, `CVE-2026-41506`,
   `CVE-2026-42504`, `CVE-2026-42505`, `CVE-2026-42507`,
   `CVE-2026-42508`, `CVE-2026-44740`, `CVE-2026-44973`,
   `CVE-2026-45570`, `CVE-2026-45738`, `CVE-2026-46595`,
   `CVE-2026-46597`, `CVE-2026-56852`, `CVE-2026-56853`,
   `CVE-2026-56854`, `CVE-2026-56855`, `CVE-2026-56859`,
   `CVE-2026-56860`, `CVE-2026-56862`, `CVE-2026-71557`,
   `CVE-2026-78662`, and `GHSA-w5pp-99ch-qj29`.

   All map to `/usr/local/bin/manager`. Finding-bearing versions are
   `stdlib@v1.24.6`, `github.com/argoproj/argo-cd/v3@v3.1.5`,
   `github.com/cloudflare/circl@v1.6.1`,
   `github.com/go-git/go-billy/v5@v5.6.2`,
   `github.com/go-git/go-git/v5@v5.16.2`,
   `github.com/moby/spdystream@v0.5.0`, `golang.org/x/crypto@v0.39.0`,
   `golang.org/x/net@v0.41.0`, `golang.org/x/text@v0.26.0`, and
   `k8s.io/kubernetes@v1.33.1`. Exact package mappings are in its
   `findings.txt`.
6. **Recurrence/version differences:** only one Go binary exists; no
   cross-binary comparison is available.
7. **Replacements:** same-path replacements are recorded for
   `gopkg.in/yaml.v2@v2.4.0` and `gopkg.in/yaml.v3@v3.0.1`.
   Kubernetes replacements are: `k8s.io/api v0.33.2 -> v0.33.1`,
   `k8s.io/apiextensions-apiserver v0.33.1 -> v0.33.1`,
   `k8s.io/apimachinery v0.33.2 -> v0.33.1`,
   `k8s.io/apiserver v0.33.2 -> v0.33.1`,
   `k8s.io/cli-runtime v0.33.2 -> v0.33.1`,
   `k8s.io/client-go v12.0.0+incompatible -> v0.33.1`,
   `k8s.io/component-base v0.33.2 -> v0.33.1`,
   `k8s.io/component-helpers v0.33.2 -> v0.33.1`, and same-version
   `v0.33.1` replacements for `k8s.io/controller-manager`,
   `k8s.io/kube-aggregator`, and `k8s.io/kubectl`.
8. **Reconciliation:** `github.com/redhat-developer/gitops-operator@(devel)`
   is unverifiable; stdlib has the informational `v1.24.6` representation
   difference. Coverage remains complete.
9. **Pattern:** every finding maps to the sole audited Go binary.
19. **Most important observation:** both requested CVEs are detected with
    symbol evidence in the manager, on distinct components (`x/crypto/ssh`
    and `crypto/tls`).
20. **Unsafe conclusions:** runtime reachability, severity, exploitability,
    native-library safety, layer completeness, and cryptographic provenance
    remain unsupported; the main module version is unverifiable.

## kube-rbac-proxy

Image:
`registry.redhat.io/openshift4/ose-kube-rbac-proxy@sha256:58698c84109b0833060ab86ef36c0092418c87aba61ba271bef60a18e6b5a6af`

Evidence:
`persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json`, its text
reports, and
`/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/`.

1. **Inventory:** one of 1,032 ELF files is identified as a Go binary,
   `/usr/bin/kube-rbac-proxy`.
2. **Build:** `go1.20.12 X:strictfipsruntime`, main module
   `github.com/brancz/kube-rbac-proxy@(devel)`, main package
   `github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy`, CGO enabled.
3. **Coverage:** complete 1/1, with no operational scan gap.
4. **Path:** `/usr/bin/kube-rbac-proxy` exists in the preserved root.
5. **Findings:** 55 preferred identifiers map to the binary:

   `CVE-2023-45288`, `CVE-2023-45289`, `CVE-2023-45290`,
   `CVE-2024-24783`, `CVE-2024-24785`, `CVE-2024-24790`,
   `CVE-2024-24791`, `CVE-2024-45336`, `CVE-2024-45341`,
   `CVE-2025-22870`, `CVE-2025-22871`, `CVE-2025-4673`,
   `CVE-2025-47906`, `CVE-2025-47912`, `CVE-2025-58185`,
   `CVE-2025-58186`, `CVE-2025-58187`, `CVE-2025-58188`,
   `CVE-2025-58189`, `CVE-2025-61723`, `CVE-2025-61724`,
   `CVE-2025-61726`, `CVE-2025-61727`, `CVE-2025-61729`,
   `CVE-2025-61730`, `CVE-2025-68121`, `CVE-2026-25679`,
   `CVE-2026-27139`, `CVE-2026-27142`, `CVE-2026-27145`,
   `CVE-2026-32280`, `CVE-2026-32281`, `CVE-2026-32283`,
   `CVE-2026-32289`, `CVE-2026-33186`, `CVE-2026-33811`,
   `CVE-2026-33814`, `CVE-2026-33818`, `CVE-2026-39821`,
   `CVE-2026-39823`, `CVE-2026-39825`, `CVE-2026-39826`,
   `CVE-2026-39836`, `CVE-2026-42504`, `CVE-2026-42505`,
   `CVE-2026-42507`, `CVE-2026-56853`, `CVE-2026-56858`,
   `CVE-2026-56859`, `CVE-2026-56860`, `CVE-2026-56862`,
   `CVE-2026-84304`, `CVE-2026-84445`, `GHSA-hrxh-6v49-42gf`, and
   `GHSA-m425-mq94-257g`.

   Finding-bearing versions are `stdlib@v1.20.12`,
   `golang.org/x/net@v0.29.0`, and `google.golang.org/grpc@v1.47.0`.
   Exact packages are in its `findings.txt`.
6. **Recurrence/version differences:** only one Go binary exists; no
   cross-binary comparison is available.
7. **Replacements:** `github.com/emicklei/go-restful/v3@v3.8.0` is replaced
   by the same path at `v3.11.0`; `go.etcd.io/etcd/client/v3@v3.5.4` is
   replaced by the same path at `v3.5.9`.
8. **Reconciliation:** `github.com/brancz/kube-rbac-proxy@(devel)` is
   unverifiable; stdlib has the informational `v1.20.12` representation
   difference. Coverage remains complete.
9. **Pattern:** every finding maps to the sole audited Go binary.
19. **Most important observation:** `CVE-2025-68121` is detected with symbol
    evidence in `crypto/tls`; `CVE-2026-46595` is not detected despite the
    declared presence of `golang.org/x/crypto@v0.27.0`.
20. **Unsafe conclusions:** the finding does not establish runtime
    reachability or exploitability, while the negative result does not prove
    module absence. Native-library, layer, and provenance claims are also
    unsupported; the main module version is unverifiable.

## Claim verdicts for every container (questions 10–18)

The reasons below apply independently to each named image; image-specific
counts and counterexamples cite that image's `audit.json` and rootfs.

| # | Claim | Argo CD | Dex | Quay Operator | GitOps Operator | kube-rbac-proxy |
|---|---|---|---|---|---|---|
| 10 | Every ELF file is a Go binary. | **Rejected:** 476 ELF, 4 Go | **Rejected:** 264 ELF, 1 Go | **Rejected:** 263 ELF, 1 Go | **Rejected:** 247 ELF, 1 Go | **Rejected:** 1,032 ELF, 1 Go |
| 11 | Every Go binary uses the same dependency versions. | **Rejected:** 45 recurring dependency paths have version differences; e.g. `x/crypto` is `v0.53.0`, `v0.36.0`, and `v0.45.0` | **Confirmed only within the observed one-binary set;** no cross-binary comparison exists | **Confirmed only within the observed one-binary set** | **Confirmed only within the observed one-binary set** | **Confirmed only within the observed one-binary set** |
| 12 | Every vulnerability affects every Go binary. | **Rejected:** for example, `CVE-2026-46595` affects only `git-lfs` and `helm` | **Confirmed within the sole Go binary** | **Confirmed within the sole Go binary** | **Confirmed within the sole Go binary** | **Confirmed within the sole Go binary** |
| 13 | A declared module proves every package in it is compiled. | **Rejected:** module declarations and package/symbol findings are separate evidence in the snapshot | **Rejected** | **Rejected** | **Rejected** | **Rejected** |
| 14 | A non-detected vulnerability proves its module/package absent. | **Rejected:** `CVE-2025-68121` is absent while other `crypto/tls` symbol evidence exists | **Rejected:** both targeted findings are absent while `x/crypto` is declared and other `crypto/tls` evidence exists | **Rejected:** both targeted findings are absent while `x/crypto` is declared and other `crypto/tls` evidence exists | **Rejected:** `CVE-2026-46600` is absent while stdlib and `x/net` are present | **Rejected:** `CVE-2026-46595` is absent while `x/crypto@v0.27.0` is declared |
| 15 | Partial reconciliation means scan coverage is incomplete. | **Rejected:** reconciliation partial, coverage complete 4/4 | **Rejected:** partial, complete 1/1 | **Rejected:** partial, complete 1/1 | **Rejected:** partial, complete 1/1 | **Rejected:** partial, complete 1/1 |
| 16 | CGO enabled invalidates Go findings. | **Rejected:** all findings remain recorded with complete coverage; only native-library coverage is out of scope | **Rejected** | **Rejected** | **Rejected** | **Rejected** |
| 17 | Runtime extraction contains every file from every image layer. | **Unverifiable:** no layer archives/history are supplied | **Unverifiable** | **Unverifiable** | **Unverifiable** | **Unverifiable** |
| 18 | Snapshot metadata cryptographically proves rootfs/image identity. | **Unverifiable:** references/digests are recorded, but no full-root hash binding, signature, or attestation is supplied | **Unverifiable** | **Unverifiable** | **Unverifiable** | **Unverifiable** |

## Cross-image limitations and conclusions

- Binary-mode evidence supports detection at module, package, or symbol level
  as recorded, but every finding records reachability as unknown. No runtime
  call path is established.
- The vulnerability database state is historical and fixed to the snapshots;
  negative checks are not current advisory lookups.
- `CGO_ENABLED=true` is recorded for every audited Go binary. The Go results
  remain usable, but native shared objects and C-language dependencies are a
  separate unassessed surface.
- Runtime roots prove that each reported pathname was preserved at review
  time. They do not show deleted lower-layer files or establish layer history.
- Image references, resolved digests, `linux/amd64`, and extractor `oc` are
  recorded, but the authorized evidence contains no independent attestation
  binding every rootfs file to the recorded digest.
- Preferred identifiers may be CVE, GHSA, or GO identifiers. The reports
  preserve aliases in `audit.json`, but this assessment does not infer
  equivalence beyond those snapshot records.

## Questions for other personas

1. **Go Engineer:** Independently assess how local `(devel)` replacements and
   absent main-module metadata constrain component/version conclusions for the
   affected binaries, using the Argo CD, Dex, Quay Operator, and GitOps
   Operator snapshots.
2. **Assurance Lead:** Independently assess what provenance claim is justified
   by the recorded image reference, manifest digest, platform, extractor,
   binary hashes, and preserved root, and whether the supplied evidence creates
   a cryptographic rootfs-to-image binding.
3. **Assurance Lead:** Independently verify that partial reconciliation is
   informational and does not reduce the complete vulnerability-scan coverage
   recorded for all five images.
