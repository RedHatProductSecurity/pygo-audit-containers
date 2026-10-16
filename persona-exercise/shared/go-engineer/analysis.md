# Go Remediation Engineer — Phase-One Analysis

## Scope and evidence notation

This review uses only the supplied snapshots and preserved runtime root filesystems. A
component row below is a compact, complete mapping at the preferred-vulnerability-ID,
module, found-version, and binary-path level. The snapshots retain the finer package and
symbol records. Binary-mode evidence is reported as evidence of code present in the
binary, not proof of runtime execution or exploitability.

Evidence labels expand to these exact paths:

- **A-S** — `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`
- **A-R** — `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/`
- **D-S** — `persona-exercise/snapshots/dex-51454e5c706f/audit.json`
- **D-R** — `/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/`
- **Q-S** — `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json`
- **Q-R** — `/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/`
- **G-S** — `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json`
- **G-R** — `/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/`
- **R-S** — `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json`
- **R-R** — `/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/`

All five snapshots record `linux/amd64`, extraction by `oc`, pygo-audit 0.1.0,
scanner toolchain `go version go1.26.8-X:nodwarf5 linux/amd64`, and the same
`https://vuln.go.dev` database timestamp, `2026-09-16T18:00:43Z`. These are scan
provenance facts, not the embedded compiler versions of the audited binaries.

## Argo CD

Image:
`registry.redhat.io/openshift-gitops-1/argocd-rhel9@sha256:deda478bd4d845e08dd25fb839e1c15d7d4507a397c7184c90b4f78d19410e05`
(resolved manifest
`sha256:a64530771531e94cc35f750738a55e74f59acabb451b65ed29e6b41bd4da5de8`).
Evidence: **A-S**, **A-R**.

### Q1–Q4 — inventory, build metadata, coverage, and preserved files

The snapshot inspected 476 unique ELF files and identified these four as Go binaries:

| Container path | Embedded Go version | Main module | CGO | Scan | Preserved rootfs verification |
|---|---|---|---|---|---|
| `/usr/local/bin/argocd` | `go1.26.5 (Red Hat 1.26.5-1.el9_8) X:strictfipsruntime` | `github.com/argoproj/argo-cd/v3@(devel)` | enabled | complete | exists; SHA-256 `02ad20a8355e8f6910c4daf5c529c5ac4df64a077fb217f336dc3e73cf67b9aa` matches |
| `/usr/local/bin/git-lfs` | same | unavailable (`main_package=command-line-arguments`) | enabled | complete | exists; SHA-256 `7a546ec8fc23eee9e5b893297ff71b5bf479403c230b1375cba8cef786407bb1` matches |
| `/usr/local/bin/helm` | same | `helm.sh/helm/v3@(devel)` | enabled | complete | exists; SHA-256 `cbc5e5a4fb8c5a3ad4fae6466ac6ddd80dbf7a15c28310d48a7755d1658d10b8` matches |
| `/usr/local/bin/kustomize` | same | `sigs.k8s.io/kustomize/kustomize/v5@(devel)` | enabled | complete | exists; SHA-256 `18a3904966c7d799f34190c9354016597eb6e408097fb90e604bb6b323abb067` matches |

All four record `CGO_ENABLED=1`, `GOOS=linux`, `GOARCH=amd64`, and the
`strictfipsruntime` build tag. Vulnerability-scan coverage is complete (4/4), with no
operational scan error. Evidence: binary records and `stats` in **A-S**; matching files
and hashes under **A-R**.

### Q5 — detected vulnerabilities and supporting components

The following component groups cover all 63 preferred identifiers in the snapshot.
Evidence types are shown because module evidence is weaker than package/symbol evidence.

| Binary | Module and current version | Evidence | Preferred identifiers |
|---|---|---|---|
| `/usr/local/bin/argocd` | `github.com/go-git/go-billy/v5@v5.6.2` | package, symbol | CVE-2026-44740, CVE-2026-44973 |
| same | `github.com/go-git/go-git/v5@v5.14.0` | symbol | CVE-2026-25934, CVE-2026-33762, CVE-2026-34165, CVE-2026-41506, CVE-2026-45022, CVE-2026-45570, CVE-2026-45571, CVE-2026-71556, CVE-2026-71557, GHSA-w5pp-99ch-qj29 |
| same | `golang.org/x/crypto@v0.53.0` | symbol | CVE-2026-56854, CVE-2026-56855, CVE-2026-78662 |
| same | `golang.org/x/text@v0.38.0` | symbol | CVE-2026-56852 |
| same | `google.golang.org/grpc@v1.79.3` | symbol | CVE-2026-84304, CVE-2026-84445, GHSA-hrxh-6v49-42gf |
| same | `k8s.io/kubernetes@v1.34.2` | symbol | CVE-2024-7598, CVE-2025-1767 |
| same | `oras.land/oras-go/v2@v2.6.0` | symbol | CVE-2026-48978, CVE-2026-50151, CVE-2026-50162, CVE-2026-50163, GHSA-vh4v-2xq2-g5cg |
| same | `stdlib@v1.26.5` | symbol | CVE-2026-33818, CVE-2026-39821, CVE-2026-46600, CVE-2026-56853, CVE-2026-56858, CVE-2026-56859, CVE-2026-56860, CVE-2026-56862 |
| `/usr/local/bin/git-lfs` | `golang.org/x/crypto@v0.36.0` | symbol | CVE-2025-47913, CVE-2025-47914, CVE-2025-58181, CVE-2026-39827, CVE-2026-39828, CVE-2026-39829, CVE-2026-39830, CVE-2026-39831, CVE-2026-39832, CVE-2026-39833, CVE-2026-39834, CVE-2026-39835, CVE-2026-42508, CVE-2026-46595, CVE-2026-46597, CVE-2026-46598, CVE-2026-56854, CVE-2026-56855, CVE-2026-78662, GO-2026-5932 |
| same | `golang.org/x/net@v0.38.0` | symbol | CVE-2025-47911, CVE-2025-58190, CVE-2026-25680, CVE-2026-25681, CVE-2026-27136, CVE-2026-33814, CVE-2026-39821, CVE-2026-42502, CVE-2026-42506, CVE-2026-46600 |
| same | `golang.org/x/text@v0.23.0` | symbol | CVE-2026-56852 |
| same | `stdlib@v1.26.5` | symbol | the same eight stdlib identifiers shown for `argocd` |
| `/usr/local/bin/helm` | `github.com/klauspost/compress@v1.18.0` | symbol | GHSA-259r-337f-4rfw |
| same | `github.com/moby/spdystream@v0.5.0` | symbol | CVE-2026-35469 |
| same | `golang.org/x/crypto@v0.45.0` | symbol | CVE-2026-39827, CVE-2026-39828, CVE-2026-39829, CVE-2026-39830, CVE-2026-39831, CVE-2026-39832, CVE-2026-39833, CVE-2026-39834, CVE-2026-39835, CVE-2026-42508, CVE-2026-46595, CVE-2026-46597, CVE-2026-46598, CVE-2026-56854, CVE-2026-56855, CVE-2026-78662, GO-2026-5932 |
| same | `golang.org/x/net@v0.47.0` | symbol | CVE-2026-25680, CVE-2026-25681, CVE-2026-27136, CVE-2026-33814, CVE-2026-39821, CVE-2026-42502, CVE-2026-42506, CVE-2026-46600 |
| same | `golang.org/x/text@v0.31.0` | symbol | CVE-2026-56852 |
| same | `google.golang.org/grpc@v1.72.1` | symbol | CVE-2026-33186, CVE-2026-84303, CVE-2026-84304, CVE-2026-84445, GHSA-hrxh-6v49-42gf |
| same | `oras.land/oras-go/v2@v2.6.0` | symbol | CVE-2026-48978, CVE-2026-50151, CVE-2026-50162, CVE-2026-50163, GHSA-vh4v-2xq2-g5cg |
| same | `stdlib@v1.26.5` | symbol | the same eight stdlib identifiers shown for `argocd` |
| `/usr/local/bin/kustomize` | `golang.org/x/text@v0.28.0` | symbol | CVE-2026-56852 |
| same | `stdlib@v1.26.5` | symbol | the same eight stdlib identifiers shown for `argocd` |

Evidence: vulnerability and finding records in **A-S**.

### Q6–Q9 — recurrence, replacements, reconciliation, and patterns

**Q6.** All binaries share the same standard library release representation
(`v1.26.5` in findings; decorated Go `go1.26.5 ... X:strictfipsruntime` in build
metadata). Ninety-one declared module paths recur across at least two binaries: 46 use
one shared version and 45 differ. The differing paths are:

`dario.cat/mergo`, `github.com/chai2010/gettext-go`, `github.com/davecgh/go-spew`,
`github.com/go-errors/errors`, `github.com/go-logr/logr`,
`github.com/go-openapi/jsonpointer`, `github.com/go-openapi/jsonreference`,
`github.com/go-openapi/swag`, `github.com/google/gnostic-models`,
`github.com/google/uuid`, `github.com/mailru/easyjson`, `github.com/mattn/go-isatty`,
`github.com/moby/spdystream`, `github.com/pkg/errors`, `github.com/sergi/go-diff`,
`github.com/sirupsen/logrus`, `github.com/spf13/cast`, `github.com/spf13/cobra`,
`github.com/spf13/pflag`, `go.yaml.in/yaml/v3`, `golang.org/x/crypto`,
`golang.org/x/net`, `golang.org/x/oauth2`, `golang.org/x/sync`, `golang.org/x/sys`,
`golang.org/x/term`, `golang.org/x/text`, `golang.org/x/time`,
`google.golang.org/genproto/googleapis/rpc`, `google.golang.org/grpc`,
`google.golang.org/protobuf`, `gopkg.in/evanphx/json-patch.v4`, `k8s.io/api`,
`k8s.io/apiextensions-apiserver`, `k8s.io/apimachinery`, `k8s.io/apiserver`,
`k8s.io/cli-runtime`, `k8s.io/client-go`, `k8s.io/component-base`,
`k8s.io/kube-openapi`, `k8s.io/kubectl`, `sigs.k8s.io/kustomize/api`,
`sigs.k8s.io/kustomize/kyaml`, `sigs.k8s.io/structured-merge-diff/v6`, and
`sigs.k8s.io/yaml`.

The vulnerability-bearing differences are especially remediation-relevant:
`x/crypto` is v0.53.0/v0.36.0/v0.45.0 in argocd/git-lfs/helm; `x/net` is
v0.56.0/v0.38.0/v0.47.0; `x/text` is v0.38.0/v0.23.0/v0.31.0/v0.28.0 across
argocd/git-lfs/helm/kustomize; gRPC is v1.79.3 in argocd and v1.72.1 in helm; and
`moby/spdystream` is v0.5.1 in argocd versus vulnerable evidence at v0.5.0 in helm.
Evidence: dependency arrays in **A-S**.

**Q7.** Only `/usr/local/bin/argocd` records dependency replacement directives. The
complete declared → effective list is:

- `github.com/argoproj/argo-cd/gitops-engine@v0.7.1-0.20250908182407-97ad5b59a627` → `./gitops-engine@(devel)`.
- Same-path/same-version effective replacements: `github.com/golang/protobuf@v1.5.4`, `github.com/grpc-ecosystem/grpc-gateway@v1.16.0`, `gopkg.in/yaml.v2@v2.4.0`, `gopkg.in/yaml.v3@v3.0.1`, `k8s.io/api@v0.34.0`, `k8s.io/apiextensions-apiserver@v0.34.0`, `k8s.io/apimachinery@v0.34.0`, `k8s.io/apiserver@v0.34.0`, `k8s.io/cli-runtime@v0.34.0`, `k8s.io/client-go@v0.34.0`, `k8s.io/component-base@v0.34.0`, `k8s.io/component-helpers@v0.34.0`, `k8s.io/controller-manager@v0.34.0`, `k8s.io/kube-aggregator@v0.34.0`, and `k8s.io/kubectl@v0.34.0`.

The other three binaries record no dependency replacement. Evidence: **A-S**.

**Q8.** Reconciliation is partial for all four binaries, but vulnerability coverage is
still complete. Unverifiable component records are:

- argocd: local `./gitops-engine@(devel)` and main `github.com/argoproj/argo-cd/v3@(devel)`;
- git-lfs: `github.com/git-lfs/git-lfs/v3@(devel)`;
- helm: main `helm.sh/helm/v3@(devel)`;
- kustomize: `sigs.k8s.io/kustomize/api@(devel)`, `sigs.k8s.io/kustomize/cmd/config@(devel)`, main `sigs.k8s.io/kustomize/kustomize/v5@(devel)`, and `sigs.k8s.io/kustomize/kyaml@(devel)`.

Finding reconciliation also records 39/54/54/54 repeated representation-difference
records respectively: `stdlib@v1.26.5` versus the decorated embedded Go 1.26.5 string.
This identifies the same release in different notation. Evidence: reconciliation and
scan-status fields in **A-S**.

**Q9.** Container-wide findings affecting all four binaries are CVE-2026-33818,
CVE-2026-39821, CVE-2026-46600, CVE-2026-56852, CVE-2026-56853, CVE-2026-56858,
CVE-2026-56859, CVE-2026-56860, and CVE-2026-56862. Three-binary patterns
(argocd/git-lfs/helm) are CVE-2026-56854, CVE-2026-56855, and CVE-2026-78662.
Many `x/crypto` and `x/net` findings affect only git-lfs plus helm; ORAS and several gRPC
findings affect argocd plus helm. Findings tied to go-git/Kubernetes are isolated to
argocd; CVE-2026-35469, CVE-2026-33186, CVE-2026-84303, and
GHSA-259r-337f-4rfw are isolated to helm; five early x/net/x/crypto findings are isolated
to git-lfs; none is isolated only to kustomize. Exact support is in the Q5 matrix and
**A-S**.

### Q10–Q18 — claim verdicts

| Q | Verdict | Evidence-backed reason |
|---|---|---|
| 10 | rejected | 476 ELF files were seen, but only four are identified Go binaries (**A-S**). |
| 11 | rejected | Recurring modules use materially different versions, including `x/crypto`, `x/net`, `x/text`, and gRPC (**A-S**). |
| 12 | rejected | Only nine of 63 preferred vulnerabilities affect all four binaries; many are isolated (**A-S**). |
| 13 | rejected | Declared module records contain no proof that every package in a module was compiled; package/symbol evidence is separately recorded (**A-S**). |
| 14 | rejected | `/usr/local/bin/argocd` declares `golang.org/x/net@v0.56.0` but has no CVE-2026-33814 finding; the finding occurs in older x/net versions in git-lfs and helm (**A-S**). |
| 15 | rejected | Reconciliation is partial for all four while vulnerability-scan coverage is complete 4/4 (**A-S**). |
| 16 | rejected | All four are CGO-enabled and retain complete Go findings; CGO creates an additional native-code coverage limitation, not invalidation (**A-S**). |
| 17 | unverifiable | **A-R** is identified as a runtime rootfs, but no image-layer archives or layer file histories are supplied. |
| 18 | rejected | Metadata names an image and digest, and the four binary hashes match **A-R**, but no signature or cryptographic binding of the entire rootfs to the manifest is supplied; **A-R** has no `.pygo-audit-image.json`. |

### Q19–Q20 — conclusions and limits

**Q19.** Remediation cannot be container-wide by dependency version: the four binaries
share the compiler/stdlib but embed different module versions. Standard-library findings
require rebuilding all four with an appropriate corrected toolchain; module findings
must be handled per binary/version. The local gitops-engine replacement and `(devel)`
components require source/build provenance to select a verifiable revision. CGO means a
separate native dependency review remains necessary. Evidence: **A-S**, **A-R**.

**Q20.** The evidence cannot establish runtime exploitability, invocation of a vulnerable
symbol, native-library safety, historical layer contents, an immutable revision for
`(devel)` components, vendor-backport status, or cryptographic image-to-rootfs
provenance. It also cannot declare a remediated build without a new snapshot.

## Dex

Image:
`registry.redhat.io/openshift-gitops-1/dex-rhel9@sha256:51454e5c706fd913503980d29a11ab233e3d0b82d319b23d46394612dd81d3ff`
(resolved manifest
`sha256:4f114a65d6d588722821ddc5bf0510829574c2428400d84260558a1b703969d4`).
Evidence: **D-S**, **D-R**.

### Q1–Q4

Of 264 unique ELF files, one is identified as Go: `/usr/local/bin/dex`. It records
`go1.26.5 (Red Hat 1.26.5-1.el9_8) X:strictfipsruntime`, main module
`github.com/dexidp/dex@(devel)`, `CGO_ENABLED=1`, Linux/amd64, and the
`strictfipsruntime` tag. Its vulnerability scan is complete (1/1), with no operational
coverage issue. The file exists in **D-R** and hashes to
`bb4c13d7c0479f799b7fef0642f0fc7c008fd2f971c12a99e0249fee1f2fccb8`, matching
**D-S**.

### Q5

All 12 preferred identifiers are covered by these support groups in **D-S**:

| Binary | Module and current version | Evidence | Preferred identifiers |
|---|---|---|---|
| `/usr/local/bin/dex` | `golang.org/x/net@v0.55.0` | module | CVE-2026-46600 |
| same | `golang.org/x/text@v0.37.0` | symbol | CVE-2026-56852 |
| same | `google.golang.org/grpc@v1.79.3` | symbol | CVE-2026-84304, CVE-2026-84445, GHSA-hrxh-6v49-42gf |
| same | `stdlib@v1.26.5` | symbol | CVE-2026-33818, CVE-2026-39821, CVE-2026-46600, CVE-2026-56853, CVE-2026-56858, CVE-2026-56859, CVE-2026-56860, CVE-2026-56862 |

The module-only x/net record does not prove package or symbol reachability.

### Q6–Q9

**Q6.** There is only one identified Go binary, so no within-container cross-binary
version comparison is possible. The stdlib finding version is v1.26.5 and the decorated
embedded compiler string is the same release. **Q7.** One effective replacement exists:
`github.com/dexidp/dex/api/v2@v2.4.0` → `./api/v2@(devel)`.

**Q8.** Reconciliation is partial because local `./api/v2@(devel)` and main
`github.com/dexidp/dex@(devel)` are unverifiable. Thirty-seven finding records express
the stdlib v1.26.5/decorated-Go-1.26.5 notation difference. Coverage nevertheless
remains complete 1/1. **Q9.** With one Go binary, all detected findings are both isolated
to `/usr/local/bin/dex` and container-wide across the identified Go inventory. Evidence:
**D-S**.

### Q10–Q18

| Q | Verdict | Evidence-backed reason |
|---|---|---|
| 10 | rejected | 264 ELF files versus one identified Go binary (**D-S**). |
| 11 | confirmed, trivially | Only one Go binary exists, so no conflicting cross-binary version is observed (**D-S**). |
| 12 | confirmed for detected findings | Every detected vulnerability has support in the sole Go binary (**D-S**). |
| 13 | rejected | Module declarations and package/symbol findings are distinct evidence records (**D-S**). |
| 14 | rejected | x/net v0.55.0 is declared, while CVE-2026-33814 is not detected in this snapshot (**D-S**). |
| 15 | rejected | Reconciliation is partial, but scan coverage is complete 1/1 (**D-S**). |
| 16 | rejected | CGO is enabled without invalidating complete Go findings; native code remains out of scope (**D-S**). |
| 17 | unverifiable | No image-layer histories accompany runtime rootfs **D-R**. |
| 18 | rejected | The matching dex file hash binds that file to the snapshot, not the whole rootfs to the stated image manifest; no rootfs sidecar/signature exists (**D-S**, **D-R**). |

### Q19–Q20

**Q19.** Remediation separates the Go 1.26.5 stdlib, x/text, gRPC, and a weaker
module-only x/net indication. The local API replacement cannot be mapped to an immutable
revision. CGO requires separate native review. **Q20.** Runtime exploitability,
vendor-backport status, the exact source revision of `(devel)` code, native dependency
safety, full layer history, and image/rootfs cryptographic provenance are not established.

## Quay Operator

Image:
`registry.redhat.io/quay/quay-operator-rhel9@sha256:d64966c08c644f4843d9ff0281f7c9357802c4769d09389c18b62389ab019692`
(resolved manifest
`sha256:b17a240fd3c7032b9f098c9a3369a52ee4afaa23aa97a35936bf3fd44243681c`).
Evidence: **Q-S**, **Q-R**.

### Q1–Q4

Of 263 unique ELF files, one is identified as Go: `/workspace/manager`. It records
`go1.26.4 (Red Hat 1.26.4-1.el9_8) X:strictfipsruntime`, `CGO_ENABLED=1`, and
Linux/amd64. The main module is unavailable (`main_package=command-line-arguments`), and
no `-tags` value is recorded even though the Go-version string contains
`X:strictfipsruntime`. The vulnerability scan is complete 1/1. The file exists in
**Q-R** and hashes to
`03959d49eafd2c07dd5add7dc793a81fa7959c9a0b64646d6979733c1e45576b`, matching
**Q-S**.

### Q5

All 14 preferred identifiers are covered by these groups in **Q-S**:

| Binary | Module and current version | Evidence | Preferred identifiers |
|---|---|---|---|
| `/workspace/manager` | `github.com/go-jose/go-jose/v4@v4.0.5` | symbol | CVE-2026-34986 |
| same | `github.com/jackc/pgx/v5@v5.7.4` | symbol | CVE-2026-33815, CVE-2026-33816, CVE-2026-41889 |
| same | `golang.org/x/net@v0.43.0` | module, symbol | CVE-2026-33814, CVE-2026-39821, CVE-2026-46600 |
| same | `golang.org/x/text@v0.29.0` | symbol | CVE-2026-56852 |
| same | `stdlib@v1.26.4` | symbol | CVE-2026-33818, CVE-2026-39821, CVE-2026-42505, CVE-2026-46600, CVE-2026-56853, CVE-2026-56859, CVE-2026-56860, CVE-2026-56862 |

### Q6–Q9

**Q6.** Only one Go binary is identified, so there is no cross-binary recurrence or
version conflict. The stdlib records represent the same Go 1.26.4 release in two forms.
**Q7.** No declared dependency replacement is recorded. **Q8.** Reconciliation is
partial solely because `github.com/quay/quay-operator@(devel)` is unverifiable; 44
finding records contain the stdlib representation difference. Vulnerability coverage is
still complete 1/1. **Q9.** All findings are isolated to the sole Go binary and are
therefore container-wide over the identified Go inventory. Evidence: **Q-S**.

### Q10–Q18

| Q | Verdict | Evidence-backed reason |
|---|---|---|
| 10 | rejected | 263 ELF files versus one identified Go binary (**Q-S**). |
| 11 | confirmed, trivially | Only one identified Go binary exists (**Q-S**). |
| 12 | confirmed for detected findings | Every detected finding supports `/workspace/manager`, the sole Go binary (**Q-S**). |
| 13 | rejected | A module record alone is separate from package and symbol evidence (**Q-S**). |
| 14 | rejected | `golang.org/x/crypto@v0.41.0` is declared while CVE-2026-46595 is not detected (**Q-S**). |
| 15 | rejected | Partial reconciliation coexists with complete 1/1 scan coverage (**Q-S**). |
| 16 | rejected | CGO does not invalidate the complete Go findings; it leaves native code outside this audit (**Q-S**). |
| 17 | unverifiable | No layer archives or historical layer file inventories accompany **Q-R**. |
| 18 | rejected | The matching manager hash does not cryptographically bind all of **Q-R** to the manifest, and no rootfs sidecar/signature is present (**Q-S**, **Q-R**). |

### Q19–Q20

**Q19.** The manager needs component-specific remediation for stdlib, x/net, x/text,
go-jose, and pgx evidence. Its missing main-module record and unverifiable devel module
weaken source-to-binary traceability. **Q20.** The snapshot does not establish source
revision, runtime reachability, vendor backports, native-library status, historical
layers, or cryptographic rootfs provenance.

## GitOps Operator

Image:
`registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator@sha256:95aa28b8b04efde78d2e4495d2c58e7f8ebd5b399cb2afda927eb01011d2061e`
(resolved manifest
`sha256:7f6e588459ff59366a9f8f8f32a784806af11931f8584e46e1d53472a2e010a9`).
Evidence: **G-S**, **G-R**.

### Q1–Q4

Of 247 unique ELF files, one is identified as Go: `/usr/local/bin/manager`. It records
`go1.24.6 (Red Hat 1.24.6-1.module+el8.10.0+23407+428597c7) X:strictfipsruntime`,
`CGO_ENABLED=1`, Linux/amd64, and the `strictfipsruntime` tag. Its main module is
unavailable (`main_package=command-line-arguments`). The scan is complete 1/1. The file
exists in **G-R** and its SHA-256
`34578cdf615bba1b8e70f88db76cf241eb8ae253cb5bce93d1c912fd10240bf4` matches
**G-S**.

### Q5

All 70 preferred identifiers are covered by these component groups in **G-S**:

| Binary | Module and current version | Evidence | Preferred identifiers |
|---|---|---|---|
| `/usr/local/bin/manager` | `github.com/argoproj/argo-cd/v3@v3.1.5` | symbol | CVE-2025-55191, CVE-2025-59531, CVE-2025-59537, CVE-2025-59538, CVE-2026-45738 |
| same | `github.com/cloudflare/circl@v1.6.1` | symbol | CVE-2026-1229 |
| same | `github.com/go-git/go-billy/v5@v5.6.2` | symbol | CVE-2026-44740, CVE-2026-44973 |
| same | `github.com/go-git/go-git/v5@v5.16.2` | symbol | CVE-2026-25934, CVE-2026-33762, CVE-2026-34165, CVE-2026-41506, CVE-2026-45570, CVE-2026-71557, GHSA-w5pp-99ch-qj29 |
| same | `github.com/moby/spdystream@v0.5.0` | package, symbol | CVE-2026-35469 |
| same | `golang.org/x/crypto@v0.39.0` | symbol | CVE-2025-47913, CVE-2025-58181, CVE-2026-39827, CVE-2026-39828, CVE-2026-39829, CVE-2026-39830, CVE-2026-39831, CVE-2026-39832, CVE-2026-39834, CVE-2026-39835, CVE-2026-42508, CVE-2026-46595, CVE-2026-46597, CVE-2026-56854, CVE-2026-56855, CVE-2026-78662 |
| same | `golang.org/x/net@v0.41.0` | symbol | CVE-2026-33814, CVE-2026-39821 |
| same | `golang.org/x/text@v0.26.0` | symbol | CVE-2026-56852 |
| same | `k8s.io/kubernetes@v1.33.1` | symbol | CVE-2024-7598, CVE-2025-13281, CVE-2025-1767, CVE-2025-4563, CVE-2025-5187 |
| same | `stdlib@v1.24.6` | symbol | CVE-2025-47912, CVE-2025-58185, CVE-2025-58186, CVE-2025-58187, CVE-2025-58188, CVE-2025-58189, CVE-2025-61723, CVE-2025-61724, CVE-2025-61726, CVE-2025-61727, CVE-2025-61728, CVE-2025-61729, CVE-2025-61730, CVE-2025-68121, CVE-2026-25679, CVE-2026-27139, CVE-2026-27145, CVE-2026-32280, CVE-2026-32281, CVE-2026-32283, CVE-2026-33811, CVE-2026-33814, CVE-2026-33818, CVE-2026-39821, CVE-2026-39836, CVE-2026-42504, CVE-2026-42505, CVE-2026-42507, CVE-2026-56853, CVE-2026-56859, CVE-2026-56860, CVE-2026-56862 |

### Q6–Q9

**Q6.** With one Go binary, there is no cross-binary dependency comparison. The stdlib
finding and decorated build strings both identify Go 1.24.6. **Q7.** All recorded
declared → effective replacements are:

- same path/version: `gopkg.in/yaml.v2@v2.4.0`, `gopkg.in/yaml.v3@v3.0.1`, `k8s.io/apiextensions-apiserver@v0.33.1`, `k8s.io/controller-manager@v0.33.1`, `k8s.io/kube-aggregator@v0.33.1`, and `k8s.io/kubectl@v0.33.1`;
- `k8s.io/api@v0.33.2` → `k8s.io/api@v0.33.1`;
- `k8s.io/apimachinery@v0.33.2` → `k8s.io/apimachinery@v0.33.1`;
- `k8s.io/apiserver@v0.33.2` → `k8s.io/apiserver@v0.33.1`;
- `k8s.io/cli-runtime@v0.33.2` → `k8s.io/cli-runtime@v0.33.1`;
- `k8s.io/client-go@v12.0.0+incompatible` → `k8s.io/client-go@v0.33.1`;
- `k8s.io/component-base@v0.33.2` → `k8s.io/component-base@v0.33.1`;
- `k8s.io/component-helpers@v0.33.2` → `k8s.io/component-helpers@v0.33.1`.

**Q8.** Reconciliation is partial because
`github.com/redhat-developer/gitops-operator@(devel)` is unverifiable. There are 154
repeated stdlib representation-difference records. This does not reduce complete 1/1
vulnerability coverage. **Q9.** Every finding is isolated to the sole Go binary and is
therefore container-wide over the identified inventory. Evidence: **G-S**.

### Q10–Q18

| Q | Verdict | Evidence-backed reason |
|---|---|---|
| 10 | rejected | 247 ELF files versus one identified Go binary (**G-S**). |
| 11 | confirmed, trivially | Only one identified Go binary exists (**G-S**). |
| 12 | confirmed for detected findings | All detected findings support the sole manager binary (**G-S**). |
| 13 | rejected | Module declarations do not themselves enumerate compiled packages; findings carry separate package/symbol evidence (**G-S**). |
| 14 | rejected | `google.golang.org/grpc@v1.73.0` is declared while CVE-2026-84304 is not detected (**G-S**). |
| 15 | rejected | Partial reconciliation coexists with complete 1/1 scan coverage (**G-S**). |
| 16 | rejected | CGO leaves native code out of scope but does not invalidate complete Go findings (**G-S**). |
| 17 | unverifiable | No historical image-layer evidence accompanies **G-R**. |
| 18 | rejected | The matching manager hash binds one file to the snapshot, not the whole rootfs to the image manifest; no rootfs sidecar/signature is present (**G-S**, **G-R**). |

### Q19–Q20

**Q19.** Remediation must use effective Kubernetes v0.33.1 components, not several
higher or incompatible declared versions. The stdlib v1.24.6 finding set is large, and
the binary also contains evidence across Argo CD, x/crypto, x/net, x/text, go-git,
Kubernetes, CIRCL, and spdystream. **Q20.** The evidence does not establish runtime
reachability, upstream-versus-vendor fix equivalence, native dependency safety, an
immutable main-module source revision, historical layers, or cryptographic rootfs
provenance.

## kube-rbac-proxy

Image:
`registry.redhat.io/openshift4/ose-kube-rbac-proxy@sha256:58698c84109b0833060ab86ef36c0092418c87aba61ba271bef60a18e6b5a6af`
(resolved manifest
`sha256:a083d6d53630f47a8503a45b639ae5c567d1f724096d1f729082bfdb9d760585`).
Evidence: **R-S**, **R-R**.

### Q1–Q4

Of 1,032 unique ELF files, one is identified as Go: `/usr/bin/kube-rbac-proxy`. It
records `go1.20.12 X:strictfipsruntime`, main module
`github.com/brancz/kube-rbac-proxy@(devel)`, `CGO_ENABLED=1`, Linux/amd64, and the
`strictfipsruntime` tag. The vulnerability scan is complete 1/1. The preserved file
exists in **R-R** and hashes to
`1448e55b04d3a40a37d9a0e62014c2cb0f341d9af7ba6ff4a1950bc86ed19113`, matching
**R-S**.

### Q5

All 55 preferred identifiers are covered by these groups in **R-S**:

| Binary | Module and current version | Evidence | Preferred identifiers |
|---|---|---|---|
| `/usr/bin/kube-rbac-proxy` | `golang.org/x/net@v0.29.0` | module, symbol | CVE-2025-22870, CVE-2026-33814, CVE-2026-39821 |
| same | `google.golang.org/grpc@v1.47.0` | symbol | CVE-2026-33186, CVE-2026-84304, CVE-2026-84445, GHSA-hrxh-6v49-42gf, GHSA-m425-mq94-257g |
| same | `stdlib@v1.20.12` | symbol | CVE-2023-45288, CVE-2023-45289, CVE-2023-45290, CVE-2024-24783, CVE-2024-24785, CVE-2024-24790, CVE-2024-24791, CVE-2024-45336, CVE-2024-45341, CVE-2025-22870, CVE-2025-22871, CVE-2025-4673, CVE-2025-47906, CVE-2025-47912, CVE-2025-58185, CVE-2025-58186, CVE-2025-58187, CVE-2025-58188, CVE-2025-58189, CVE-2025-61723, CVE-2025-61724, CVE-2025-61726, CVE-2025-61727, CVE-2025-61729, CVE-2025-61730, CVE-2025-68121, CVE-2026-25679, CVE-2026-27139, CVE-2026-27142, CVE-2026-27145, CVE-2026-32280, CVE-2026-32281, CVE-2026-32283, CVE-2026-32289, CVE-2026-33186, CVE-2026-33811, CVE-2026-33814, CVE-2026-33818, CVE-2026-39821, CVE-2026-39823, CVE-2026-39825, CVE-2026-39826, CVE-2026-39836, CVE-2026-42504, CVE-2026-42505, CVE-2026-42507, CVE-2026-56853, CVE-2026-56858, CVE-2026-56859, CVE-2026-56860, CVE-2026-56862 |

### Q6–Q9

**Q6.** Only one Go binary is identified, so no cross-binary version comparison exists.
The stdlib records both identify Go 1.20.12. **Q7.** Two effective replacements exist:
`github.com/emicklei/go-restful/v3@v3.8.0` → same module at v3.11.0, and
`go.etcd.io/etcd/client/v3@v3.5.4` → same module at v3.5.9.

**Q8.** Reconciliation is partial because main
`github.com/brancz/kube-rbac-proxy@(devel)` is unverifiable. There are 377 repeated
stdlib representation-difference records. Vulnerability coverage remains complete 1/1.
**Q9.** All findings support the sole binary and are both isolated to it and
container-wide over the identified Go inventory. Evidence: **R-S**.

### Q10–Q18

| Q | Verdict | Evidence-backed reason |
|---|---|---|
| 10 | rejected | 1,032 ELF files versus one identified Go binary (**R-S**). |
| 11 | confirmed, trivially | Only one identified Go binary exists (**R-S**). |
| 12 | confirmed for detected findings | All detected findings support the sole Go binary (**R-S**). |
| 13 | rejected | Module records are not proof that every package was linked; package and symbol evidence is separate (**R-S**). |
| 14 | rejected | `golang.org/x/text@v0.18.0` is declared while CVE-2026-56852 is not detected (**R-S**). |
| 15 | rejected | Reconciliation is partial while vulnerability coverage is complete 1/1 (**R-S**). |
| 16 | rejected | CGO does not invalidate the Go evidence; it exposes an additional native-code blind spot (**R-S**). |
| 17 | unverifiable | Runtime rootfs **R-R** has no accompanying historical layer data. |
| 18 | rejected | The matching binary hash is not a cryptographic proof for the entire rootfs/image relationship, and no rootfs sidecar/signature exists (**R-S**, **R-R**). |

### Q19–Q20

**Q19.** This is the oldest embedded toolchain in the dataset (Go 1.20.12) and has a
large stdlib finding set plus x/net and gRPC evidence. Remediation must honor the two
effective version upgrades rather than declared versions. CGO leaves native code for a
separate audit. **Q20.** Runtime exploitability, vendor-backport status, main-module
revision, native-library safety, layer history, and cryptographic rootfs provenance
remain unverified.

## Cross-image remediation observations

- Complete vulnerability coverage and partial reconciliation are not contradictory:
  all eight identified Go binaries completed govulncheck, while `(devel)` and local
  components prevent full version reconciliation.
- Every binary has `CGO_ENABLED=1`. The Go findings remain usable, but none of these
  snapshots covers native libraries.
- The scanner toolchain (Go 1.26.8) differs from embedded build toolchains (Go 1.26.5,
  1.26.4, 1.24.6, and 1.20.12). Remediation must use the embedded-version evidence, not
  confuse it with scanner provenance.
- Effective replacement versions are authoritative for remediation. This is especially
  important for GitOps Operator's Kubernetes replacements and for local `(devel)`
  replacements in Argo CD and Dex.
- Matching per-binary hashes connect preserved files to snapshot records. They do not
  prove that each complete rootfs was produced from the stated OCI manifest.

## Limitations

The authorized evidence contains no source trees, build pipelines, external advisories,
vendor backport statements, runtime traces, native dependency inventory, layer archives,
or signed rootfs attestation. Consequently, this review cannot prescribe an externally
validated fixed version, prove reachability/exploitability, verify native-code safety,
recover immutable revisions for `(devel)` components, or certify image provenance.

## Questions for other personas

1. **Security Analyst:** How should module-only findings versus package/symbol findings
   be prioritized when all snapshot reachability states remain unknown, particularly
   Dex's x/net CVE-2026-46600 and kube-rbac-proxy's mixed x/net evidence?
2. **Security Analyst:** Do the cross-image age and breadth patterns justify prioritizing
   kube-rbac-proxy's Go 1.20.12 rebuild and GitOps Operator's Go 1.24.6 rebuild ahead of
   the Go 1.26.x images, without importing external severity or exploitability data?
3. **Assurance Lead:** What additional signed extraction or manifest/layer evidence is
   required before the recorded image reference/digest and matching binary hashes can be
   treated as adequate rootfs provenance?
4. **Assurance Lead:** What closure evidence should be required after remediation for
   local or `(devel)` components whose versions are currently unverifiable?
