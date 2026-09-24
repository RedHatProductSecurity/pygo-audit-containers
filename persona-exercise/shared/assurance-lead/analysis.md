# Platform assurance lead: phase-one analysis

## Evidence-readiness summary

All conclusions below use only `persona-exercise/snapshots/` and the preserved
root filesystems under `/tmp/pygo-audit-persona-rootfs/`. The five snapshots
are schema 6. Each bundle `audit.json` is byte-identical to its corresponding
file in `persona-exercise/snapshots/store/`, and recomputing the canonical JSON
SHA-256 produced the store filename shown below:

| Image | Content-addressed snapshot | Vulnerability coverage | Reconciliation |
|---|---|---:|---|
| Argo CD | `persona-exercise/snapshots/store/3c8370f7cbec63890b77c2a8d702dbaf83e4c6ae1e4a3b89e9b386bc52dab949.json` | complete, 4/4 | partial, 4/4; 8 unverifiable components |
| Dex | `persona-exercise/snapshots/store/f26c0e7685601832563b0c2c2a055b0d41a98a4b9ce866ff363a495e1e1e5292.json` | complete, 1/1 | partial, 1/1; 2 unverifiable components |
| Quay Operator | `persona-exercise/snapshots/store/ebad81c263e3474e46264bc99dfb89cbadd0cc68cd394beebec1897a8f0b78e8.json` | complete, 1/1 | partial, 1/1; 1 unverifiable component |
| GitOps Operator | `persona-exercise/snapshots/store/29314403694c6ec4e24eff6ce0c8187040e1113356bd1135f8caa010296b17dd.json` | complete, 1/1 | partial, 1/1; 1 unverifiable component |
| kube-rbac-proxy | `persona-exercise/snapshots/store/e88d0a2c84e6544ab2bf302468c43fffd24b52b6e71419a1e4bf1f7a3c8e10e5.json` | complete, 1/1 | partial, 1/1; 1 unverifiable component |

All five snapshots record `pygo-audit 0.1.0`, host toolchain `go version
go1.26.8-X:nodwarf5 linux/amd64`, `govulncheck@v0.0.0`, database
`https://vuln.go.dev` updated `2026-09-16T18:00:43Z`, platform
`linux/amd64`, and extractor `oc`. The database timestamp and scanner string
are provenance observations, not database-content or scanner-binary digests.
Each image reference and resolved manifest is present, but the evidence has no
cryptographic commitment over the complete rootfs. The snapshot does commit to
each reported Go binary's SHA-256, and every preserved binary was independently
read and found to match that value.

All nine reported Go binaries have `CGO_ENABLED=1`. This does not invalidate
the Go findings; it means native-code dependency and vulnerability coverage is
outside this evidence. All finding reachability values are `unknown`, so
binary-mode module, package, or symbol evidence must not be restated as runtime
reachability or exploitability.

## Argo CD

Evidence: `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`,
`persona-exercise/snapshots/argocd-deda478bd4d8/overview.txt`,
`persona-exercise/snapshots/argocd-deda478bd4d8/findings.txt`,
`persona-exercise/snapshots/argocd-deda478bd4d8/binaries.txt`,
`persona-exercise/snapshots/argocd-deda478bd4d8/diagnostics.txt`, and
`/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/`.

Identity and provenance: source reference
`registry.redhat.io/openshift-gitops-1/argocd-rhel9@sha256:deda478bd4d845e08dd25fb839e1c15d7d4507a397c7184c90b4f78d19410e05`,
resolved manifest
`sha256:a64530771531e94cc35f750738a55e74f59acabb451b65ed29e6b41bd4da5de8`,
scan `2026-09-24T01:47:52.116066Z` through
`2026-09-24T01:47:57.868566Z`.

### Questionnaire answers

1. **Go binaries:** `/usr/local/bin/argocd`, `/usr/local/bin/git-lfs`,
   `/usr/local/bin/helm`, and `/usr/local/bin/kustomize`. The snapshot counted
   476 unique ELF files and identified these four as Go binaries.
2. **Build identity:** all four record `go1.26.5 (Red Hat 1.26.5-1.el9_8)
   X:strictfipsruntime` and `CGO_ENABLED=1`. Main modules are
   `github.com/argoproj/argo-cd/v3@(devel)` for `argocd`, unavailable for
   `git-lfs`, `helm.sh/helm/v3@(devel)` for `helm`, and
   `sigs.k8s.io/kustomize/kustomize/v5@(devel)` for `kustomize`.
3. **Coverage:** complete for 4/4. There are no operational coverage issues.
   The four issue records are informational standard-library representation
   differences.
4. **Rootfs consistency:** all four paths exist as regular files in the cited
   rootfs. Their rootfs/snapshot SHA-256 values match respectively:
   `02ad20a8355e8f6910c4daf5c529c5ac4df64a077fb217f336dc3e73cf67b9aa`,
   `7a546ec8fc23eee9e5b893297ff71b5bf479403c230b1375cba8cef786407bb1`,
   `cbc5e5a4fb8c5a3ad4fae6466ac6ddd80dbf7a15c28310d48a7755d1658d10b8`,
   and `18a3904966c7d799f34190c9354016597eb6e408097fb90e604bb6b323abb067`.
5. **Detected vulnerability support:** 63 preferred identifiers affect 186
   packages. The complete package-level evidence is in the cited
   `findings.txt`; the following module/version grouping accounts for every
   identifier without repeating symbol records:

   - `/usr/local/bin/argocd`: `github.com/go-git/go-billy/v5@v5.6.2`
     supports CVE-2026-44740 and CVE-2026-44973;
     `github.com/go-git/go-git/v5@v5.14.0` supports CVE-2026-25934,
     CVE-2026-33762, CVE-2026-34165, CVE-2026-41506, CVE-2026-45022,
     CVE-2026-45570, CVE-2026-45571, CVE-2026-71556, CVE-2026-71557, and
     GHSA-w5pp-99ch-qj29; `golang.org/x/crypto@v0.53.0` supports
     CVE-2026-56854, CVE-2026-56855, and CVE-2026-78662;
     `golang.org/x/text@v0.38.0` supports CVE-2026-56852;
     `google.golang.org/grpc@v1.79.3` supports CVE-2026-84304,
     CVE-2026-84445, and GHSA-hrxh-6v49-42gf;
     `k8s.io/kubernetes@v1.34.2` supports CVE-2024-7598 and CVE-2025-1767;
     `oras.land/oras-go/v2@v2.6.0` supports CVE-2026-48978,
     CVE-2026-50151, CVE-2026-50162, CVE-2026-50163, and
     GHSA-vh4v-2xq2-g5cg.
   - `/usr/local/bin/git-lfs`: `golang.org/x/crypto@v0.36.0` supports
     CVE-2025-47913, CVE-2025-47914, CVE-2025-58181, CVE-2026-39827 through
     CVE-2026-39835, CVE-2026-42508, CVE-2026-46595, CVE-2026-46597,
     CVE-2026-46598, CVE-2026-56854, CVE-2026-56855, CVE-2026-78662, and
     GO-2026-5932; `golang.org/x/net@v0.38.0` supports CVE-2025-47911,
     CVE-2025-58190, CVE-2026-25680, CVE-2026-25681, CVE-2026-27136,
     CVE-2026-33814, CVE-2026-39821, CVE-2026-42502, CVE-2026-42506, and
     CVE-2026-46600; `golang.org/x/text@v0.23.0` supports CVE-2026-56852.
   - `/usr/local/bin/helm`: `github.com/klauspost/compress@v1.18.0` supports
     GHSA-259r-337f-4rfw; `github.com/moby/spdystream@v0.5.0` supports
     CVE-2026-35469; `golang.org/x/crypto@v0.45.0` supports CVE-2026-39827
     through CVE-2026-39835, CVE-2026-42508, CVE-2026-46595,
     CVE-2026-46597, CVE-2026-46598, CVE-2026-56854, CVE-2026-56855,
     CVE-2026-78662, and GO-2026-5932; `golang.org/x/net@v0.47.0` supports
     CVE-2026-25680, CVE-2026-25681, CVE-2026-27136, CVE-2026-33814,
     CVE-2026-39821, CVE-2026-42502, CVE-2026-42506, and CVE-2026-46600;
     `golang.org/x/text@v0.31.0` supports CVE-2026-56852;
     `google.golang.org/grpc@v1.72.1` supports CVE-2026-33186,
     CVE-2026-84303, CVE-2026-84304, CVE-2026-84445, and
     GHSA-hrxh-6v49-42gf; `oras.land/oras-go/v2@v2.6.0` supports
     CVE-2026-48978, CVE-2026-50151, CVE-2026-50162, CVE-2026-50163, and
     GHSA-vh4v-2xq2-g5cg.
   - `/usr/local/bin/kustomize`: `golang.org/x/text@v0.28.0` supports
     CVE-2026-56852.
   - All four: `stdlib@v1.26.5` supports CVE-2026-33818, CVE-2026-39821,
     CVE-2026-46600, CVE-2026-56853, CVE-2026-56858, CVE-2026-56859,
     CVE-2026-56860, and CVE-2026-56862.

6. **Recurrence and version differences:** all four share standard library
   `v1.26.5`. Ninety-one declared dependency paths recur across at least two
   binaries; their complete per-binary inventory is in the cited
   `binaries.txt`. Material version variation is extensive: 44 recurring paths
   have multiple versions, including `golang.org/x/crypto` (`v0.36.0`,
   `v0.45.0`, `v0.53.0`), `golang.org/x/net` (`v0.38.0`, `v0.47.0`,
   `v0.56.0`), `golang.org/x/text` (`v0.23.0`, `v0.28.0`, `v0.31.0`,
   `v0.38.0`), `google.golang.org/grpc` (`v1.72.1`, `v1.79.3`), and the
   Kubernetes modules at `v0.34.0` versus `v0.34.2`. Other differing paths are
   `dario.cat/mergo`, `github.com/chai2010/gettext-go`,
   `github.com/davecgh/go-spew`, `github.com/go-errors/errors`,
   `github.com/go-logr/logr`, the three `github.com/go-openapi` paths,
   `github.com/google/gnostic-models`, `github.com/google/uuid`,
   `github.com/mailru/easyjson`, `github.com/mattn/go-isatty`,
   `github.com/moby/spdystream`, `github.com/pkg/errors`,
   `github.com/sergi/go-diff`, `github.com/sirupsen/logrus`,
   `github.com/spf13/cast`, `github.com/spf13/cobra`,
   `github.com/spf13/pflag`, `go.yaml.in/yaml/v3`, `golang.org/x/oauth2`,
   `golang.org/x/sync`, `golang.org/x/sys`, `golang.org/x/term`,
   `golang.org/x/time`, `google.golang.org/genproto/googleapis/rpc`,
   `google.golang.org/protobuf`, `gopkg.in/evanphx/json-patch.v4`,
   `k8s.io/api`, `k8s.io/apiextensions-apiserver`, `k8s.io/apimachinery`,
   `k8s.io/apiserver`, `k8s.io/cli-runtime`, `k8s.io/client-go`,
   `k8s.io/component-base`, `k8s.io/kube-openapi`, `k8s.io/kubectl`,
   `sigs.k8s.io/kustomize/api`, `sigs.k8s.io/kustomize/kyaml`,
   `sigs.k8s.io/structured-merge-diff/v6`, and `sigs.k8s.io/yaml`.
7. **Replacements:** `argocd` declares
   `github.com/argoproj/argo-cd/gitops-engine@v0.7.1-0.20250908182407-97ad5b59a627`
   with effective `./gitops-engine@(devel)`. It also records same-component,
   same-version replacements for `github.com/golang/protobuf`,
   `github.com/grpc-ecosystem/grpc-gateway`, `gopkg.in/yaml.v2`,
   `gopkg.in/yaml.v3`, and Kubernetes paths `api`,
   `apiextensions-apiserver`, `apimachinery`, `apiserver`, `cli-runtime`,
   `client-go`, `component-base`, `component-helpers`, `controller-manager`,
   `kube-aggregator`, and `kubectl`. No other Argo-image binary has a declared
   replacement.
8. **Reconciliation:** partial, but vulnerability coverage remains complete.
   Eight SBOM components have unverifiable versions: the local gitops-engine
   replacement and Argo main module; git-lfs, Helm, and four Kustomize main or
   development modules. All four also have the informational
   `stdlib@v1.26.5` versus vendor-form `go1.26.5 ...` representation difference.
9. **Pattern:** only the eight standard-library IDs listed above plus
   CVE-2026-56852 affect all four binaries (9 IDs total). The remaining 54 IDs
   affect subsets, precisely partitioned by the binary/module groups in answer
   5. This directly rejects a container-wide interpretation of every finding.

### Claim verdicts

| # | Verdict | Evidence-based reason |
|---|---|---|
| 10 | rejected | 476 unique ELF files versus 4 identified Go binaries. |
| 11 | rejected | 44 recurring dependency paths have differing versions. |
| 12 | rejected | 54 of 63 identifiers affect only a subset of the four binaries. |
| 13 | rejected | Declared modules are inventory evidence; the snapshot does not state that every package in each module was compiled. |
| 14 | rejected | A missing finding is not package-absence evidence; dependency inventory and finding detection are separate records. |
| 15 | rejected | Diagnostics explicitly report complete 4/4 vulnerability coverage despite partial reconciliation. |
| 16 | rejected | All four CGO-enabled binaries have complete Go scans; native libraries are merely outside scope. |
| 17 | unverifiable | No historical layer inventory is supplied for comparison with the runtime rootfs. |
| 18 | rejected | Image metadata is recorded, but there is no cryptographic digest over the complete rootfs tying it to the manifest. |

19. **Assurance conclusion:** the evidence is strong for what these four
    preserved binary files contained at scan time: content-addressed snapshot,
    complete binary-mode scans, matching rootfs binary hashes, and explicit
    finding-to-binary/module/version relationships. Dependency versions vary
    significantly between binaries, and most findings are not container-wide.
20. **Unsafe conclusions:** this evidence cannot establish runtime
    reachability, exploitability, native-code safety, historical-layer
    contents, full-rootfs identity attestation, or current database status. It
    also cannot resolve the eight development/local component versions.

## Dex

Evidence: `persona-exercise/snapshots/dex-51454e5c706f/audit.json`,
`persona-exercise/snapshots/dex-51454e5c706f/overview.txt`,
`persona-exercise/snapshots/dex-51454e5c706f/findings.txt`,
`persona-exercise/snapshots/dex-51454e5c706f/binaries.txt`,
`persona-exercise/snapshots/dex-51454e5c706f/diagnostics.txt`, and
`/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/`.

Identity and provenance: source reference
`registry.redhat.io/openshift-gitops-1/dex-rhel9@sha256:51454e5c706fd913503980d29a11ab233e3d0b82d319b23d46394612dd81d3ff`,
resolved manifest
`sha256:4f114a65d6d588722821ddc5bf0510829574c2428400d84260558a1b703969d4`,
scan `2026-09-24T01:52:29.883165Z` through
`2026-09-24T01:52:31.519812Z`.

### Questionnaire answers

1. **Go binary:** `/usr/local/bin/dex`; 264 unique ELF files were observed and
   one was identified as Go.
2. **Build identity:** `go1.26.5 (Red Hat 1.26.5-1.el9_8)
   X:strictfipsruntime`, main module `github.com/dexidp/dex@(devel)`,
   `CGO_ENABLED=1`.
3. **Coverage:** complete 1/1; no operational issue. One issue is the
   informational standard-library representation difference.
4. **Rootfs consistency:** the path exists and its rootfs SHA-256 matches the
   snapshot: `bb4c13d7c0479f799b7fef0642f0fc7c008fd2f971c12a99e0249fee1f2fccb8`.
5. **Detected vulnerability support:** all 12 affect `/usr/local/bin/dex`.
   `golang.org/x/net@v0.55.0` supports CVE-2026-46600;
   `golang.org/x/text@v0.37.0` supports CVE-2026-56852;
   `google.golang.org/grpc@v1.79.3` supports CVE-2026-84304,
   CVE-2026-84445, and GHSA-hrxh-6v49-42gf; `stdlib@v1.26.5` supports
   CVE-2026-33818, CVE-2026-39821, CVE-2026-46600, CVE-2026-56853,
   CVE-2026-56858, CVE-2026-56859, CVE-2026-56860, and CVE-2026-56862.
   Exact package and evidence levels are in the cited `findings.txt`.
6. **Recurrence:** only one Go binary exists, so cross-binary recurrence and
   within-container version differences are not applicable. Its standard
   library is `v1.26.5`.
7. **Replacement:** declared `github.com/dexidp/dex/api/v2@v2.4.0` has
   effective `./api/v2@(devel)`.
8. **Reconciliation:** partial because the replacement above and main module
   `github.com/dexidp/dex@(devel)` have unverifiable versions. The stdlib
   representation differs textually but denotes the same release. Neither
   limitation reduces complete vulnerability coverage.
9. **Pattern:** because there is one Go binary, all 12 detected identifiers are
   container-wide with respect to the identified Go-binary population; there
   is no multi-binary isolation comparison.

| Claim # | Verdict | Evidence-based reason |
|---|---|---|
| 10 | rejected | 264 unique ELF files versus 1 Go binary. |
| 11 | confirmed, cardinality-only | There is only one Go binary, so no pair can disagree. |
| 12 | confirmed, cardinality-only | Every detected identifier affects the sole Go binary. |
| 13 | rejected | Module declaration is not evidence that every package in it was compiled. |
| 14 | rejected | Non-detection is not package-absence evidence. |
| 15 | rejected | Coverage is complete despite partial reconciliation. |
| 16 | rejected | The CGO-enabled binary has a complete Go vulnerability scan; native code remains outside scope. |
| 17 | unverifiable | No historical layer inventory is supplied. |
| 18 | rejected | No cryptographic commitment binds the complete rootfs to the recorded manifest. |

19. **Assurance conclusion:** this is a complete, internally consistent
    binary-mode audit of the one preserved Go binary, and its file hash matches
    the snapshot. Two development/local components remain version-unverifiable.
20. **Unsafe conclusions:** runtime reachability, exploitability, native-code
    safety, historical layers, full-rootfs identity, current database state,
    and exact versions for the two partial components remain unproven.

## Quay Operator

Evidence: `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json`,
`persona-exercise/snapshots/quay-operator-d64966c08c64/overview.txt`,
`persona-exercise/snapshots/quay-operator-d64966c08c64/findings.txt`,
`persona-exercise/snapshots/quay-operator-d64966c08c64/binaries.txt`,
`persona-exercise/snapshots/quay-operator-d64966c08c64/diagnostics.txt`, and
`/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/`.

Identity and provenance: source reference
`registry.redhat.io/quay/quay-operator-rhel9@sha256:d64966c08c644f4843d9ff0281f7c9357802c4769d09389c18b62389ab019692`,
resolved manifest
`sha256:b17a240fd3c7032b9f098c9a3369a52ee4afaa23aa97a35936bf3fd44243681c`,
scan `2026-09-24T01:53:23.024218Z` through
`2026-09-24T01:53:24.838352Z`.

### Questionnaire answers

1. **Go binary:** `/workspace/manager`; 263 unique ELF files were observed and
   one was identified as Go.
2. **Build identity:** `go1.26.4 (Red Hat 1.26.4-1.el9_8)
   X:strictfipsruntime`, main module unavailable, `CGO_ENABLED=1`.
3. **Coverage:** complete 1/1; no operational issue. The only issue is an
   informational standard-library representation difference.
4. **Rootfs consistency:** the path exists and its rootfs SHA-256 matches the
   snapshot: `03959d49eafd2c07dd5add7dc793a81fa7959c9a0b64646d6979733c1e45576b`.
5. **Detected vulnerability support:** all 14 affect `/workspace/manager`.
   `github.com/go-jose/go-jose/v4@v4.0.5` supports CVE-2026-34986;
   `github.com/jackc/pgx/v5@v5.7.4` supports CVE-2026-33815,
   CVE-2026-33816, and CVE-2026-41889; `golang.org/x/net@v0.43.0` supports
   CVE-2026-33814, CVE-2026-39821, and CVE-2026-46600;
   `golang.org/x/text@v0.29.0` supports CVE-2026-56852; `stdlib@v1.26.4`
   supports CVE-2026-33818, CVE-2026-39821, CVE-2026-42505,
   CVE-2026-46600, CVE-2026-56853, CVE-2026-56859, CVE-2026-56860, and
   CVE-2026-56862. Exact package and evidence levels are in `findings.txt`.
6. **Recurrence:** not applicable across one binary; standard library is
   `v1.26.4`.
7. **Replacements:** none recorded.
8. **Reconciliation:** partial only because
   `github.com/quay/quay-operator@(devel)` is version-unverifiable. The stdlib
   representation differs textually but denotes the same release. Coverage
   remains complete.
9. **Pattern:** all 14 identifiers affect the sole Go binary.

| Claim # | Verdict | Evidence-based reason |
|---|---|---|
| 10 | rejected | 263 unique ELF files versus 1 Go binary. |
| 11 | confirmed, cardinality-only | Only one Go binary exists. |
| 12 | confirmed, cardinality-only | Every identifier affects the sole Go binary. |
| 13 | rejected | Declared module does not prove all module packages are compiled. |
| 14 | rejected | Non-detection does not prove package absence. |
| 15 | rejected | Coverage is complete despite partial reconciliation. |
| 16 | rejected | CGO does not invalidate the complete Go scan; native code is outside scope. |
| 17 | unverifiable | No historical layer inventory is supplied. |
| 18 | rejected | Recorded image metadata is not a whole-rootfs cryptographic attestation. |

19. **Assurance conclusion:** complete scan coverage and matching binary hash
    support the 14 module/version-qualified findings for the preserved
    manager; the development main module remains version-unverifiable.
20. **Unsafe conclusions:** reachability, exploitability, native safety,
    layer history, complete rootfs identity, current database status, and the
    exact main-module version cannot be established.

## GitOps Operator

Evidence:
`persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json`,
`persona-exercise/snapshots/gitops-operator-95aa28b8b04e/overview.txt`,
`persona-exercise/snapshots/gitops-operator-95aa28b8b04e/findings.txt`,
`persona-exercise/snapshots/gitops-operator-95aa28b8b04e/binaries.txt`,
`persona-exercise/snapshots/gitops-operator-95aa28b8b04e/diagnostics.txt`, and
`/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/`.

Identity and provenance: source reference
`registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator@sha256:95aa28b8b04efde78d2e4495d2c58e7f8ebd5b399cb2afda927eb01011d2061e`,
resolved manifest
`sha256:7f6e588459ff59366a9f8f8f32a784806af11931f8584e46e1d53472a2e010a9`,
scan `2026-09-24T01:53:55.590517Z` through
`2026-09-24T01:54:06.134201Z`.

### Questionnaire answers

1. **Go binary:** `/usr/local/bin/manager`; 247 unique ELF files were observed
   and one was identified as Go.
2. **Build identity:** `go1.24.6 (Red Hat
   1.24.6-1.module+el8.10.0+23407+428597c7) X:strictfipsruntime`, main module
   unavailable, `CGO_ENABLED=1`.
3. **Coverage:** complete 1/1 with no operational issue; the one issue is an
   informational stdlib representation difference.
4. **Rootfs consistency:** the path exists and matches snapshot SHA-256
   `34578cdf615bba1b8e70f88db76cf241eb8ae253cb5bce93d1c912fd10240bf4`.
5. **Detected vulnerability support:** all 70 identifiers affect the manager.
   `github.com/argoproj/argo-cd/v3@v3.1.5` supports CVE-2025-55191,
   CVE-2025-59531, CVE-2025-59537, CVE-2025-59538, and CVE-2026-45738;
   `github.com/cloudflare/circl@v1.6.1` supports CVE-2026-1229;
   `github.com/go-git/go-billy/v5@v5.6.2` supports CVE-2026-44740 and
   CVE-2026-44973; `github.com/go-git/go-git/v5@v5.16.2` supports
   CVE-2026-25934, CVE-2026-33762, CVE-2026-34165, CVE-2026-41506,
   CVE-2026-45570, CVE-2026-71557, and GHSA-w5pp-99ch-qj29;
   `github.com/moby/spdystream@v0.5.0` supports CVE-2026-35469;
   `golang.org/x/crypto@v0.39.0` supports CVE-2025-47913, CVE-2025-58181,
   CVE-2026-39827 through CVE-2026-39832, CVE-2026-39834, CVE-2026-39835,
   CVE-2026-42508, CVE-2026-46595, CVE-2026-46597, CVE-2026-56854,
   CVE-2026-56855, and CVE-2026-78662; `golang.org/x/net@v0.41.0` supports
   CVE-2026-33814 and CVE-2026-39821; `golang.org/x/text@v0.26.0` supports
   CVE-2026-56852; `k8s.io/kubernetes@v1.33.1` supports CVE-2024-7598,
   CVE-2025-13281, CVE-2025-1767, CVE-2025-4563, and CVE-2025-5187;
   `stdlib@v1.24.6` supports CVE-2025-47912, CVE-2025-58185 through
   CVE-2025-58189, CVE-2025-61723, CVE-2025-61724, CVE-2025-61726 through
   CVE-2025-61730, CVE-2025-68121, CVE-2026-25679, CVE-2026-27139,
   CVE-2026-27145, CVE-2026-32280, CVE-2026-32281, CVE-2026-32283,
   CVE-2026-33811, CVE-2026-33814, CVE-2026-33818, CVE-2026-39821,
   CVE-2026-39836, CVE-2026-42504, CVE-2026-42505, CVE-2026-42507,
   CVE-2026-56853, CVE-2026-56859, CVE-2026-56860, and CVE-2026-56862.
   Exact package/evidence detail is in `findings.txt`.
6. **Recurrence:** not applicable across one binary; stdlib is `v1.24.6`.
7. **Replacements:** recorded declared/effective changes are `k8s.io/api`,
   `apimachinery`, `apiserver`, `cli-runtime`, `component-base`, and
   `component-helpers` from `v0.33.2` to `v0.33.1`, and
   `k8s.io/client-go` from `v12.0.0+incompatible` to `v0.33.1`. Same-version
   replacements are `k8s.io/apiextensions-apiserver`, `controller-manager`,
   `kube-aggregator`, and `kubectl` at `v0.33.1`, plus `gopkg.in/yaml.v2`
   `v2.4.0` and `gopkg.in/yaml.v3` `v3.0.1`.
8. **Reconciliation:** partial because
   `github.com/redhat-developer/gitops-operator@(devel)` is
   version-unverifiable. The stdlib representation difference is
   informational. Coverage remains complete.
9. **Pattern:** all findings affect the sole Go binary.

| Claim # | Verdict | Evidence-based reason |
|---|---|---|
| 10 | rejected | 247 unique ELF files versus 1 Go binary. |
| 11 | confirmed, cardinality-only | Only one Go binary exists. |
| 12 | confirmed, cardinality-only | Every detected identifier affects it. |
| 13 | rejected | Module declaration is not all-package compilation evidence. |
| 14 | rejected | Non-detection is not package-absence evidence. |
| 15 | rejected | Complete coverage coexists with partial reconciliation. |
| 16 | rejected | CGO leaves native code outside scope but does not invalidate Go findings. |
| 17 | unverifiable | Historical layers are not supplied. |
| 18 | rejected | No whole-rootfs cryptographic binding to image metadata is supplied. |

19. **Assurance conclusion:** complete scan coverage, explicit effective
    Kubernetes replacements, and a matching preserved binary hash provide
    reviewable evidence for 70 identifiers; the main module remains
    version-unverifiable.
20. **Unsafe conclusions:** the evidence does not establish reachability,
    exploitability, native safety, layer history, full-rootfs image identity,
    current database status, or an exact main-module version.

## kube-rbac-proxy

Evidence:
`persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json`,
`persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/overview.txt`,
`persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/findings.txt`,
`persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/binaries.txt`,
`persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/diagnostics.txt`, and
`/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/`.

Identity and provenance: source reference
`registry.redhat.io/openshift4/ose-kube-rbac-proxy@sha256:58698c84109b0833060ab86ef36c0092418c87aba61ba271bef60a18e6b5a6af`,
resolved manifest
`sha256:a083d6d53630f47a8503a45b639ae5c567d1f724096d1f729082bfdb9d760585`,
scan `2026-09-24T01:54:20.255044Z` through
`2026-09-24T01:54:22.118869Z`.

### Questionnaire answers

1. **Go binary:** `/usr/bin/kube-rbac-proxy`; 1,032 unique ELF files were
   observed and one was identified as Go.
2. **Build identity:** `go1.20.12 X:strictfipsruntime`, main module
   `github.com/brancz/kube-rbac-proxy@(devel)`, `CGO_ENABLED=1`.
3. **Coverage:** complete 1/1; no operational issue, one informational stdlib
   representation difference.
4. **Rootfs consistency:** the path exists and matches snapshot SHA-256
   `1448e55b04d3a40a37d9a0e62014c2cb0f341d9af7ba6ff4a1950bc86ed19113`.
5. **Detected vulnerability support:** all 55 identifiers affect the sole
   binary. `golang.org/x/net@v0.29.0` supports CVE-2025-22870,
   CVE-2026-33814, and CVE-2026-39821; `google.golang.org/grpc@v1.47.0`
   supports CVE-2026-33186, CVE-2026-84304, CVE-2026-84445,
   GHSA-hrxh-6v49-42gf, and GHSA-m425-mq94-257g; `stdlib@v1.20.12` supports
   CVE-2023-45288, CVE-2023-45289, CVE-2023-45290, CVE-2024-24783,
   CVE-2024-24785, CVE-2024-24790, CVE-2024-24791, CVE-2024-45336,
   CVE-2024-45341, CVE-2025-22870, CVE-2025-22871, CVE-2025-4673,
   CVE-2025-47906, CVE-2025-47912, CVE-2025-58185 through CVE-2025-58189,
   CVE-2025-61723, CVE-2025-61724, CVE-2025-61726, CVE-2025-61727,
   CVE-2025-61729, CVE-2025-61730, CVE-2025-68121, CVE-2026-25679,
   CVE-2026-27139, CVE-2026-27142, CVE-2026-27145, CVE-2026-32280,
   CVE-2026-32281, CVE-2026-32283, CVE-2026-32289, CVE-2026-33811,
   CVE-2026-33814, CVE-2026-33818, CVE-2026-39821, CVE-2026-39823,
   CVE-2026-39825, CVE-2026-39826, CVE-2026-39836, CVE-2026-42504,
   CVE-2026-42505, CVE-2026-42507, CVE-2026-56853, CVE-2026-56858,
   CVE-2026-56859, CVE-2026-56860, and CVE-2026-56862. Exact package and
   evidence detail is in `findings.txt`.
6. **Recurrence:** not applicable across one binary; stdlib is `v1.20.12`.
7. **Replacements:** `github.com/emicklei/go-restful/v3@v3.8.0` has effective
   `github.com/emicklei/go-restful/v3@v3.11.0`; `go.etcd.io/etcd/client/v3@v3.5.4`
   has effective `go.etcd.io/etcd/client/v3@v3.5.9`.
8. **Reconciliation:** partial because the main module
   `github.com/brancz/kube-rbac-proxy@(devel)` is version-unverifiable. The
   stdlib representation difference is informational; coverage remains
   complete.
9. **Pattern:** all 55 identifiers affect the sole Go binary.

| Claim # | Verdict | Evidence-based reason |
|---|---|---|
| 10 | rejected | 1,032 unique ELF files versus 1 Go binary. |
| 11 | confirmed, cardinality-only | Only one Go binary exists. |
| 12 | confirmed, cardinality-only | Every identifier affects the sole binary. |
| 13 | rejected | A declared module does not establish compilation of every package. |
| 14 | rejected | Non-detection does not prove package absence. |
| 15 | rejected | Coverage is complete despite partial reconciliation. |
| 16 | rejected | CGO does not invalidate the Go scan; native code is outside scope. |
| 17 | unverifiable | No historical layer inventory is supplied. |
| 18 | rejected | Image metadata is not cryptographic proof of complete-rootfs origin. |

19. **Assurance conclusion:** the preserved binary hash matches, coverage is
    complete, and findings are module/version-qualified. The notably older
    `v1.20.12` standard library supports most of the 55 detected identifiers.
20. **Unsafe conclusions:** no reachability, exploitability, native safety,
    historical-layer completeness, rootfs attestation, current database state,
    or exact main-module version can be inferred.

## Cross-image observations

- Six identifiers occur in all five image snapshots: CVE-2026-33818,
  CVE-2026-39821, CVE-2026-56853, CVE-2026-56859, CVE-2026-56860, and
  CVE-2026-56862. Their binary/module/package evidence still differs by image;
  shared identifier does not mean shared reachability.
- Every vulnerability scan is complete, while every binary's dependency
  reconciliation is partial. This dataset demonstrates why those states must
  remain separate.
- All reported Go binaries exist and hash-match. This is strong binary-level
  continuity evidence, but it does not hash or attest the rest of each rootfs.
- The source-reference digest and resolved-manifest digest are distinct values
  in every image record. Both are preserved; no inference about their registry
  relationship is necessary for the findings.
- All snapshots use the same host scanner/database state, which improves
  cross-image comparability at that recorded time. It does not make results
  current beyond `2026-09-16T18:00:43Z` database provenance.
- The reported counts range from 12 identifiers in Dex to 70 in GitOps
  Operator. Counts alone are not a severity or exploitability measure.

## Explicit evidence limitations

1. Binary-mode finding evidence has unknown reachability.
2. Native dependencies and vulnerabilities are not covered despite CGO being
   enabled in every reported binary.
3. Preserved root filesystems are runtime views; no historical layer inventory
   is authorized evidence.
4. Image identity fields are metadata, not a cryptographic rootfs attestation.
5. Content-addressed snapshots establish JSON-content identity, not the
   currentness or correctness of the vulnerability database.
6. `govulncheck@v0.0.0` is the recorded scanner identifier; no scanner binary
   digest is supplied.
7. Development and local replacements marked `(devel)` remain
   version-unverifiable, even though vulnerability scans completed.
8. Main-module metadata is unavailable for three binaries; the snapshot alone
   does not explain why.

## Questions for other personas

1. **Go engineer:** Can the supplied build metadata distinguish why the main
   module is unavailable for Argo CD's `/usr/local/bin/git-lfs`, GitOps
   Operator's `/usr/local/bin/manager`, and Quay Operator's
   `/workspace/manager`, or must the reason remain unverifiable?
2. **Go engineer:** Which recorded `replace` entries represent a materially
   different effective dependency, and how should identical declared/effective
   replacement records be described without overstating them?
3. **Security analyst:** Please independently validate the six identifiers
   detected in all five snapshots and summarize their per-image
   module/package/evidence levels, explicitly preserving the unknown
   reachability qualification.
