# Container audit results — 2026-09-22

These reports were produced with the repository-local `pygo-audit` utility for
the `linux/amd64` variants of the exact image digests below. All vulnerability
scans completed successfully against `https://vuln.go.dev`, last modified
2026-09-16T18:00:43Z.

| Image | Go binaries | Unique vulnerabilities | Reports |
|---|---:|---:|---|
| `quay.io/openshift-release-dev/ocp-release@sha256:d03909e954e9a6d24900809750bd39f5f69d8a9e480eec97d481b9977c430d4d` | 1 | 24 | [summary](ocp-release.summary.txt), [full JSON](ocp-release.json) |
| `registry.redhat.io/openshift-gitops-1/argocd-rhel9@sha256:deda478bd4d845e08dd25fb839e1c15d7d4507a397c7184c90b4f78d19410e05` | 4 | 63 | [summary](argocd.summary.txt), [full JSON](argocd.json) |
| `registry.redhat.io/openshift-gitops-1/dex-rhel9@sha256:51454e5c706fd913503980d29a11ab233e3d0b82d319b23d46394612dd81d3ff` | 1 | 12 | [summary](dex.summary.txt), [full JSON](dex.json) |
| `registry.redhat.io/quay/quay-operator-rhel9@sha256:d64966c08c644f4843d9ff0281f7c9357802c4769d09389c18b62389ab019692` | 1 | 14 | [summary](quay-operator.summary.txt), [full JSON](quay-operator.json) |
| `registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator@sha256:95aa28b8b04efde78d2e4495d2c58e7f8ebd5b399cb2afda927eb01011d2061e` | 1 | 70 | [summary](gitops-operator.summary.txt), [full JSON](gitops-operator.json) |
| `registry.redhat.io/openshift4/ose-kube-rbac-proxy@sha256:58698c84109b0833060ab86ef36c0092418c87aba61ba271bef60a18e6b5a6af` | 1 | 55 | [summary](kube-rbac-proxy.summary.txt), [full JSON](kube-rbac-proxy.json) |

The summary files group preferred vulnerability identifiers by module and
version. The JSON files retain binaries, packages, symbols, advisories,
affected ranges, build settings, SBOMs, and reconciliation evidence.

Binary-mode findings establish that affected modules, packages, or symbols are
present in the compiled binaries. They do not by themselves prove runtime
reachability or exploitability.

## Known report issue

Each binary currently has a reconciliation warning caused by equivalent
standard-library versions being formatted as `v1.x` by govulncheck findings and
`go1.x` by `go version -m`. The vulnerability scans themselves completed, and
the warning does not change or suppress any findings.
