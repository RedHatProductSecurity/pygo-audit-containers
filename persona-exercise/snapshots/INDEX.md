# Persona Exercise Dataset

This directory contains the successful, read-only scan snapshots for the
persona exercise. The corresponding runtime root filesystems are preserved
under `/tmp/pygo-audit-persona-rootfs/`.

All images were extracted with `oc` for `linux/amd64`. All scans used the same
local Go toolchain and `govulncheck` database state recorded in each snapshot.
The previously considered `ocp-release` image is not part of this dataset.

## Argo CD

- Source reference: `registry.redhat.io/openshift-gitops-1/argocd-rhel9@sha256:deda478bd4d845e08dd25fb839e1c15d7d4507a397c7184c90b4f78d19410e05`
- Resolved manifest: `sha256:a64530771531e94cc35f750738a55e74f59acabb451b65ed29e6b41bd4da5de8`
- Reports: `argocd-deda478bd4d8/`
- Content-addressed snapshot: `store/3c8370f7cbec63890b77c2a8d702dbaf83e4c6ae1e4a3b89e9b386bc52dab949.json`
- Rootfs: `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/`

## Dex

- Source reference: `registry.redhat.io/openshift-gitops-1/dex-rhel9@sha256:51454e5c706fd913503980d29a11ab233e3d0b82d319b23d46394612dd81d3ff`
- Resolved manifest: `sha256:4f114a65d6d588722821ddc5bf0510829574c2428400d84260558a1b703969d4`
- Reports: `dex-51454e5c706f/`
- Content-addressed snapshot: `store/f26c0e7685601832563b0c2c2a055b0d41a98a4b9ce866ff363a495e1e1e5292.json`
- Rootfs: `/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/`

## Quay Operator

- Source reference: `registry.redhat.io/quay/quay-operator-rhel9@sha256:d64966c08c644f4843d9ff0281f7c9357802c4769d09389c18b62389ab019692`
- Resolved manifest: `sha256:b17a240fd3c7032b9f098c9a3369a52ee4afaa23aa97a35936bf3fd44243681c`
- Reports: `quay-operator-d64966c08c64/`
- Content-addressed snapshot: `store/ebad81c263e3474e46264bc99dfb89cbadd0cc68cd394beebec1897a8f0b78e8.json`
- Rootfs: `/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/`

## GitOps Operator

- Source reference: `registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator@sha256:95aa28b8b04efde78d2e4495d2c58e7f8ebd5b399cb2afda927eb01011d2061e`
- Resolved manifest: `sha256:7f6e588459ff59366a9f8f8f32a784806af11931f8584e46e1d53472a2e010a9`
- Reports: `gitops-operator-95aa28b8b04e/`
- Content-addressed snapshot: `store/29314403694c6ec4e24eff6ce0c8187040e1113356bd1135f8caa010296b17dd.json`
- Rootfs: `/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/`

## kube-rbac-proxy

- Source reference: `registry.redhat.io/openshift4/ose-kube-rbac-proxy@sha256:58698c84109b0833060ab86ef36c0092418c87aba61ba271bef60a18e6b5a6af`
- Resolved manifest: `sha256:a083d6d53630f47a8503a45b639ae5c567d1f724096d1f729082bfdb9d760585`
- Reports: `kube-rbac-proxy-58698c84109b/`
- Content-addressed snapshot: `store/e88d0a2c84e6544ab2bf302468c43fffd24b52b6e71419a1e4bf1f7a3c8e10e5.json`
- Rootfs: `/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/`
