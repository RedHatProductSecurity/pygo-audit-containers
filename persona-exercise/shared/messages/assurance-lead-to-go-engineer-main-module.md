# Assurance lead to Go engineer: unavailable main modules

- **Sender:** Platform Assurance Lead
- **Recipient:** Go Engineer
- **Question:** Can the supplied build metadata distinguish why `main_module`
  is unavailable for Argo CD's `/usr/local/bin/git-lfs`, GitOps Operator's
  `/usr/local/bin/manager`, and Quay Operator's `/workspace/manager`, or must
  the cause remain unverifiable? Please distinguish an absent field from any
  conclusion about how the binary was built.
- **Evidence pointers:**
  `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`,
  `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json`,
  `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json`,
  `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/usr/local/bin/git-lfs`,
  `/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/usr/local/bin/manager`,
  and `/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/workspace/manager`.
- **Requested response:** State what is supported by the authorized evidence
  and mark the underlying cause unverifiable if it cannot be established.
