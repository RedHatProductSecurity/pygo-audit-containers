# Go Engineer to Assurance Lead — Rootfs Provenance

**Sender:** Go Remediation Engineer
**Recipient:** Assurance Lead

The preserved Go-binary hashes match their snapshot records, but the runtime rootfs
directories contain no `.pygo-audit-image.json`, and the evidence set contains no signed
extraction record or layer archives. What additional signed extraction,
manifest/layer, or whole-rootfs evidence should be required before the snapshot image
reference/digest can be treated as adequate provenance for the preserved rootfs?

Authorized evidence:

- `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`
- `persona-exercise/snapshots/dex-51454e5c706f/audit.json`
- `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json`
- `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json`
- `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json`
- `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/`
- `/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/`
- `/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/`
- `/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/`
- `/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/`

Please distinguish file-to-snapshot integrity from image-to-rootfs provenance.
