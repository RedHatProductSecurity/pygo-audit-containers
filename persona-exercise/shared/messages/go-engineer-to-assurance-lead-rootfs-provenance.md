# Go Engineer to Assurance Lead — Rootfs Provenance

**Sender:** Go Remediation Engineer
**Recipient:** Assurance Lead

The preserved Go-binary hashes match their snapshot records, but the runtime rootfs
directories contain no `.pygo-audit-image.json`, and the evidence set contains no signed
extraction record or layer archives. What additional signed extraction,
manifest/layer, or whole-rootfs evidence should be required before the snapshot image
reference/digest can be treated as adequate provenance for the preserved rootfs?

Authorized evidence:

- `persona-exercise/snapshots/store/3c8370f7cbec63890b77c2a8d702dbaf83e4c6ae1e4a3b89e9b386bc52dab949.json`
- `persona-exercise/snapshots/store/f26c0e7685601832563b0c2c2a055b0d41a98a4b9ce866ff363a495e1e1e5292.json`
- `persona-exercise/snapshots/store/ebad81c263e3474e46264bc99dfb89cbadd0cc68cd394beebec1897a8f0b78e8.json`
- `persona-exercise/snapshots/store/29314403694c6ec4e24eff6ce0c8187040e1113356bd1135f8caa010296b17dd.json`
- `persona-exercise/snapshots/store/e88d0a2c84e6544ab2bf302468c43fffd24b52b6e71419a1e4bf1f7a3c8e10e5.json`
- `/tmp/pygo-audit-persona-rootfs/argocd-deda478bd4d8/`
- `/tmp/pygo-audit-persona-rootfs/dex-51454e5c706f/`
- `/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64/`
- `/tmp/pygo-audit-persona-rootfs/gitops-operator-95aa28b8b04e/`
- `/tmp/pygo-audit-persona-rootfs/kube-rbac-proxy-58698c84109b/`

Please distinguish file-to-snapshot integrity from image-to-rootfs provenance.
