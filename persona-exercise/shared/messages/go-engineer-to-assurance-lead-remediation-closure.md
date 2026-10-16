# Go Engineer to Assurance Lead — Remediation Closure

**Sender:** Go Remediation Engineer
**Recipient:** Assurance Lead

What closure evidence should be required after remediation for local or `(devel)`
components whose current versions are not verifiable? Relevant examples include Argo
CD's `./gitops-engine@(devel)`, Dex's `./api/v2@(devel)`, and the `(devel)` main or
dependency modules in all five snapshots.

Authorized evidence:

- `persona-exercise/snapshots/argocd-deda478bd4d8/audit.json`
- `persona-exercise/snapshots/dex-51454e5c706f/audit.json`
- `persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json`
- `persona-exercise/snapshots/gitops-operator-95aa28b8b04e/audit.json`
- `persona-exercise/snapshots/kube-rbac-proxy-58698c84109b/audit.json`

Please propose a minimum evidence set that can be verified without silently converting
an unverifiable component into a known version.
