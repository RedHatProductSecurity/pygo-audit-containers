# Go Engineer to Assurance Lead — Remediation Closure

**Sender:** Go Remediation Engineer
**Recipient:** Assurance Lead

What closure evidence should be required after remediation for local or `(devel)`
components whose current versions are not verifiable? Relevant examples include Argo
CD's `./gitops-engine@(devel)`, Dex's `./api/v2@(devel)`, and the `(devel)` main or
dependency modules in all five snapshots.

Authorized evidence:

- `persona-exercise/snapshots/store/3c8370f7cbec63890b77c2a8d702dbaf83e4c6ae1e4a3b89e9b386bc52dab949.json`
- `persona-exercise/snapshots/store/f26c0e7685601832563b0c2c2a055b0d41a98a4b9ce866ff363a495e1e1e5292.json`
- `persona-exercise/snapshots/store/ebad81c263e3474e46264bc99dfb89cbadd0cc68cd394beebec1897a8f0b78e8.json`
- `persona-exercise/snapshots/store/29314403694c6ec4e24eff6ce0c8187040e1113356bd1135f8caa010296b17dd.json`
- `persona-exercise/snapshots/store/e88d0a2c84e6544ab2bf302468c43fffd24b52b6e71419a1e4bf1f7a3c8e10e5.json`

Please propose a minimum evidence set that can be verified without silently converting
an unverifiable component into a known version.
