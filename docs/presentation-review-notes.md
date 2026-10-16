# Presentation review notes

Reviewed on 2026-10-06 for a 20–30 minute presentation to engineers and
security analysts. The experiment results are on
`persona-experiment-1-results` at commit
`c210f52540bbdbcb5c01271a5d1fa911748dd1d7`.

## Verified experiment observations

- The five successful image snapshots contain eight Go binary records: four
  for Argo CD, and one each for Dex, Quay Operator, GitOps Operator, and
  kube-rbac-proxy. All eight completed vulnerability scanning.
- All five content-addressed snapshots validate against their filenames, and
  each portable `audit.json` is byte-identical to its corresponding stored
  snapshot.
- Each persona's 20 targeted status conclusions agree with the snapshot
  findings: five detected identifier/image pairs and fifteen results of
  “not detected in this snapshot.” This checks status agreement; it does not
  measure vulnerability-detector accuracy or validate every narrative claim.
- The retained Argo CD DNS-failure snapshot has zero completed vulnerability
  scans out of four Go binaries. All four targeted identifiers return
  `INDETERMINATE` for that snapshot.
- The three personas produced twelve deliverables and exchanged ten
  questions. Their discussions distinguish scan coverage from dependency
  reconciliation, symbol evidence from runtime reachability, and finding
  counts from security risk.

Start with the [dataset index](../persona-exercise/snapshots/INDEX.md),
[targeted result matrix](../persona-exercise/shared/assurance-lead/targeted.md),
and [security prioritization discussion](../persona-exercise/shared/security-analyst/response.md).
These evidence files are available on the results branch.

## Corrections and demonstration follow-up

1. **Persona summary counts:** the security analyst's initial analysis says
   seven Go binaries; the assurance lead's says nine. The snapshots establish
   eight. Use eight in presentation material and retain the original reports
   as the experiment record. These discrepancies are useful examples of why
   AI-generated summaries need independent evidence checks.
2. **Rendered snapshot identity:** the pending working-tree edits remove
   `schema_version` from the serialized report. Loading an archived schema-6
   snapshot validates its original content address, but rendering computes a
   new digest from the report without that field. Consequently the displayed
   snapshot SHA-256 differs from the archived filename. All five successful
   snapshots reproduce this behavior; the schema field is the only document
   difference. The source snapshots are intact. Resolve the identity behavior
   or rehearse with the committed code that produced the archived reports
   before demonstrating snapshot identity. No corrective code change was made
   during this review.
3. **Rootfs availability:** the results branch retains snapshots and persona
   outputs, but not the extracted root filesystems. The recorded
   `/tmp/pygo-audit-persona-rootfs/` directory was absent at review time.
   Snapshot-backed reports remain usable; repeating binary-to-rootfs hash
   comparisons requires supplying the matching root filesystems again.

The preserved findings are historical: the successful scans record
2026-09-24 UTC and vulnerability-database update `2026-09-16T18:00:43Z`.
Do not present them as a current scan or as proof of runtime exploitability.

## Installation walkthrough starting point

The repository declares Python 3.14 or newer and no third-party Python runtime
dependencies. Installation also needs the declared setuptools build backend.
Scanning requires a compatible host Go toolchain, `govulncheck`, Linux with
`/proc`, and an extracted container filesystem. Rendering existing snapshots
does not invoke Go or `govulncheck`.

At review time, this terminal's `python3` resolved to Python 3.11.16 from an
existing environment, despite the README describing Python 3.14.7. Select an
explicit Python 3.14-or-newer interpreter and a dedicated virtual environment
when rehearsing installation from a fresh clone.
