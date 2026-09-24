# Security Analyst Tutorial: Reviewing an Existing Snapshot

This tutorial uses only previously created snapshots. It does not extract an
image, rescan a root filesystem, run a container binary, invoke
`govulncheck`, or contact the internet.

Run the examples from the repository root.

## 1. Select the snapshot

Use the Quay Operator snapshot for a compact example:

```bash
SNAPSHOT=persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json
ROOTFS=/tmp/pygo-audit-persona-rootfs/quay-operator-d64966c08c64
```

The snapshot is the vulnerability evidence. The rootfs is useful only for
read-only confirmation that a reported pathname still exists.

## 2. Start with the overview

```bash
./pygo-audit report overview "$SNAPSHOT"
```

This answers:

- Were vulnerabilities detected?
- How many identified Go binaries received a completed vulnerability scan?
- How many unique vulnerabilities and affected packages were recorded?
- Was CGO enabled?
- Which image reference, digest, platform, vulnerability database date, and
  scanner/toolchain were recorded?

Read `Coverage: COMPLETE (N of N binaries)` before interpreting an absent
finding. A CGO warning does not invalidate the Go findings; it means native
libraries are outside this Go audit.

## 3. Review findings by package or vulnerability

Group by package when assigning a finding to a component owner:

```bash
./pygo-audit report findings "$SNAPSHOT" --group-by package
```

Group by vulnerability when investigating a specific advisory across packages
and binaries:

```bash
./pygo-audit report findings "$SNAPSHOT" --group-by vulnerability
```

Look for four separate facts:

1. preferred vulnerability identifier;
2. affected package and enclosing module;
3. current version recorded in the binary;
4. complete affected binary pathname.

Evidence levels are not interchangeable:

- `symbol` gives package/symbol-level compiled-binary evidence;
- `module` gives only a module/version association.

Neither level proves that the vulnerable code executes at runtime. Preserve
the evidence level when recording a finding.

## 4. Pivot to the affected binary

```bash
./pygo-audit report binaries "$SNAPSHOT"
```

This view groups findings under each Go binary and also shows its Go version,
main package/module when available, CGO state, scan status, declared
dependencies, and effective replacements. Use it to distinguish two binaries
in one container that declare different dependency versions.

Do not interpret a declared module as proof that every package in that module
was compiled into the binary. Prefer the package/symbol evidence in the
finding record when it is available.

## 5. Run a focused vulnerability check

Check one detected and one non-detected identifier in the Quay Operator
snapshot:

```bash
./pygo-audit check "$SNAPSHOT" CVE-2026-41889 CVE-2024-3094
```

For this supplied snapshot, the check reports:

- `CVE-2026-41889`: detected in
  `github.com/jackc/pgx/v5/internal/sanitize`, module
  `github.com/jackc/pgx/v5`, current version `v5.7.4`, affecting
  `/workspace/manager`;
- `CVE-2024-3094`: not detected in this snapshot, with complete 1-of-1
  Go-binary coverage.

The second result is deliberately narrow. It does not say that the container
is clean, that a related component is absent, or that a non-Go vulnerability
scanner would reach the same conclusion.

For a multi-binary example, check Argo CD:

```bash
ARGO_SNAPSHOT=persona-exercise/snapshots/argocd-deda478bd4d8/audit.json
./pygo-audit check "$ARGO_SNAPSHOT" CVE-2026-46595
```

That result demonstrates why path and version matter: the same package is
recorded at `golang.org/x/crypto@v0.36.0` in `/usr/local/bin/git-lfs` and
`golang.org/x/crypto@v0.45.0` in `/usr/local/bin/helm`.

## 6. Interpret result and coverage states

| Result state | Safe interpretation |
|---|---|
| `DETECTED` | The snapshot contains matching evidence for the listed binary/component. Record package/module, version, evidence level, and pathname. Do not claim runtime exploitability. |
| `NOT DETECTED IN THIS SNAPSHOT` | With complete coverage, no matching finding was recorded for any audited Go binary in that historical snapshot. Do not claim that the image is not vulnerable or that the module/package is absent. |
| `INDETERMINATE` | Missing or failed vulnerability scans prevent a reliable snapshot-wide negative result. Identify the uncovered binary and operational failure. |

Coverage modifies the conclusion:

- `COMPLETE (N of N binaries)` supports a snapshot-scoped negative result.
- Partial, failed, timed-out, disabled, or unavailable vulnerability scanning
  leaves one or more binaries unevaluated. Positive findings remain evidence
  for the binaries where they were found, but absence cannot be generalized to
  the container.
- `Reconciliation: PARTIAL` is a different concept. It means some dependency
  records could not be matched exactly between `go version -m` and
  `govulncheck`; consult diagnostics to see whether scan coverage itself is
  complete.

Always preserve the scan completion time and vulnerability database update
shown in `SCAN CONTEXT` or `PROVENANCE`. A later database state could produce a
different result.

## 7. Inspect diagnostics separately

```bash
./pygo-audit report diagnostics "$SNAPSHOT"
```

Use diagnostics to distinguish:

- operational failures that can limit scan coverage;
- unverifiable `(devel)` or local replacement versions;
- harmless representation differences such as `v1.26.4` versus a longer Red
  Hat Go toolchain string.

Do not convert an informational reconciliation difference into a failed
vulnerability scan when the report still says coverage is complete.

## 8. Confirm a reported pathname without executing it

```bash
test -f "$ROOTFS/workspace/manager" && \
  printf 'preserved path exists: %s\n' "$ROOTFS/workspace/manager"

stat -- "$ROOTFS/workspace/manager"
```

This confirms that the file exists in the preserved runtime rootfs. Do not run
the binary. Existence does not independently prove its package inventory,
vulnerable reachability, or the completeness of every historical image layer.

## 9. Optionally cache only the targeted check

Without `--output-dir`, `check` is read-only. To retain a check report, write
only inside the Security Analyst's private directory:

```bash
PRIVATE_OUTPUT=persona-exercise/shared/security-analyst/check-cache

./pygo-audit check \
  --output-dir "$PRIVATE_OUTPUT" \
  "$SNAPSHOT" \
  CVE-2026-41889 CVE-2024-3094

find "$PRIVATE_OUTPUT/checks" -maxdepth 1 -type f -print
```

Do not point `--output-dir` at `persona-exercise/snapshots/`; the shared
snapshot collection is read-only evidence. Cached text is a derived view, so
retain the original snapshot path or digest alongside it.

## 10. A compact analyst workflow

```bash
SNAPSHOT=persona-exercise/snapshots/quay-operator-d64966c08c64/audit.json

./pygo-audit report overview "$SNAPSHOT"
./pygo-audit check "$SNAPSHOT" CVE-2026-41889 CVE-2024-3094
./pygo-audit report findings "$SNAPSHOT" --group-by vulnerability
./pygo-audit report binaries "$SNAPSHOT"
./pygo-audit report diagnostics "$SNAPSHOT"
```

The order is intentional: establish coverage and provenance first, answer the
targeted question, expand into package/binary evidence, and inspect limitations
last. Report exactly what the snapshot establishes and label everything else
unverifiable.
