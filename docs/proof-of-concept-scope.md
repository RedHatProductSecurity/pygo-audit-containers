# Proof-of-concept scope

The proof of concept makes container-level Go vulnerability findings easy
to understand while retaining the evidence required for analyst review. The
scanner remains extraction-tool-agnostic, uses no third-party Python runtime
dependencies, and never executes binaries from the inspected filesystem.

## Finding model

One normalized finding model preserves the complete relationship between:

```text
container -> binary path -> vulnerability -> module -> package -> symbol
```

It also retains installed and fixed versions, evidence level, aliases,
hardlinks, CGO status, reconciliation state, and scan coverage. Every renderer
consumes this model so container aggregation does not discard binary paths
or supporting evidence.

## Container identity

Container identity is optional because a merged root filesystem does not
contain a standardized OCI image reference or manifest digest. Callers may
provide an image reference, resolved digest, platform, and extractor through
CLI options or a tool-independent sidecar JSON file. When identity is absent,
the report identifies its subject as an unpacked root filesystem and does
not infer an OCI digest.

## Commands, reports, and grouping

The analyst interface uses explicit subcommands and report views:

```text
pygo-audit scan ROOT
pygo-audit report overview SNAPSHOT
pygo-audit report findings SNAPSHOT [--group-by GROUP]
pygo-audit report binaries SNAPSHOT
pygo-audit report diagnostics SNAPSHOT
pygo-audit report json SNAPSHOT
pygo-audit check SNAPSHOT ID [ID ...]
```

Reports lead with result state, scan coverage, and vulnerability findings;
subject identity, vulnerability database provenance, and tool versions
appear at the bottom. Finding rows retain the affected binary pathname.
The `check` subcommand emits only the requested vulnerability results,
including a scoped `NOT DETECTED IN THIS SNAPSHOT` result when scan coverage is
complete. Results appear before a compact shared scan-context footer. With
`--output-dir`, it persists only the corresponding `checks/ID.txt` files.

Container-level result states distinguish vulnerabilities, complete scans
with no findings, incomplete scans, roots containing no recognized Go
binaries, and operational errors. Detailed operational issues and differences
between `go version -m` and `govulncheck` appear in the snapshot-backed
diagnostics report. Primary reports show concise counts only when
diagnostics exist. Reconciliation differences remain informational; they are
not presented as incomplete coverage, do not raise an error, and do not trigger
strict issue handling. Unverifiable components are grouped across affected
binaries as reconciliation limitations; they make reconciliation partial but
do not make vulnerability coverage incomplete.

## Scan snapshots

Canonical JSON snapshots may be written to a content-addressed
store and read later without rescanning:

```text
pygo-audit scan ROOT --snapshot-dir SNAPSHOTS
pygo-audit report findings SNAPSHOTS/DIGEST.json --group-by container
pygo-audit check SNAPSHOTS/DIGEST.json CVE-YYYY-NNNNN
```

Snapshots are immutable scan IR. They retain scan timestamps, binary hashes,
producer and tool versions, database URL and last-modified
observations, coverage, and errors. Their content address covers all of those
fields and is not itself a vulnerability database digest. Digest-named
snapshots are automatically validated against their content address whenever
they are loaded. Reading a snapshot does not imply that it was refreshed
against the current database.

## Build inventory

Dependency preservation focuses on the `Deps` records from
`go version -m -json`, including declared module paths, versions, checksums, and
replacements. It does not expand the artifact into a general VCS or build-
setting report. `binaries.txt` presents this declared inventory. CGO status
remains visible, and human-readable reports
state that native-library coverage is outside the Go dependency audit when CGO
is enabled.

## Generated artifacts

A single scan can generate multiple artifacts without rerunning
`govulncheck`:

```text
audit.json
overview.txt
findings.txt
binaries.txt
diagnostics.txt
```

The `check` subcommand can later add one focused `checks/ID.txt` artifact per
requested identifier without regenerating the base bundle or rerunning
`govulncheck`.

`--output-dir` writes this portable bundle. `audit.json` is the complete scan
snapshot, and every text file is rendered from that same in-memory model. The
same bundle can be regenerated later from a stored snapshot. Requested checks
are cached as individual, visually structured text reports tied to the snapshot
digest and recorded vulnerability database/toolchain provenance. Existing
identical artifacts are reused; differing generated content is not overwritten.

## Out of scope

- Offline `govulncheck -mode extract` collection.
- Vulnerability-policy enforcement or build gating.
- Cryptographically attesting that an extracted root filesystem belongs to a
  claimed image digest.
- Inferring an OCI image digest from an unpacked root filesystem.
- Historical-layer inventory of deleted or superseded binaries.
- Treating binary-mode symbol presence as proof of runtime reachability or
  exploitability.
- Native package and shared-library vulnerability scanning.
