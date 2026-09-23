# Proof-of-concept scope

The proof of concept will make container-level Go vulnerability findings easy
to understand while retaining the evidence required for analyst review. The
scanner will remain extraction-tool-agnostic, use no third-party Python runtime
dependencies, and never execute binaries from the inspected filesystem.

## Finding model

One normalized finding model will preserve the complete relationship between:

```text
container -> binary path -> vulnerability -> module -> package -> symbol
```

It will also retain installed and fixed versions, evidence level, aliases,
hardlinks, CGO status, reconciliation state, and scan coverage. Every renderer
will consume this model so container aggregation does not discard binary paths
or supporting evidence.

## Container identity

Container identity will be optional because a merged root filesystem does not
contain a standardized OCI image reference or manifest digest. Callers may
provide an image reference, resolved digest, platform, and extractor through
CLI options or a tool-independent sidecar JSON file. When identity is absent,
the report will identify its subject as an unpacked root filesystem and will
not infer an OCI digest.

## Reports and grouping

Output encoding and result grouping will be independent concepts:

```text
--format text|markdown|json|sarif|openvex
--group-by container|binary|package|vulnerability
```

Reports will begin with subject identity, result state, scan coverage,
vulnerability database provenance, and tool versions. Finding rows will retain
the affected binary pathname. Targeted `--check` queries will emit an explicit
result for every requested vulnerability and container, including a scoped
"no matching finding detected" result when scan coverage is complete.

Container-level result states will distinguish vulnerabilities, complete scans
with no findings, incomplete scans, roots containing no recognized Go
binaries, and operational errors. Informational reconciliation notes will not
be presented as incomplete vulnerability coverage.

## Report cache

Canonical JSON reports may be written to a report cache and read later without
rescanning:

```text
pygo-audit scan ROOT --cache-dir CACHE --cache-mode write
pygo-audit report CACHE --group-by container
pygo-audit report CACHE --check CVE-YYYY-NNNNN
```

Cached reports will be immutable audit snapshots. They will retain their scan
timestamp, schema version, binary hashes, tool versions, database URL and
revision, coverage, and errors. Reading a cached report will not imply that it
was refreshed against the current vulnerability database.

## Build inventory

The canonical audit will retain normalized and raw `go version -m -json` build
information for every binary, including module replacements, build settings,
Go version, main module, VCS metadata, platform, build mode, and CGO status.
Human-readable reports will state that native-library coverage is outside the
Go dependency audit when CGO is enabled.

The proof of concept will generate a CycloneDX JSON dependency inventory that
relates each binary to its embedded Go modules without inventing module-to-
module relationships that are not present in Go build information.

## Generated artifacts

A single scan will be able to generate multiple artifacts without rerunning
`govulncheck`:

```text
audit.json
report.txt
report.md
buildinfo.json
dependencies.cdx.json
findings.sarif
findings.openvex.json
```

Exit behavior will separately address vulnerability findings, incomplete
coverage, and other issues through an explicit `--fail-on` policy.

## Out of scope

- Offline `govulncheck -mode extract` collection.
- Inferring an OCI image digest from an unpacked root filesystem.
- Historical-layer inventory of deleted or superseded binaries.
- Treating binary-mode symbol presence as proof of runtime reachability or
  exploitability.
- Native package and shared-library vulnerability scanning.
